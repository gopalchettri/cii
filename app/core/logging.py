"""JSON logging to stdout (collected by Loki); with CII_LOG_DIR set (laptop), also to a file per process.
Every line is one JSON object, Celery's and the libraries' too, so their errors reach the error views."""

import logging
import logging.handlers
import os
import sys
from collections.abc import MutableMapping
from pathlib import Path
from typing import Any, Final

import structlog

from app.core.config import Settings
from app.core.redaction import MASKED, SECRET_FIELD_NAME, redact

#: Our loggers: every module's structlog.get_logger(__name__) ("app.…") and the request log ("http").
_OUR_LOGGERS: Final = ("app", "http")

#: uvicorn's own loggers, sent to ours: "Exception in ASGI application" must not stay plain text.
_UVICORN_LOGGERS: Final = ("uvicorn", "uvicorn.error")

#: A laptop log file rolls over at this size; this many old copies are kept (<role>.log.1 …), so each role
#: uses at most 200 MB.
_LOG_FILE_MAX_BYTES: Final = 50 * 1024 * 1024
_LOG_FILE_OLD_COPIES: Final = 3


def mask_secret_values(_logger: Any, _name: str, event: MutableMapping[str, Any]) -> MutableMapping[str, Any]:
    for field_name in list(event):
        if SECRET_FIELD_NAME.search(field_name) and event[field_name]:
            event[field_name] = MASKED
    return event


#: Fields that hold error text (a traceback, an error's message, or a line's own message): redacted.
_ERROR_TEXT_FIELDS: Final = ("event", "exception", "error", "reason", "message", "detail")


def redact_error_text(_logger: Any, _name: str, event: MutableMapping[str, Any]) -> MutableMapping[str, Any]:
    """Secrets and personal data taken out of a line's error text; its other fields are left as they are."""
    for field_name in _ERROR_TEXT_FIELDS:
        if isinstance(event.get(field_name), str):
            event[field_name] = redact(event[field_name])
    return event


def current_request_id() -> str | None:
    """The id of the API request this code runs for (bound by the middleware, or by a worker from the job's
    record); None outside one."""
    request_id = structlog.contextvars.get_contextvars().get("request_id")
    return str(request_id) if request_id else None


#: Added to every line, ours and the libraries'.
_EVERY_LINE: Final = (
    structlog.contextvars.merge_contextvars,
    structlog.processors.add_log_level,
    structlog.processors.TimeStamper(fmt="iso", utc=True),
    mask_secret_values,
)


def _json_formatter() -> structlog.stdlib.ProcessorFormatter:
    """One JSON object per line; a library's line also names its logger ("celery.app.trace"), and a traceback
    stays inside its line."""
    return structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=[*_EVERY_LINE, structlog.stdlib.add_logger_name],
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.processors.format_exc_info,
            redact_error_text,  # after the traceback is text
            structlog.processors.JSONRenderer(),
        ],
    )


def configure_logging(settings: Settings, role: str | None = None) -> None:
    """JSON lines to stdout; with CII_LOG_DIR set (laptop), also to <log_dir>/<role>.log (api, worker-…)."""
    level = settings.log_level
    root = logging.getLogger()
    if not root.handlers:  # as logging.basicConfig: a handler already there (pytest's) is kept
        stdout = logging.StreamHandler(sys.stdout)
        stdout.setFormatter(_json_formatter())
        root.addHandler(stdout)
    for name in _UVICORN_LOGGERS:
        logging.getLogger(name).handlers.clear()
        logging.getLogger(name).propagate = True
    # G263: DEBUG is for our code only. On the root it also printed every library's debug lines (each MongoDB
    # command and its reply in UAT, stored data among them); libraries keep INFO and above.
    logging.getLogger().setLevel(logging.INFO if level == "DEBUG" else level)
    for name in _OUR_LOGGERS:
        logging.getLogger(name).setLevel(level)
    if settings.log_dir and role:
        _also_write_to(Path(settings.log_dir) / f"{role}.log", level)
    structlog.configure(
        processors=[*_EVERY_LINE, structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.make_filtering_bound_logger(logging.getLevelName(level)),
        cache_logger_on_first_use=True,
    )


def _also_write_to(path: Path, level: str) -> None:
    root = logging.getLogger()
    if any(getattr(handler, "baseFilename", None) == os.path.abspath(path) for handler in root.handlers):
        return  # start-up ran twice in this process (tests): one file handler, never duplicated lines
    path.parent.mkdir(parents=True, exist_ok=True)
    # One writer per file (each process has its own role), so rolling over is safe; Alloy reads only the
    # current <role>.log, never the old copies. Pods log to stdout instead.
    handler = logging.handlers.RotatingFileHandler(
        path, maxBytes=_LOG_FILE_MAX_BYTES, backupCount=_LOG_FILE_OLD_COPIES, encoding="utf-8"
    )
    handler.setFormatter(_json_formatter())
    handler.setLevel(level)
    root.addHandler(handler)
