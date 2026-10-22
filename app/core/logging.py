"""JSON logging to stdout (collected by Loki); with CII_LOG_DIR set (laptop), also to a file per process.
Every line is one JSON object, Celery's and the libraries' too, so their errors reach the error views."""

import logging
import os
import sys
from collections.abc import MutableMapping
from pathlib import Path
from typing import Any, Final

import structlog

from app.core.config import Settings
from app.core.redaction import MASKED, SECRET_FIELD_NAME

#: Our loggers: every module's structlog.get_logger(__name__) ("app.…") and the request log ("http").
_OUR_LOGGERS: Final = ("app", "http")

#: uvicorn's own loggers, sent to ours: "Exception in ASGI application" must not stay plain text.
_UVICORN_LOGGERS: Final = ("uvicorn", "uvicorn.error")


def mask_secret_values(_logger: Any, _name: str, event: MutableMapping[str, Any]) -> MutableMapping[str, Any]:
    for field_name in list(event):
        if SECRET_FIELD_NAME.search(field_name) and event[field_name]:
            event[field_name] = MASKED
    return event


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
    # ponytail: never rotated (laptop only); delete the folder when it grows. Pods log to stdout instead.
    handler = logging.FileHandler(path, encoding="utf-8")
    handler.setFormatter(_json_formatter())
    handler.setLevel(level)
    root.addHandler(handler)
