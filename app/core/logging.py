"""JSON logging to stdout (collected by Loki); with CII_LOG_DIR set (laptop), also to a file per process."""

import logging
import logging.handlers
import os
import sys
from collections.abc import Iterator, MutableMapping
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Any, Final

import structlog

from app.core.config import Settings
from app.core.redaction import MASKED, SECRET_FIELD_NAME, redact

_LOG_FILE_MAX_BYTES: Final = 50 * 1024 * 1024  # a laptop log file rolls over at this size


def mask_secret_values(_logger: Any, _name: str, event: MutableMapping[str, Any]) -> MutableMapping[str, Any]:
    for field_name in list(event):
        if SECRET_FIELD_NAME.search(field_name) and event[field_name]:
            event[field_name] = MASKED
    return event


def redact_error_text(_logger: Any, _name: str, event: MutableMapping[str, Any]) -> MutableMapping[str, Any]:
    """Secrets and personal data taken out of a line's error text; its other fields are left as they are."""
    for field_name in ("event", "exception", "error", "reason", "message", "detail"):
        if isinstance(event.get(field_name), str):
            event[field_name] = redact(event[field_name])
    return event


def current_request_id() -> str | None:
    """The id of the API request this code runs for; None outside one."""
    request_id = structlog.contextvars.get_contextvars().get("request_id")
    return str(request_id) if request_id else None


#: Who a job works for: saved on the job (job.origin), bound on its log lines and AI usage rows.
JOB_ORIGIN_FIELDS: Final = ("api", "client_id", "entity_id")
_JOB_ORIGIN: ContextVar[dict[str, Any] | None] = ContextVar("job_origin", default=None)


@contextmanager
def job_origin_scope(api: str, client_id: str, entity_id: int | str) -> Iterator[None]:
    """Names the API call and caller every job queued inside it works for; an outer scope's name stays."""
    if _JOB_ORIGIN.get() is not None:
        yield
        return
    token = _JOB_ORIGIN.set({"api": api, "client_id": client_id, "entity_id": entity_id})
    try:
        yield
    finally:
        _JOB_ORIGIN.reset(token)


def current_job_origin() -> dict[str, Any]:
    """The API call and caller this code runs for; {} outside both."""
    if (origin := _JOB_ORIGIN.get()) is not None:
        return dict(origin)
    bound = structlog.contextvars.get_contextvars()
    return {name: bound[name] for name in JOB_ORIGIN_FIELDS if bound.get(name) is not None}


#: Added to every line, ours and the libraries'.
_EVERY_LINE: Final = (
    structlog.contextvars.merge_contextvars,
    structlog.processors.add_log_level,
    structlog.processors.TimeStamper(fmt="iso", utc=True),
    mask_secret_values,
)


def _json_formatter() -> structlog.stdlib.ProcessorFormatter:
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
    for name in ("uvicorn", "uvicorn.error"):  # sent to ours: no plain-text "Exception in ASGI application"
        logging.getLogger(name).handlers.clear()
        logging.getLogger(name).propagate = True
    # DEBUG is for our code only: libraries' debug lines would print stored data.
    logging.getLogger().setLevel(logging.INFO if level == "DEBUG" else level)
    for name in ("app", "http"):  # every module's get_logger(__name__) and the request log
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
    # One writer per file (each process has its own role), so rolling over is safe.
    handler = logging.handlers.RotatingFileHandler(path, maxBytes=_LOG_FILE_MAX_BYTES, backupCount=3, encoding="utf-8")
    handler.setFormatter(_json_formatter())
    handler.setLevel(level)
    root.addHandler(handler)
