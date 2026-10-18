"""JSON logging to stdout (collected by Loki); with CII_LOG_DIR set (laptop), also to a file per process."""

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


def mask_secret_values(_logger: Any, _name: str, event: MutableMapping[str, Any]) -> MutableMapping[str, Any]:
    for field_name in list(event):
        if SECRET_FIELD_NAME.search(field_name) and event[field_name]:
            event[field_name] = MASKED
    return event


def configure_logging(settings: Settings, role: str | None = None) -> None:
    """JSON lines to stdout; with CII_LOG_DIR set (laptop), also to <log_dir>/<role>.log (api, worker-…)."""
    level = settings.log_level
    logging.basicConfig(stream=sys.stdout, format="%(message)s")  # does nothing once a handler exists
    # G263: DEBUG is for our code only. On the root it also printed every library's debug lines (each MongoDB
    # command and its reply in UAT, stored data among them); libraries keep INFO and above.
    logging.getLogger().setLevel(logging.INFO if level == "DEBUG" else level)
    for name in _OUR_LOGGERS:
        logging.getLogger(name).setLevel(level)
    if settings.log_dir and role:
        _also_write_to(Path(settings.log_dir) / f"{role}.log", level)
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            mask_secret_values,
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
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
    handler.setFormatter(logging.Formatter("%(message)s"))
    handler.setLevel(level)
    root.addHandler(handler)
