"""JSON logging to stdout (collected by Loki); with CII_LOG_DIR set (laptop), also to a file per process."""

import logging
import os
import sys
from collections.abc import MutableMapping
from pathlib import Path
from typing import Any

import structlog

from app.core.config import Settings
from app.core.redaction import MASKED, SECRET_FIELD_NAME
from app.core.tracing import set_step_detail, set_step_tracing


def mask_secret_values(_logger: Any, _name: str, event: MutableMapping[str, Any]) -> MutableMapping[str, Any]:
    for field_name in list(event):
        if SECRET_FIELD_NAME.search(field_name) and event[field_name]:
            event[field_name] = MASKED
    return event


def configure_logging(settings: Settings, role: str | None = None) -> None:
    """JSON lines to stdout; with CII_LOG_DIR set (laptop), also to <log_dir>/<role>.log (api, worker-…). The
    step trace (DEBUG_STEP_OUTPUT, DEBUG_STEP_DETAIL) is switched on or off here, once per process."""
    set_step_tracing(settings.debug_step_output)
    set_step_detail(settings.debug_step_detail, settings.debug_step_top)
    level = settings.log_level
    logging.basicConfig(stream=sys.stdout, level=level, format="%(message)s")
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
