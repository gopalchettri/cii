"""G221: two harmless messages stay out of the laptop's DEBUG logs. The AI library's own tracing (every
request in full, a failed price lookup per call: "This model isn't mapped yet") and Windows' traceback when
a browser closed its live-update stream first (ConnectionResetError, WinError 10054). Real problems still
show."""

import asyncio
import logging
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient

import app.ai  # noqa: F401 — the cap is set where the AI library is imported
from app.core.config import get_settings
from app.core.logging import configure_logging
from app.main import _ignore_client_gone


def test_the_ai_librarys_own_debug_lines_stay_out_of_our_debug_logs(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)  # as CII_LOG_LEVEL=DEBUG on the laptop
    for name in ("LiteLLM", "LiteLLM Router", "LiteLLM Proxy"):
        logging.getLogger(name).debug("checking potential_model_names in litellm.model_cost")
        logging.getLogger(name).warning("a real problem")
    assert [record.getMessage() for record in caplog.records if record.name.startswith("LiteLLM")] == [
        "a real problem"
    ] * 3
    logging.getLogger("app").debug("our own debug line")
    assert caplog.records[-1].getMessage() == "our own debug line"


def test_debug_is_for_our_code_only_while_libraries_keep_info_and_above() -> None:
    # G263 (UAT, 2026-10-16): CII_LOG_LEVEL=DEBUG on the root logger printed every MongoDB command and its
    # reply ("Connection checkout started", "Command succeeded"), stored data among them.
    saved = {name: logging.getLogger(name).level for name in ("", "app", "http")}
    try:
        configure_logging(get_settings().model_copy(update={"log_level": "DEBUG"}))
        driver = logging.getLogger("pymongo.command")
        assert not driver.isEnabledFor(logging.DEBUG) and driver.isEnabledFor(logging.INFO)
        assert logging.getLogger("app.data_access.audit").isEnabledFor(logging.DEBUG)
        assert logging.getLogger("http").isEnabledFor(logging.DEBUG)  # the request log
    finally:
        for name, level in saved.items():
            logging.getLogger(name).setLevel(level)


class _Loop:
    def __init__(self) -> None:
        self.passed_on: list[dict[str, Any]] = []

    def default_exception_handler(self, context: dict[str, Any]) -> None:
        self.passed_on.append(context)


_CLEAN_UP = "Exception in callback _ProactorBasePipeTransport._call_connection_lost(None)"


def test_a_browser_that_left_first_is_no_error_but_anything_else_still_is() -> None:
    loop = _Loop()
    gone = {
        "message": _CLEAN_UP,
        "exception": ConnectionResetError(10054, "forcibly closed by the remote host"),
    }
    other_reset = {"message": "Exception in callback Server.read()", "exception": ConnectionResetError()}
    other_error = {"message": _CLEAN_UP, "exception": ValueError("not a closed connection")}
    no_exception = {"message": "Task was destroyed but it is pending!"}
    for context in (gone, other_reset, other_error, no_exception):
        _ignore_client_gone(cast(asyncio.AbstractEventLoop, loop), context)
    assert loop.passed_on == [other_reset, other_error, no_exception]


def test_the_api_installs_it_on_its_event_loop(client: TestClient) -> None:
    installed = client.portal.call(lambda: asyncio.get_running_loop().get_exception_handler())  # type: ignore[union-attr]
    assert installed is _ignore_client_gone
