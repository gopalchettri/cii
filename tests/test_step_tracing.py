"""DEBUG_STEP_OUTPUT (owner, 2026-10-10): on, every traced step logs its redacted inputs, results, output,
time and errors; off, nothing extra. No secret ever reaches a step line."""

import contextvars
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

import numpy as np
import pytest
import structlog
from structlog.testing import capture_logs

from app.core.constants import LogEvent, Tracing
from app.core.redaction import MASKED, REDACTED, safe_preview
from app.core.tracing import (
    detail_top,
    ranked,
    record_detail,
    set_step_detail,
    set_step_tracing,
    traced,
    traced_step,
)


@pytest.fixture
def tracing_on() -> Iterator[None]:
    set_step_tracing(True)
    yield
    set_step_tracing(False)


@pytest.fixture
def detail_on(tracing_on: None) -> Iterator[None]:
    set_step_detail(True, 3)
    yield
    set_step_detail(False)


@traced("test.add")
def add(first: int, second: int, api_key: str = "") -> int:
    return first + second


def _step_lines(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [line for line in logs if str(line.get("event", "")).startswith("step.")]


def test_off_logs_nothing_and_still_returns_the_value() -> None:
    set_step_tracing(False)
    with capture_logs() as logs:
        assert add(2, 3) == 5
        with traced_step("test.block") as trace:
            trace.record(seen=1)
    assert _step_lines(logs) == []


@pytest.mark.usefixtures("tracing_on")
def test_on_logs_start_and_finish_with_time_inputs_and_output() -> None:
    with capture_logs() as logs:
        assert add(2, 3) == 5
    started, finished = _step_lines(logs)
    assert (started["event"], started["step"], started["inputs"]) == (
        LogEvent.STEP_STARTED,
        "test.add",
        {"first": 2, "second": 3},
    )
    assert (finished["event"], finished["output"]) == (LogEvent.STEP_FINISHED, 5)
    assert isinstance(finished["ms"], float) and finished["ms"] >= 0


@pytest.mark.usefixtures("tracing_on")
def test_secret_fields_and_secrets_in_text_never_reach_a_step_line() -> None:
    with capture_logs() as logs:
        add(1, 1, api_key="sk-live-abcdefghijklmnop")
        with traced_step("test.block", note="password: hunter2 and mail ops@example.com") as trace:
            trace.record(db_dsn="mssql://user:pw@host", token="t0k3n")  # noqa: S106 — a fake, to be masked
    text = str(logs)
    assert "sk-live" not in text and "hunter2" not in text and "ops@example.com" not in text
    assert "t0k3n" not in text and "user:pw" not in text
    started = _step_lines(logs)[0]
    assert started["inputs"]["api_key"] == MASKED
    assert REDACTED in _step_lines(logs)[2]["inputs"]["note"]


@pytest.mark.usefixtures("tracing_on")
def test_a_failing_step_logs_its_error_and_time_and_still_raises() -> None:
    failing = traced_step("test.fails", size=3)
    with capture_logs() as logs, pytest.raises(ValueError, match="bad input"), failing:
        raise ValueError("bad input")
    failed = _step_lines(logs)[-1]
    assert (failed["event"], failed["error"], failed["message"]) == (
        LogEvent.STEP_FAILED,
        "ValueError",
        "bad input",
    )
    assert "ms" in failed


@pytest.mark.usefixtures("tracing_on")
def test_intermediate_results_are_logged_once_each() -> None:
    with capture_logs() as logs, traced_step("test.block") as trace:
        trace.record(written=3, failed=1)
        trace.set_output({"done": True})
    lines = _step_lines(logs)
    expected = [LogEvent.STEP_STARTED, LogEvent.STEP_RESULT, LogEvent.STEP_FINISHED]
    assert [line["event"] for line in lines] == expected
    assert lines[1]["results"] == {"written": 3, "failed": 1}
    assert lines[2]["output"] == {"done": True}
    assert lines[0]["call"] == lines[1]["call"] == lines[2]["call"]


@pytest.mark.usefixtures("tracing_on")
def test_inner_records_write_nothing_unless_detail_is_on() -> None:
    set_step_detail(False)
    with capture_logs() as logs, traced_step("test.block"):
        record_detail("bm25", "T1", given={"query": "relay"}, produced={"hits": 2})
    assert [line["event"] for line in _step_lines(logs)] == [LogEvent.STEP_STARTED, LogEvent.STEP_FINISHED]


@pytest.mark.usefixtures("detail_on")
def test_an_inner_record_is_logged_under_the_open_call() -> None:
    with capture_logs() as logs:
        record_detail("bm25", given={}, produced={})  # outside any traced call: nothing
        with traced_step("test.block"):
            record_detail("bm25", "T1", given={"query": "relay"}, produced={"hits": 2})
    started, result, finished = _step_lines(logs)
    assert (result["event"], result["step"]) == (LogEvent.STEP_RESULT, "test.block")
    assert result["call"] == started["call"] == finished["call"]
    expected = {"sub": "bm25", "item": "T1", "input": {"query": "relay"}, "output": {"hits": 2}}
    assert result["results"] == expected


@pytest.mark.usefixtures("detail_on")
def test_a_nested_step_names_its_parent_and_records_go_to_the_innermost() -> None:
    with capture_logs() as logs, traced_step("test.outer"):
        with traced_step("test.inner"):
            record_detail("merge", given={}, produced={})
        record_detail("rank", given={}, produced={})
    outer, inner, inner_record, inner_end, outer_record, _ = _step_lines(logs)
    assert outer["parent"] is None and inner["parent"] == outer["call"] != inner["call"]
    assert inner_record["call"] == inner_end["call"] == inner["call"]
    assert (outer_record["step"], outer_record["call"]) == ("test.outer", outer["call"])


@pytest.mark.usefixtures("detail_on")
def test_a_record_made_in_a_worker_thread_carries_the_outer_call() -> None:
    def work() -> None:
        record_detail("similarity", "T2", given={"pairs": 1}, produced={"best": 0.9})

    with capture_logs() as logs, traced_step("test.parallel"), ThreadPoolExecutor() as pool:
        pool.submit(contextvars.copy_context().run, work).result()
    started, result, _ = _step_lines(logs)
    assert (result["step"], result["call"]) == ("test.parallel", started["call"])


@pytest.mark.usefixtures("detail_on")
def test_ranked_keeps_the_top_n_rounded_as_plain_numbers_first_label_wins() -> None:
    pairs = [("a", np.float32(0.912345)), ("b", 0.5), ("a", 0.1), ("c", 0.33333), ("d", 0.2)]
    shown = ranked(pairs)
    assert detail_top() == 3
    assert shown == {"a": 0.9123, "b": 0.5, "c": 0.3333}
    assert all(type(score) is float for score in shown.values())


@dataclass
class _Context:
    name: str
    systems: list[dict[str, Any]]


def test_a_preview_is_bounded_whatever_the_value() -> None:
    long_text = "x" * (Tracing.PREVIEW_CHARS + 50)
    assert safe_preview(long_text).endswith("(+50 chars)")
    many = list(range(10))
    assert safe_preview(many) == {"count": 10, "first": [0, 1, 2]}
    context = _Context("Substation", [{"id": i, "password": "p"} for i in range(5)])
    shown = safe_preview(context)
    assert shown["type"] == "_Context" and shown["systems"]["count"] == 5
    assert shown["systems"]["first"][0] == {"id": 0, "password": MASKED}
    deep: dict[str, Any] = {"a": {"b": {"c": {"d": {"e": 1}}}}}
    assert safe_preview(deep) == {"a": {"b": {"c": {"d": "<dict>"}}}}
    assert safe_preview(object()) == "<object>"


def test_a_plans_risk_owner_never_reaches_a_trace() -> None:
    """BLUEPRINT M11 Security (review S56): the risk owner is a person; the plan's teams are not."""
    plan = {
        "risk_owner": "Head of Grid Operations",
        "mitigation_owner": "OT Security",
        "register": {"risk_owner": "x"},
    }
    assert safe_preview(plan) == {
        "risk_owner": MASKED,
        "mitigation_owner": "OT Security",
        "register": {"risk_owner": MASKED},
    }


def test_configure_logging_switches_the_trace(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.core.config import get_settings
    from app.core.logging import configure_logging
    from app.core.tracing import step_detail_enabled, step_tracing_enabled

    update = {"debug_step_output": True, "debug_step_detail": True, "debug_step_top": 5, "log_dir": ""}
    settings = get_settings().model_copy(update=update)
    configure_logging(settings)
    assert (step_tracing_enabled(), step_detail_enabled(), detail_top()) == (True, True, 5)
    configure_logging(settings.model_copy(update={"debug_step_output": False}))
    assert (step_tracing_enabled(), step_detail_enabled()) == (False, False)  # detail needs the trace
    set_step_detail(False)
    structlog.reset_defaults()


def test_a_password_inside_a_connection_url_is_redacted_wherever_it_is() -> None:
    """Review of S0b: a URL's user:password passed the step trace (field not secret-named) and prompts."""
    urls = {"mongo_url": "mongodb://tsg_user:S3cret!@mongo:27017/cii", "note": "redis://:pa55@r:6379"}
    shown = safe_preview(urls)
    assert "S3cret" not in str(shown) and "pa55" not in str(shown)
    assert shown["mongo_url"] == f"mongodb://{REDACTED}@mongo:27017/cii"
    assert (
        safe_preview("see https://docs.example/path@v2") == "see https://docs.example/path@v2"
    )  # no password
