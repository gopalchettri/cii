"""Step tracing (DEBUG_STEP_OUTPUT): when on, every workflow step logs its inputs, intermediate results,
output, time taken and any error, each value redacted and bounded (core/redaction.safe_preview). When off,
nothing extra is logged: the operational, security and audit logs stay as they are, and a traced call costs
one bool check.

    @traced("planner.build_landscape")      # a function: its arguments in, its return value out
    def describe_asset_for_ai(context, budget): ...

    with traced_step("writer.batch", paths=len(batch)) as trace:   # a block inside a function
        ...
        trace.record(written=3, failed=1)    # an intermediate result
        trace.set_output(summary)

Each traced call gets a short `call` id on its lines, and its step.started line names the enclosing traced
call as `parent` (None at the top), so nested and parallel calls of one step can be told apart. The id is
kept in a ContextVar: a worker thread started with contextvars.copy_context().run carries it too.

DEBUG_STEP_DETAIL (only with DEBUG_STEP_OUTPUT on) adds the inner sub-steps of a traced call (BM25,
similarity, merges, ranking…): record_detail(sub, item, given=..., produced=...) logs one step.result
under the innermost open call; ranked(pairs) keeps a best-first list's DEBUG_STEP_TOP entries. Off, or
outside any traced call, record_detail logs nothing."""

import functools
import inspect
import time
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, ParamSpec, TypeVar
from uuid import uuid4

import structlog

from app.core.constants import LogEvent, Tracing
from app.core.redaction import clipped_text, redact, safe_preview

log = structlog.get_logger(__name__)

P = ParamSpec("P")
R = TypeVar("R")

_enabled = False
_detail = False
_top = Tracing.DETAIL_TOP
#: (step name, call id) of the innermost open traced call in this context; None outside any.
_current: ContextVar[tuple[str, str] | None] = ContextVar("trace_step_call", default=None)


def set_step_tracing(enabled: bool) -> None:
    """Set once at process start from Settings.debug_step_output (core/logging.configure_logging)."""
    global _enabled
    _enabled = enabled


def step_tracing_enabled() -> bool:
    return _enabled


def set_step_detail(enabled: bool, top: int = Tracing.DETAIL_TOP) -> None:
    """Set once at process start from Settings.debug_step_detail and debug_step_top (configure_logging)."""
    global _detail, _top
    _detail, _top = enabled, top


def step_detail_enabled() -> bool:
    return _enabled and _detail


def detail_top() -> int:
    return _top


class StepTrace:
    """What a traced step adds while it runs: intermediate results, and the output its end logs."""

    def __init__(self, step: str, call: str | None = None) -> None:
        self.step = step
        self.call = call
        self.output: Any = None

    def record(self, **results: Any) -> None:
        if _enabled:
            log.info(LogEvent.STEP_RESULT, step=self.step, call=self.call, results=safe_preview(results))

    def set_output(self, value: Any) -> None:
        self.output = value


@contextmanager
def traced_step(step: str, /, **inputs: Any) -> Iterator[StepTrace]:
    """Logs step.started (inputs), then step.finished (output, ms) or step.failed (error, ms); re-raises."""
    if not _enabled:
        yield StepTrace(step)
        return
    call = uuid4().hex[:8]
    parent = (_current.get() or (None, None))[1]
    token = _current.set((step, call))
    trace = StepTrace(step, call)
    started = time.perf_counter()
    log.info(LogEvent.STEP_STARTED, step=step, call=call, parent=parent, inputs=safe_preview(inputs))
    try:
        yield trace
    except BaseException as exc:
        log.warning(
            LogEvent.STEP_FAILED,
            step=step,
            call=call,
            error=type(exc).__name__,
            message=clipped_text(redact(str(exc)), Tracing.PREVIEW_CHARS),
            ms=_milliseconds_since(started),
        )
        raise
    finally:
        _current.reset(token)
    log.info(
        LogEvent.STEP_FINISHED,
        step=step,
        call=call,
        ms=_milliseconds_since(started),
        output=safe_preview(trace.output),
    )


def record_detail(
    sub: str, item: str | None = None, *, given: Mapping[str, Any], produced: Mapping[str, Any]
) -> None:
    """One inner sub-step (e.g. "bm25" for one threat) of the innermost open traced call: what it was given
    and what it produced, redacted and bounded. Only with DEBUG_STEP_DETAIL on, and only inside a call."""
    if not step_detail_enabled():
        return
    current = _current.get()
    if current is None:
        return
    results = {"sub": sub, "item": item, "input": dict(given), "output": dict(produced)}
    log.info(LogEvent.STEP_RESULT, step=current[0], call=current[1], results=safe_preview(results))


def ranked(pairs: Iterable[tuple[str, float]]) -> dict[str, float]:
    """The first detail_top() of `pairs` (already best first) as {label: score rounded to 4}; a label seen
    again keeps its first score. float() turns a numpy score into a number the preview shows."""
    shown: dict[str, float] = {}
    for label, score in pairs:
        if len(shown) >= _top:
            break
        shown.setdefault(label, round(float(score), 4))
    return shown


def traced(step: str) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Trace every call of the decorated function: its arguments (self left out) and its return value."""

    def decorate(function: Callable[P, R]) -> Callable[P, R]:
        signature = inspect.signature(function)

        @functools.wraps(function)
        def traced_call(*args: P.args, **kwargs: P.kwargs) -> R:
            if not _enabled:
                return function(*args, **kwargs)
            arguments = signature.bind_partial(*args, **kwargs).arguments
            inputs = {name: value for name, value in arguments.items() if name not in ("self", "cls")}
            with traced_step(step, **inputs) as trace:
                result = function(*args, **kwargs)
                trace.set_output(result)
            return result

        return traced_call

    return decorate


def _milliseconds_since(started: float) -> float:
    return round((time.perf_counter() - started) * 1000, 1)
