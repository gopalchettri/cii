"""Running AI calls at the same time: results in item order, each call in a copy of the log context (so every
AI call record still names the run); all finish first, then the most retryable error is raised."""

import contextvars
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor, wait

from app.core.exceptions import TEMPORARY_ERRORS, LeaseLost, outage_reason


def run_in_parallel[Item, Result](
    work: Callable[[Item], Result], items: Sequence[Item], at_once: int, name: str
) -> list[Result]:
    """`work` on every item, at most `at_once` at a time, results in item order; the most retryable error raised."""
    if len(items) <= 1:
        return [work(item) for item in items]
    with ThreadPoolExecutor(min(at_once, len(items)), thread_name_prefix=name) as pool:
        futures = [pool.submit(contextvars.copy_context().run, work, item) for item in items]
        wait(futures)
    raise_most_retryable([error for future in futures if (error := future.exception()) is not None])
    return [future.result() for future in futures]


def raise_most_retryable(errors: list[BaseException]) -> None:
    """Raise a lost lease first, then a retryable error naming an AI outage, then any retryable one, else the first."""
    if errors:
        raise min(
            errors,
            key=lambda error: (
                not isinstance(error, LeaseLost),
                not isinstance(error, TEMPORARY_ERRORS),
                outage_reason(error) is None,
            ),
        )
