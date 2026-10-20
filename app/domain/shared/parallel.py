"""Running AI calls at the same time: results in item order, each call in a copy of the log context (so every
AI call record still names the run); all finish first, then the most retryable error is raised."""

import contextvars
from collections.abc import Callable, Sequence
from concurrent.futures import Executor, ThreadPoolExecutor, wait

from app.ai.common import outage_reason
from app.core.exceptions import TEMPORARY_ERRORS, LeaseLost


def run_in_parallel[Item, Result](
    work: Callable[[Item], Result], items: Sequence[Item], at_once: int, name: str
) -> list[Result]:
    """`work` on every item, at most `at_once` at a time, results in item order; each runs in a copy of the
    log context, so every AI call record still names the run. All finish first; then the most retryable error
    is raised (an outage retries the job before a bad answer is noted)."""
    if len(items) <= 1:
        return [work(item) for item in items]
    with ThreadPoolExecutor(min(at_once, len(items)), thread_name_prefix=name) as pool:
        return run_in_shared_pool(pool, work, items)


def run_in_shared_pool[Item, Result](
    pool: Executor, work: Callable[[Item], Result], items: Sequence[Item]
) -> list[Result]:
    """`work` on every item in a shared `pool`, results in item order, each in a copy of the log context. All
    finish first; then the most retryable error is raised."""
    futures = [pool.submit(contextvars.copy_context().run, work, item) for item in items]
    wait(futures)
    raise_most_retryable([error for future in futures if (error := future.exception()) is not None])
    return [future.result() for future in futures]


def raise_most_retryable(errors: list[BaseException]) -> None:
    """Raise a lost lease first (the job is no longer this delivery's: nothing else matters), then the
    first retryable error that names an AI outage (so the retry notice tells which), then any retryable
    one, else the first error; nothing when there is none."""
    if errors:
        raise min(
            errors,
            key=lambda error: (
                not isinstance(error, LeaseLost),
                not isinstance(error, TEMPORARY_ERRORS),
                outage_reason(error) is None,
            ),
        )
