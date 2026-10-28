"""The embedding batches of one call, several requests in flight at once (app/ai/embeddings.py)."""

import contextvars
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed


def embed_batches_in_parallel[Answer](
    batches: list[list[str]], request: Callable[[list[str]], Answer], concurrency: int
) -> Iterator[tuple[list[str], Answer]]:
    """(batch, its answer) as each answer arrives, with up to `concurrency` requests in flight: the library
    index build sends ~100 batches. After a failure no new batch is sent, but every answer already paid for is
    still handed back (and so stored) before the failure is raised."""
    if concurrency <= 1 or len(batches) <= 1:
        for batch in batches:
            yield batch, request(batch)
        return
    pool = ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="embed")
    try:
        # Each request in a copy of the caller's context: its log fields (the run) and its job's lease signal
        # reach the pool's threads too.
        sent = {pool.submit(contextvars.copy_context().run, request, batch): batch for batch in batches}
        failure: BaseException | None = None
        for answer in as_completed(sent):
            if answer.cancelled():
                continue
            if answer.exception() is None:
                yield sent[answer], answer.result()
            elif failure is None:
                failure = answer.exception()
                for waiting in sent:
                    waiting.cancel()  # only batches not yet sent; those in flight still arrive
        if failure is not None:
            raise failure
    finally:
        pool.shutdown(wait=True, cancel_futures=True)
