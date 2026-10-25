"""A writer whose first evidence-index build an AI or store outage keeps stopping serves the placeholder, so
every batch waits: it tries the build again after the first, short pause every time, never the doubled one."""

import threading
from typing import Any

import pytest

from app.core.constants import AI_OUTAGE_MESSAGES, AiOutage
from app.core.exceptions import Unavailable
from app.search.external_intelligence.index_keeper import RETRY_FIRST_SECONDS, EvidenceIndexKeeper
from tests.external_intelligence.evidence_fakes import TextEmbeddings, technique_doc
from tests.external_intelligence.search.test_index_keeper import Clock, _keeper


class BusyEmbeddings(TextEmbeddings):
    """The library's embedding call refused as busy while `busy`."""

    def __init__(self) -> None:
        super().__init__()
        self.busy = True

    def embed_library_texts(self, corpus: Any, texts: Any, sources: Any) -> Any:
        if self.busy:
            raise Unavailable(AI_OUTAGE_MESSAGES[AiOutage.BUSY], reason=AiOutage.BUSY)
        return super().embed_library_texts(corpus, texts, sources)


def _built_within_seconds(keeper: EvidenceIndexKeeper, seconds: float = 5.0) -> bool:
    """True once the build a request started in the background has swapped a real index in."""
    pause = threading.Event()
    for _ in range(int(seconds / 0.05)):
        if keeper.peek_index().snapshot_id is not None:
            return True
        pause.wait(0.05)
    return False


def test_a_first_build_an_outage_keeps_stopping_is_tried_again_after_the_first_pause_each_time() -> None:
    clock, embeddings = Clock(), BusyEmbeddings()
    keeper, *_ = _keeper([technique_doc("T1")], embeddings, clock=clock)
    for _ in range(6):  # six busy builds in a row: a doubled pause would now be 900 s
        with pytest.raises(Unavailable):
            keeper.rebuild_index().result(10)
        assert keeper.peek_index().snapshot_id is None  # still the placeholder: every batch waits
    embeddings.busy = False
    clock.now += RETRY_FIRST_SECONDS + 1
    keeper.current_index()  # due again: a request starts the build in the background
    assert _built_within_seconds(keeper)
