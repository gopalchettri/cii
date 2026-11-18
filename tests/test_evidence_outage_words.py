"""Each refusal keeps its own words while its reason stays the outage's (ai_busy, so the enum contract holds):
a reranker wait that ran out, or an AI slot wait (on a path or a first index build), is never told as the
gateway's "The AI service is busy"."""

from typing import Any

import pytest
from pymongo.errors import ConnectionFailure

from app.core.constants import AI_PATH_OUTAGE_MESSAGE, AiOutage, AiTask, ErrorCode, ErrorMessage, Lease
from app.core.exceptions import Unavailable
from app.domain.intel import evidence
from app.domain.intel.evidence import RerankGate
from app.domain.intel.index import build_corpus, build_index
from app.worker.scenario.write_job import find_evidence_outage
from tests.external_intelligence.evidence_fakes import ScoredBy, TextEmbeddings, request_of, technique_doc, use_index
from tests.external_intelligence.search.test_index_keeper import _keeper
from tests.fakes import FakeChatModel
from tests.test_writing_job import (  # noqa: F401 - fixtures used by name
    _answer_for,
    _on_last_try,
    _queued_run,
    _scenarios_of,
    _write_batch,
    chat,
    sent,
    unreadable_then,
)


def test_a_first_build_whose_ai_slot_wait_ran_out_holds_writes_back_in_that_wait_s_words(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    slots_full = ErrorMessage.AI_BUSY.format(seconds=300)

    class SlotsFull(TextEmbeddings):
        def embed_library_texts(self, corpus: Any, texts: Any, sources: Any) -> Any:
            raise Unavailable(slots_full, reason=AiOutage.BUSY)  # TSG's own slots stayed full: no gateway 429

    keeper, *_ = _keeper(monkeypatch, [technique_doc("T1")], SlotsFull())
    with pytest.raises(Unavailable):
        keeper.rebuild_index().result(10)
    use_index(monkeypatch, keeper.peek_index, gate=RerankGate(1))
    (result,) = evidence.find_evidence([request_of()])  # the placeholder
    problem = find_evidence_outage({"intel_search": result.search.as_doc()})
    assert problem is not None and (problem.reason, problem.detail) == (AiOutage.BUSY, slots_full)


def test_a_search_stopped_by_a_fault_not_the_ai_s_keeps_no_driver_text(monkeypatch: pytest.MonkeyPatch) -> None:
    class StoreDown(TextEmbeddings):
        def embed_search_queries(self, texts: Any, corpus: Any) -> Any:
            raise ConnectionFailure("mongo-host:27017: connection refused")  # a store's fault, not an outage

    index = build_index(build_corpus([technique_doc("T1")]), StoreDown(), ScoredBy(), "rr-model")
    use_index(monkeypatch, index, gate=RerankGate(1))
    (result,) = evidence.find_evidence([request_of()])
    assert (result.search.outage, result.search.outage_message) == (None, "")


@pytest.mark.usefixtures("sent")
def test_a_path_whose_ai_slot_wait_ran_out_on_the_last_try_gets_a_card_in_that_wait_s_words(
    chat: FakeChatModel,  # noqa: F811
) -> None:
    slots_full = ErrorMessage.AI_BUSY.format(seconds=300)
    waits_out = Unavailable(slots_full, reason=AiOutage.BUSY)  # TSG's own slots stayed full: no gateway 429
    chat.responders[AiTask.WRITE_SCENARIO] = unreadable_then("Threat 2", waits_out)
    record_id = _queued_run(["Threat 1", "Threat 2"])
    _write_batch(_on_last_try(record_id))
    assert _scenarios_of(record_id)[1]["failure"] == {
        "code": ErrorCode.UNAVAILABLE,
        "message": AI_PATH_OUTAGE_MESSAGE.format(outage=slots_full, tries=Lease.MAX_ATTEMPTS),
        "reason": AiOutage.BUSY,
    }
