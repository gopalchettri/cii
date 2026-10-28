"""Each refusal keeps its own words while its reason stays the outage's (ai_busy, so the enum contract holds):
a reranker wait that ran out, or an AI slot wait (on a path or a first index build), is never told as the
gateway's "The AI service is busy"."""

from typing import Any

import pytest
from pymongo.errors import ConnectionFailure

from app.core.constants import (
    AI_OUTAGE_MESSAGES,
    AI_PATH_OUTAGE_MESSAGE,
    AiOutage,
    AiTask,
    ErrorCode,
    ErrorMessage,
    Lease,
)
from app.core.exceptions import Unavailable
from app.domain.external_intelligence.evidence_finder import EvidenceFinder
from app.domain.external_intelligence.rerank_gate import RerankGate
from app.domain.scenario.write import evidence_problem
from app.search.external_intelligence.corpus_builder import build_corpus
from app.search.external_intelligence.evidence_index import build_index
from app.worker.jobs import describe_outage
from tests.external_intelligence.evidence_fakes import (
    ALL_SOURCES,
    ScoredBy,
    TextEmbeddings,
    request_of,
    technique_doc,
)
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
)


def test_a_reranker_wait_that_ran_out_holds_the_path_back_in_its_own_words() -> None:
    gate = RerankGate(1, wait_seconds=0.05, check_every=0.01)
    index = build_index(build_corpus([technique_doc("T1")]), TextEmbeddings(), ScoredBy(), "rr-model")
    finder = EvidenceFinder(lambda: index, 1.0, gate=gate, candidates=6, kept_per_threat=3)
    with gate.hold_place():  # its one place taken: the search's rerank waits out the gate's limit
        (result,), _ = finder.find_evidence([request_of()], stale=False, approved=ALL_SOURCES)
    problem = evidence_problem({"intel_search": result.search.as_doc()})
    words = ErrorMessage.RERANK_BUSY.format(seconds=0)
    assert problem is not None and (problem.reason, problem.detail) == (AiOutage.BUSY, words)
    assert describe_outage(problem) == words != AI_OUTAGE_MESSAGES[AiOutage.BUSY]  # the retry notice's words
    assert "without evidence" not in words  # the path waits for its evidence: it is never written without
    assert "Try again" not in words  # the retry notice already says TSG tries again by itself


def test_a_first_build_whose_ai_slot_wait_ran_out_holds_writes_back_in_that_wait_s_words() -> None:
    slots_full = ErrorMessage.AI_BUSY.format(seconds=300)

    class SlotsFull(TextEmbeddings):
        def embed_library_texts(self, corpus: Any, texts: Any, sources: Any) -> Any:
            raise Unavailable(slots_full, reason=AiOutage.BUSY)  # TSG's own slots stayed full: no gateway 429

    keeper, *_ = _keeper([technique_doc("T1")], SlotsFull())
    with pytest.raises(Unavailable):
        keeper.rebuild_index().result(10)
    finder = EvidenceFinder(keeper.peek_index, 1.0, gate=RerankGate(1), candidates=6, kept_per_threat=3)
    (result,), _ = finder.find_evidence([request_of()], stale=False, approved=ALL_SOURCES)  # the placeholder
    problem = evidence_problem({"intel_search": result.search.as_doc()})
    assert problem is not None and (problem.reason, problem.detail) == (AiOutage.BUSY, slots_full)


def test_a_search_stopped_by_a_fault_not_the_ai_s_keeps_no_driver_text() -> None:
    class StoreDown(TextEmbeddings):
        def embed_search_queries(self, texts: Any, corpus: Any) -> Any:
            raise ConnectionFailure("mongo-host:27017: connection refused")  # a store's fault, not an outage

    index = build_index(build_corpus([technique_doc("T1")]), StoreDown(), ScoredBy(), "rr-model")
    finder = EvidenceFinder(lambda: index, 1.0, gate=RerankGate(1), candidates=6, kept_per_threat=3)
    (result,), _ = finder.find_evidence([request_of()], stale=False, approved=ALL_SOURCES)
    assert (result.search.outage, result.search.outage_message) == (None, "")


@pytest.mark.usefixtures("sent")
def test_a_path_whose_ai_slot_wait_ran_out_on_the_last_try_gets_a_card_in_that_wait_s_words(
    chat: FakeChatModel,  # noqa: F811
) -> None:
    slots_full = ErrorMessage.AI_BUSY.format(seconds=300)

    def threat_two_waits_out(user_prompt: str) -> dict[str, Any]:
        if '"Threat 2"' in user_prompt:
            raise Unavailable(slots_full, reason=AiOutage.BUSY)  # TSG's own slots stayed full: no gateway 429
        return _answer_for(user_prompt)

    chat.responders[AiTask.WRITE_SCENARIO] = threat_two_waits_out
    record_id = _queued_run(["Threat 1", "Threat 2"])
    _write_batch(_on_last_try(record_id))
    assert _scenarios_of(record_id)[1]["failure"] == {
        "code": ErrorCode.UNAVAILABLE,
        "message": AI_PATH_OUTAGE_MESSAGE.format(outage=slots_full, tries=Lease.MAX_ATTEMPTS),
        "reason": AiOutage.BUSY,
    }
