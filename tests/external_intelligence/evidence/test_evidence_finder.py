"""External evidence for a batch of requests: the IT / OT filter before ranking, the recorded decision for
every candidate, failures isolated per request, ONE embedding call."""

from typing import Any

import pytest

from app.core.constants import AI_OUTAGE_MESSAGES, AiOutage, AssetType, EvidenceDecision, EvidenceSearchFailure
from app.core.exceptions import Unavailable
from app.domain.intel import evidence
from app.domain.intel.index import EMPTY_SNAPSHOT_ID, build_corpus, build_index, empty_index
from app.worker.scenario.write_job import find_evidence_outage
from tests.external_intelligence.evidence_fakes import ScoredBy, TextEmbeddings, request_of, technique_doc, use_index

IT = {"IT", AssetType.IT_OT}
OT = {"OT", AssetType.IT_OT}


def finder_of(
    monkeypatch: pytest.MonkeyPatch,
    docs: list[dict],
    rerank: ScoredBy | None = None,
    threshold: float = 1.0,
    embeddings=None,
    candidates: int = 6,
    kept_per_threat: int = 3,
) -> TextEmbeddings:
    """evidence.find_evidence searches an index of `docs` from now on; returns its embedding model."""
    embeddings = embeddings or TextEmbeddings()
    index = build_index(build_corpus(docs), embeddings, rerank or ScoredBy(), "rr-model")
    use_index(monkeypatch, index, threshold, candidates, kept_per_threat)
    return embeddings


def one(request: Any):
    return evidence.find_evidence([request])[0]


def refs(result) -> set[str]:
    return {item.ref for item in result.evidence}


def test_an_it_asset_sees_it_and_it_ot_records_and_an_ot_asset_ot_and_it_ot(monkeypatch: pytest.MonkeyPatch) -> None:
    docs = [technique_doc("T1", "IT"), technique_doc("T2", "OT"), technique_doc("T3", AssetType.IT_OT)]
    finder_of(monkeypatch, docs)
    result = one(request_of(types=IT))
    assert refs(result) == {"T1", "T3"} and {c.ref for c in result.search.considered} == {"T1", "T3"}
    result = one(request_of(types=OT))
    assert refs(result) == {"T2", "T3"} and set(result.search.asset_types) == OT


def test_a_rerank_asked_again_is_answered_from_memory_once_it_succeeded(monkeypatch: pytest.MonkeyPatch) -> None:
    """Another path of the same threat, a later set or a retry: the same query over the same candidates of the
    same snapshot is scored once; a failed call is never kept, and another query is scored on its own."""

    class DownOnce(ScoredBy):
        def score_relevance(self, query: str, documents: list[str]) -> list[float]:
            scores = super().score_relevance(query, documents)
            if len(self.calls) == 1:
                raise Unavailable("down")
            return scores

    rerank = DownOnce()
    finder_of(monkeypatch, [technique_doc("T1"), technique_doc("T2")], rerank)
    assert one(request_of()).search.failure is not None
    first, again = (one(request_of()) for _ in range(2))
    assert len(rerank.calls) == 2 and first == again and refs(first) == {"T1", "T2"}
    one(request_of("Threat: Phishing of the operators"))
    assert len(rerank.calls) == 3


def test_the_finder_reranks_at_most_its_candidates(monkeypatch: pytest.MonkeyPatch) -> None:
    docs = [technique_doc(f"T{n}") for n in range(1, 6)]
    for candidates in (2, 30):
        finder_of(monkeypatch, docs, candidates=candidates)
        result = one(request_of())
        assert len(result.search.considered) == min(candidates, len(docs))


def test_the_finder_keeps_at_most_its_kept_count_and_marks_the_rest_over_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    docs = [technique_doc(f"T{n}") for n in range(1, 5)]
    finder_of(monkeypatch, docs, kept_per_threat=2)
    result = one(request_of())
    over = [c for c in result.search.considered if c.decision == EvidenceDecision.OVER_LIMIT]
    assert len(result.evidence) == 2 and len(over) == 2 and "2 places" in over[0].reason


def test_the_audit_names_the_query_the_snapshot_the_threshold_and_the_rerank_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    finder_of(monkeypatch, [technique_doc("T1")], threshold=5.0)
    result = one(request_of("Threat: X"))
    search = result.search
    assert (search.query, search.threshold, search.rerank_model) == ("Threat: X", 5.0, "rr-model")
    assert search.snapshot_id is not None
    assert search.as_doc()["rerank_model"] == "rr-model"


def test_a_candidate_under_the_threshold_is_recorded_with_its_score_and_a_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    finder_of(monkeypatch, [technique_doc("T1"), technique_doc("T2")], ScoredBy({"Technique T2": 0.5}))
    result = one(request_of())
    low = next(c for c in result.search.considered if c.ref == "T2")
    assert refs(result) == {"T1"} and (low.decision, low.score) == (EvidenceDecision.BELOW_THRESHOLD, 0.5)
    assert "1 needed" in low.reason


def test_the_threshold_is_the_setting(monkeypatch: pytest.MonkeyPatch) -> None:
    """Under it, the same record is used only as the nearest."""
    docs = [technique_doc("T1")]
    finder_of(monkeypatch, docs, ScoredBy(default=3.0), threshold=1.0)
    assert [item.nearest for item in one(request_of()).evidence] == [False]
    finder_of(monkeypatch, docs, ScoredBy(default=3.0), threshold=5.0)
    assert [item.nearest for item in one(request_of()).evidence] == [True]


def test_only_the_best_few_are_used_and_the_rest_are_over_the_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    docs = [technique_doc(f"T{n}") for n in range(1, 7)]
    scores = {f"Technique T{n}": 100.0 - n for n in range(1, 7)}
    finder_of(monkeypatch, docs, ScoredBy(scores))
    result = one(request_of())
    assert [item.ref for item in result.evidence] == ["T1", "T2", "T3"]
    over = [c.ref for c in result.search.considered if c.decision == EvidenceDecision.OVER_LIMIT]
    assert over == ["T4", "T5", "T6"]


def test_an_entry_is_built_only_for_the_records_kept(monkeypatch: pytest.MonkeyPatch) -> None:
    """Building an entry cleans its facts: a usable record over the limit is never built, in either pass."""
    docs = [technique_doc(f"T{n}") for n in range(1, 7)]
    scores = {f"Technique T{n}": 100.0 - n for n in range(1, 7)}
    for threshold, nearest in ((1.0, False), (200.0, True)):
        built: list[str] = []

        def counting(hit, real=evidence.write_facts, built=built):
            built.append(hit.external_id)
            return real(hit)

        finder_of(monkeypatch, docs, ScoredBy(scores), threshold=threshold)
        monkeypatch.setattr(evidence, "write_facts", counting)
        result = one(request_of())
        monkeypatch.undo()
        assert built == [e.ref for e in result.evidence] == ["T1", "T2", "T3"]
        assert {e.nearest for e in result.evidence} == {nearest}


def test_no_index_yet_or_no_request_means_no_search_and_no_error(monkeypatch: pytest.MonkeyPatch) -> None:
    use_index(monkeypatch, empty_index(TextEmbeddings(), ScoredBy()))
    result = one(request_of())
    assert result.evidence == () and result.search.snapshot_id is None and result.search.considered == ()
    assert isinstance(find_evidence_outage({"intel_search": result.search.as_doc()}), Unavailable)  # it waits
    embeddings = finder_of(monkeypatch, [technique_doc("T1")])
    assert evidence.find_evidence([]) == [] and "query" not in embeddings.calls


def test_a_first_index_build_the_ai_stopped_holds_the_paths_back_as_that_outage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Owner 2026-10-20: no snapshot yet because the AI was down while building it: the held path is told as
    "ai_down", not as a missing snapshot."""
    use_index(monkeypatch, empty_index(TextEmbeddings(), ScoredBy(), outage=AiOutage.DOWN))
    result = one(request_of())
    assert result.search.snapshot_id is None and result.search.outage == AiOutage.DOWN
    problem = find_evidence_outage({"intel_search": result.search.as_doc()})
    assert problem is not None and (problem.reason, problem.detail) == (
        AiOutage.DOWN,
        AI_OUTAGE_MESSAGES[AiOutage.DOWN],
    )


def test_a_settled_empty_index_finds_no_evidence_and_is_no_outage(monkeypatch: pytest.MonkeyPatch) -> None:
    """Searched and nothing found: the path is written without evidence, never held back."""
    use_index(monkeypatch, empty_index(TextEmbeddings(), ScoredBy(), settled=True))
    result = one(request_of())
    search = result.search
    assert (result.evidence, search.snapshot_id, search.failure) == ((), EMPTY_SNAPSHOT_ID, None)
    assert find_evidence_outage({"intel_search": search.as_doc(), "evidence": []}) is None


def test_an_embedding_outage_leaves_every_request_without_evidence_and_says_why(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    embeddings = finder_of(monkeypatch, [technique_doc("T1")])
    embeddings.queries_down = True
    results = evidence.find_evidence([request_of(), request_of("Threat: other")])
    assert all(r.evidence == () and r.search.failure == EvidenceSearchFailure.UNAVAILABLE for r in results)
    assert all(r.search.outage == AiOutage.UNREACHABLE for r in results)  # the gateway's own outage


def test_a_rerank_outage_costs_only_the_request_it_hit(monkeypatch: pytest.MonkeyPatch) -> None:
    class DownFor(ScoredBy):
        def score_relevance(self, query: str, documents: list[str]) -> list[float]:
            if "phishing" in query:
                raise Unavailable("down")
            return super().score_relevance(query, documents)

    finder_of(monkeypatch, [technique_doc("T1")], DownFor())
    first, second = evidence.find_evidence([request_of(), request_of("Threat: phishing ransomware")])
    assert refs(first) == {"T1"} and second.evidence == ()
    assert second.search.failure == EvidenceSearchFailure.UNAVAILABLE


def test_an_ai_outage_in_the_search_tells_which_and_the_held_path_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    """Owner 2026-10-20: the UI learns the AI timed out (or was down, unreachable, busy), never only that the
    evidence search could not be made."""

    class TimedOutFor(ScoredBy):
        def score_relevance(self, query: str, documents: list[str]) -> list[float]:
            if "phishing" in query:
                raise Unavailable(AI_OUTAGE_MESSAGES[AiOutage.TIMED_OUT], reason=AiOutage.TIMED_OUT)
            return super().score_relevance(query, documents)

    finder_of(monkeypatch, [technique_doc("T1")], TimedOutFor())
    requests = [request_of(), request_of("Threat: phishing ransomware")]
    found, lost = evidence.find_evidence(requests)
    assert lost.search.outage == AiOutage.TIMED_OUT and "outage" not in found.search.as_doc()
    problem = find_evidence_outage({"intel_search": lost.search.as_doc()})
    assert problem is not None
    assert (problem.reason, problem.detail) == (AiOutage.TIMED_OUT, AI_OUTAGE_MESSAGES[AiOutage.TIMED_OUT])


def test_all_requests_of_a_batch_are_embedded_in_one_call(monkeypatch: pytest.MonkeyPatch) -> None:
    embeddings = finder_of(monkeypatch, [technique_doc("T1")])
    requests = [request_of(f"Threat: ransomware {n}") for n in range(5)]
    results = evidence.find_evidence(requests)
    assert embeddings.calls.count("query") == 1 and len(results) == 5


def test_a_search_record_holds_no_stale_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    finder_of(monkeypatch, [technique_doc("T1")])
    result = one(request_of())
    assert refs(result) == {"T1"} and "stale" not in result.search.as_doc()


def test_one_source_at_the_threshold_leaves_the_nearest_out(monkeypatch: pytest.MonkeyPatch) -> None:
    docs = [technique_doc("T1"), technique_doc("T2")]
    finder_of(monkeypatch, docs, ScoredBy({"Technique T1": 60.0, "Technique T2": 30.0}), threshold=50.0)
    result = one(request_of())
    assert [(item.ref, item.nearest) for item in result.evidence] == [("T1", False)]
    assert "nearest" not in result.evidence[0].as_doc()


def test_a_score_under_the_threshold_never_reads_as_reaching_it(monkeypatch: pytest.MonkeyPatch) -> None:
    """The score is rounded down to one decimal (29.96 under 30 reads 29.9, never 30.0) and the threshold
    shown as set (0.5, never 0), whether the record is left out or used as the nearest."""
    docs = [technique_doc("T1"), technique_doc("T2")]
    finder_of(monkeypatch, docs, ScoredBy({"Technique T1": 90.0, "Technique T2": 29.96}), threshold=30.0)
    reasons = {c.ref: c.reason for c in one(request_of()).search.considered}
    assert reasons["T2"] == "Scored 29.9 of 100, under the 30 needed."
    finder_of(monkeypatch, docs, ScoredBy({"Technique T1": 0.46, "Technique T2": 0.2}), threshold=0.5)
    reasons = {c.ref: c.reason for c in one(request_of()).search.considered}
    assert reasons == {
        "T1": "Scored 0.4 of 100, under the 0.5 needed.",
        "T2": "Scored 0.2 of 100, under the 0.5 needed.",
    }
