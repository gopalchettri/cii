"""External evidence for a batch of requests: the IT / OT filter before ranking, the recorded decision for
every candidate, applicability (unknown stays unknown), failures isolated per request, ONE embedding call."""

import re
from typing import Any

from app.core.constants import (
    Applicability,
    AssetType,
    EvidenceDecision,
    EvidenceLimits,
    EvidenceRole,
    EvidenceSearchFailure,
)
from app.core.exceptions import Unavailable
from app.engine.external_intelligence.evidence_finder import EvidenceFinder
from app.engine.external_intelligence.rerank_gate import RerankGate
from app.search.external_intelligence.corpus_builder import CorpusBuilder
from app.search.external_intelligence.evidence_index import build_index, empty_index
from tests.external_intelligence.evidence_fakes import (
    ScoredBy,
    TextEmbeddings,
    advisory_doc,
    request_of,
    technique_doc,
    vulnerability_doc,
)

IDS = re.compile(r"\bT\d{4}\b|CVE-\d{4}-\d+", re.IGNORECASE)
IT = {"IT", AssetType.IT_OT}
OT = {"OT", AssetType.IT_OT}
WINCC = {"vendors": ["Siemens"], "products": ["Siemens WinCC"]}


def finder_of(docs: list[dict], rerank: ScoredBy | None = None, threshold: float = 1.0, embeddings=None):
    embeddings = embeddings or TextEmbeddings()
    index = build_index(CorpusBuilder().build_corpus(docs), embeddings, rerank or ScoredBy(), "rr-model")
    return EvidenceFinder(lambda: index, threshold, gate=RerankGate(2)), embeddings


def one(finder: EvidenceFinder, request: Any, *, stale: bool = False):
    results, summary = finder.find_evidence([request], stale=stale)
    return results[0], summary


def refs(result) -> set[str]:
    return {item.ref for item in result.evidence}


def test_an_it_asset_sees_it_and_it_ot_records_and_an_ot_asset_ot_and_it_ot() -> None:
    docs = [technique_doc("T1", "IT"), technique_doc("T2", "OT"), technique_doc("T3", AssetType.IT_OT)]
    finder, _ = finder_of(docs)
    result, _ = one(finder, request_of(types=IT))
    assert refs(result) == {"T1", "T3"} and {c.ref for c in result.search.considered} == {"T1", "T3"}
    result, _ = one(finder, request_of(types=OT))
    assert refs(result) == {"T2", "T3"} and set(result.search.asset_types) == OT


def test_the_audit_names_the_query_the_snapshot_the_threshold_and_the_rerank_model() -> None:
    finder, _ = finder_of([technique_doc("T1")], threshold=5.0)
    result, summary = one(finder, request_of("Threat: X"))
    search = result.search
    assert (search.query, search.threshold, search.rerank_model) == ("Threat: X", 5.0, "rr-model")
    assert search.snapshot_id == summary.snapshot_id is not None
    assert search.as_doc()["rerank_model"] == "rr-model"


def test_a_candidate_under_the_threshold_is_recorded_with_its_score_and_a_reason() -> None:
    finder, _ = finder_of([technique_doc("T1"), technique_doc("T2")], ScoredBy({"Technique T2": 0.5}))
    result, _ = one(finder, request_of())
    low = next(c for c in result.search.considered if c.ref == "T2")
    assert refs(result) == {"T1"} and (low.decision, low.score) == (EvidenceDecision.BELOW_THRESHOLD, 0.5)
    assert "1 needed" in low.reason


def test_the_threshold_is_the_constructor_argument() -> None:
    docs = [technique_doc("T1")]
    low, _ = finder_of(docs, ScoredBy(default=3.0), threshold=1.0)
    high, _ = finder_of(docs, ScoredBy(default=3.0), threshold=5.0)
    assert refs(one(low, request_of())[0]) == {"T1"} and one(high, request_of())[0].evidence == ()


def test_only_the_best_few_are_used_and_the_rest_are_over_the_limit() -> None:
    docs = [technique_doc(f"T{n}") for n in range(1, 7)]
    scores = {f"Technique T{n}": 100.0 - n for n in range(1, 7)}
    result, _ = one(finder_of(docs, ScoredBy(scores))[0], request_of())
    assert [item.ref for item in result.evidence] == ["T1", "T2", "T3"][: EvidenceLimits.PER_THREAT]
    over = [c.ref for c in result.search.considered if c.decision == EvidenceDecision.OVER_LIMIT]
    assert over == ["T4", "T5", "T6"]


def test_a_vulnerability_of_another_vendor_is_not_applicable() -> None:
    finder, _ = finder_of([vulnerability_doc("CVE-2024-0001", "Apache", "HTTP Server")])
    result, _ = one(finder, request_of(vendors=["Siemens"], products=["Windows", "Siemens WinCC"]))
    (row,) = result.search.considered
    assert result.evidence == () and row.decision == EvidenceDecision.NOT_APPLICABLE
    assert "Apache HTTP Server" in row.reason


def test_same_vendor_and_product_without_a_version_is_unknown_never_confirmed() -> None:
    finder, _ = finder_of([vulnerability_doc("CVE-2024-0002", "Siemens", "WinCC")])
    result, _ = one(finder, request_of(vendors=["Siemens"], products=["Siemens WinCC V7.5"]))
    assert result.evidence[0].applicability == Applicability.UNKNOWN


def test_an_asset_that_records_no_product_cannot_be_tied_to_a_vulnerability_or_advisory() -> None:
    docs = [
        vulnerability_doc("CVE-1", "Apache", "HTTP Server"),
        advisory_doc("ICSA-24-001-01"),
        technique_doc("T1"),
    ]
    result, _ = one(finder_of(docs)[0], request_of(types=IT | OT))
    assert refs(result) == {"T1"}
    decisions = {c.ref: c.decision for c in result.search.considered}
    assert decisions["CVE-1"] == decisions["ICSA-24-001-01"] == EvidenceDecision.NO_PRODUCT_LINK


def test_a_technique_has_no_applicability_and_a_known_version_confirms_only_inside_the_range() -> None:
    entry = {
        "vendor": "Siemens",
        "product": "WinCC",
        "versions": [{"start": "7.0", "end": "7.5", "end_inclusive": True}],
    }
    docs = [vulnerability_doc("CVE-5", "Siemens", "WinCC", affected=[entry]), technique_doc("T1")]
    result, _ = one(finder_of(docs)[0], request_of(**WINCC, versions=["7.2"]))
    by_ref = {item.ref: item for item in result.evidence}
    assert by_ref["T1"].applicability is None and by_ref["CVE-5"].applicability == Applicability.CONFIRMED
    # G229: only a weakness confirmed in the asset's product is direct evidence; a technique is context.
    assert (by_ref["CVE-5"].role, by_ref["T1"].role) == (EvidenceRole.DIRECT, EvidenceRole.CONTEXT)
    outside, _ = one(finder_of(docs)[0], request_of(**WINCC, versions=["8.0"]))
    assert refs(outside) == {"T1"}


def test_no_index_yet_or_no_request_means_no_search_and_no_error() -> None:
    empty = empty_index(TextEmbeddings(), ScoredBy())
    finder = EvidenceFinder(lambda: empty, 1.0, gate=RerankGate(1))
    result, summary = one(finder, request_of())
    assert result.evidence == () and result.search.snapshot_id is None and result.search.considered == ()
    assert (summary.snapshot_id, summary.threats_searched, summary.source_versions) == (None, 0, {})
    full, embeddings = finder_of([technique_doc("T1")])
    results, summary = full.find_evidence([], stale=True)
    assert (
        results == []
        and summary.snapshot_id is None
        and not summary.stale
        and "query" not in embeddings.calls
    )


def test_an_embedding_outage_leaves_every_request_without_evidence_and_says_why() -> None:
    finder, embeddings = finder_of([technique_doc("T1")])
    embeddings.queries_down = True
    results, summary = finder.find_evidence([request_of(), request_of("Threat: other")], stale=False)
    assert all(r.evidence == () and r.search.failure == EvidenceSearchFailure.UNAVAILABLE for r in results)
    assert (summary.threats_searched, summary.threats_with_evidence) == (2, 0)


def test_a_rerank_outage_costs_only_the_request_it_hit() -> None:
    class DownFor(ScoredBy):
        def score_relevance(self, query: str, documents: list[str]) -> list[float]:
            if "phishing" in query:
                raise Unavailable("down")
            return super().score_relevance(query, documents)

    finder, _ = finder_of([technique_doc("T1")], DownFor())
    first, second = finder.find_evidence(
        [request_of(), request_of("Threat: phishing ransomware")], stale=False
    )[0]
    assert refs(first) == {"T1"} and second.evidence == ()
    assert second.search.failure == EvidenceSearchFailure.UNAVAILABLE


def test_all_requests_of_a_batch_are_embedded_in_one_call() -> None:
    finder, embeddings = finder_of([technique_doc("T1")])
    requests = [request_of(f"Threat: ransomware {n}") for n in range(5)]
    results, summary = finder.find_evidence(requests, stale=False)
    assert embeddings.calls.count("query") == 1 and len(results) == 5 and summary.threats_searched == 5


def test_a_stale_index_is_still_used_but_marked() -> None:
    finder, _ = finder_of([technique_doc("T1")])
    result, summary = one(finder, request_of(), stale=True)
    assert refs(result) == {"T1"} and result.search.stale and summary.stale
    assert summary.source_versions == {"mitre_attack_enterprise": "r1"}
    assert (summary.threats_with_evidence, summary.evidence_used) == (1, 1)


def test_facts_are_plain_sentences_without_any_id() -> None:
    uses = [
        {"name": "Stuxnet", "kind": "software"},
        {"name": "Sandworm Team", "kind": "group"},
        {"name": "Triton", "kind": "software"},
    ]
    docs = [
        technique_doc("T1486", real_world_use=uses, mitigations=["Data Backup", "Audit"], tactics=["impact"]),
        vulnerability_doc("CVE-2024-0009", "Siemens", "WinCC", known_ransomware_use=True, epss=0.4321),
    ]
    result, _ = one(finder_of(docs)[0], request_of(**WINCC))
    by_ref = {item.ref: item for item in result.evidence}
    facts = by_ref["T1486"].facts
    assert "Stuxnet, a piece of malicious software, has used this technique." in facts
    assert not any("Triton" in fact for fact in facts)  # two users at most
    assert (
        "It can be reduced by: Data Backup, Audit." in facts
        and "It is used for these attacker goals: impact." in facts
    )
    vuln = by_ref["CVE-2024-0009"].facts
    assert (
        vuln[0] == "CISA lists weaknesses in Siemens WinCC as exploited in real attacks (added 2024-03-01)."
    )
    assert "It scored 43% likelihood of exploitation in the next 30 days." in vuln
    assert not any(IDS.search(fact) for item in result.evidence for fact in item.facts)
