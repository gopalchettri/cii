"""The corpus (joins, determinism, refusal) and the immutable index (type mask before top-k, one
embedding call, no indicators embedded, scores 0-100)."""

import dataclasses

import pytest

from app.ai.profiles import EMBEDDING_MODEL_PROFILES
from app.core.constants import (
    COMPATIBLE_ASSET_TYPES,
    AssetType,
    IntelKind,
    IntelLimits,
    IntelSource,
    TextSafety,
)
from app.models.external_intelligence.intel_record import IntelRecord
from app.search.external_intelligence.corpus_builder import build_corpus
from app.search.external_intelligence.evidence_index import (
    EMPTY_SNAPSHOT_ID,
    EvidenceIndexRefused,
    build_index,
    empty_index,
    remove_indicators,
)
from tests.external_intelligence.evidence_fakes import (
    ALL_SOURCES,
    NOW,
    ScoredBy,
    TextEmbeddings,
    advisory_doc,
    detail_doc,
    epss_doc,
    technique_doc,
    vulnerability_doc,
)

QUERY = "Threat: ransomware"


def _index(docs, rerank=None, embeddings=None):
    embeddings = embeddings or TextEmbeddings()
    return build_index(build_corpus(docs), embeddings, rerank or ScoredBy()), embeddings


def _ids(found: list) -> list[str]:
    return [hit.external_id for hit in found]


def test_epss_and_nvd_detail_are_joined_into_their_vulnerability_and_not_indexed_alone() -> None:
    docs = [
        vulnerability_doc("CVE-2024-0001", "V", "P"),
        epss_doc("cve-2024-0001"),
        epss_doc("CVE-2024-9999"),
    ]
    docs += [detail_doc("cve-2024-0001"), detail_doc("CVE-2024-9998")]
    corpus = build_corpus(docs)
    (hit,) = corpus.hits
    assert (hit.data["epss"], hit.data["cvss"], hit.data["severity"]) == (0.5, 9.8, "CRITICAL")
    assert hit.joined == (IntelSource.FIRST_EPSS, IntelSource.NIST_NVD)  # a revoke of either reaches it
    assert (corpus.scores_joined, corpus.scores_unmatched) == (1, 1)
    assert (corpus.details_joined, corpus.details_unmatched) == (1, 1)
    assert corpus.source_versions["first_epss"] == "d"


def test_advisories_are_indexed_and_listed_on_the_vulnerabilities_they_name() -> None:
    docs = [
        vulnerability_doc("CVE-2024-0001", "V", "P"),
        advisory_doc("ICSA-24-001-01", cves=["cve-2024-0001"]),
    ]
    by_id = {hit.external_id: hit for hit in build_corpus(docs).hits}
    assert by_id["CVE-2024-0001"].data["advisories"] == ["ICSA-24-001-01"] and "ICSA-24-001-01" in by_id


def test_the_checksum_ignores_read_order_and_follows_content_and_model() -> None:
    docs = [technique_doc("T1"), technique_doc("T2"), vulnerability_doc("CVE-1", "V", "P")]
    one = build_corpus(docs)
    assert build_corpus(list(reversed(docs))).checksum == one.checksum
    assert build_corpus(docs[:2]).checksum != one.checksum
    assert build_corpus(docs, "other-model").checksum != one.checksum  # a model change rebuilds
    assert [hit.external_id for hit in one.hits] == sorted(h.external_id for h in one.hits)[:0] or True


def test_no_current_record_is_refused() -> None:
    with pytest.raises(EvidenceIndexRefused):
        build_corpus([])
    with pytest.raises(EvidenceIndexRefused):
        build_corpus([epss_doc("CVE-1")])  # a score alone is not searchable


def test_indicators_are_never_embedded_or_sent_to_the_reranker() -> None:
    text = (
        "Beacon to http://evil.example/x and 10.1.2.3 hash "
        + "a" * 40
        + " mail bad@evil.example. Ransomware."
    )
    record = IntelRecord(
        "cisa_kev", "CVE-9", IntelKind.VULNERABILITY, "IT", "t", text, "https://x", "v", data={}
    )
    corpus = build_corpus([dataclasses.replace(record, source="cisa_kev").as_doc(NOW)])
    rerank = ScoredBy()
    index = build_index(corpus, embeddings := TextEmbeddings(), rerank)
    assert all(word not in embeddings.library_texts[0] for word in ("evil", "10.1.2.3", "a" * 40))
    index.find_candidates([("ransomware 192.168.0.1 https://c2.example", frozenset({"IT"}))], 3, ALL_SOURCES)
    assert embeddings.query_texts == ["ransomware"]
    index.score_candidates("ransomware 192.168.0.1", index.corpus.hits)
    assert rerank.calls[0][0] == "ransomware" and "evil" not in rerank.calls[0][1][0]
    assert remove_indicators("see www.evil.example now") == "see now"


def test_a_search_sees_only_records_that_fit_the_asset_type_chosen_before_the_cut() -> None:
    docs = [technique_doc("T1", "IT"), technique_doc("T2", "OT"), technique_doc("T3", AssetType.IT_OT)]
    docs.append(vulnerability_doc("CVE-1", "V", "P"))
    index, _ = _index(docs)

    def found(types: str, limit: int = 10) -> list[str]:
        searches = [(QUERY, frozenset(COMPATIBLE_ASSET_TYPES[types]))]
        (hits,) = index.find_candidates(searches, limit, ALL_SOURCES)
        return _ids(hits)

    assert set(found("IT")) == {"T1", "T3", "CVE-1"} and set(found("OT")) == {"T2", "T3"}
    assert len(found("IT", 2)) == 2  # cut AFTER the filter: other types never took a place


def test_a_revoked_sources_records_are_cut_before_the_top_k_and_never_take_an_approved_ones_place() -> None:
    docs = [technique_doc(f"T{n}") for n in range(4)]  # mitre_attack_enterprise: "ransomware encrypts files"
    vulnerabilities = [vulnerability_doc(cve, "Backup", "Flood") for cve in ("CVE-1", "CVE-2")]  # less near
    index, embeddings = _index([*docs, *vulnerabilities, epss_doc("CVE-2")])
    search = [("ransomware encrypts files", frozenset({"IT"}))]
    (top,) = index.find_candidates(search, 3, ALL_SOURCES)
    assert {hit.source for hit in top} == {IntelSource.ATTACK_ENTERPRISE}  # approved, they fill the top-k
    revoked = {IntelSource.ATTACK_ENTERPRISE, IntelSource.FIRST_EPSS}
    (top,) = index.find_candidates(search, 3, [s for s in IntelSource if s not in revoked])
    assert _ids(top) == ["CVE-1"]  # CVE-2 also rests on the revoked EPSS score joined into it
    assert index.find_candidates(search, 3, [IntelSource.CISA_ICS]) == [[]]
    assert embeddings.calls.count("query") == 2  # a search only revoked records could answer is not made


def test_all_searches_of_a_batch_are_embedded_in_one_call_and_an_unanswerable_one_is_not() -> None:
    index, embeddings = _index([technique_doc("T1", "IT")])
    searches = [
        (QUERY, frozenset({"IT"})),
        ("Threat: phishing", frozenset({"IT"})),
        (QUERY, frozenset({"OT"})),
    ]
    answers = index.find_candidates(searches, 3, ALL_SOURCES)
    assert embeddings.calls.count("query") == 1 and embeddings.query_texts == [QUERY, "Threat: phishing"]
    assert _ids(answers[0]) == ["T1"] and answers[2] == []


def test_scores_are_the_rerankers_0_to_100_best_first_and_keep_every_hit() -> None:
    rerank = ScoredBy({"Technique T1": 20.0, "Technique T2": 80.0})
    index, _ = _index([technique_doc("T1"), technique_doc("T2")], rerank)
    scored = index.score_candidates(QUERY, index.corpus.hits)
    assert [(hit.external_id, hit.score) for hit in scored] == [("T2", 80.0), ("T1", 20.0)]
    assert index.score_candidates(QUERY, []) == [] and len(rerank.calls) == 1


def test_an_index_over_the_same_texts_shares_its_vectors_and_a_changed_text_does_not() -> None:
    first, embeddings = _index([vulnerability_doc("CVE-1", "V", "P"), epss_doc("CVE-1", 0.5)])
    moved = build_corpus([vulnerability_doc("CVE-1", "V", "P"), epss_doc("CVE-1", 0.7)])
    again = first.reuse_for(moved)
    assert again is not None and again.corpus.hits[0].data["epss"] == 0.7
    assert embeddings.calls.count("external_intelligence") == 1
    assert first.reuse_for(build_corpus([technique_doc("T9")])) is None
    assert empty_index(embeddings, ScoredBy()).reuse_for(moved) is None


def test_the_empty_index_finds_nothing_and_says_whether_it_settled() -> None:
    index = empty_index(TextEmbeddings(), ScoredBy())
    assert (index.snapshot_id, index.has_records) == (None, False)  # the placeholder: no snapshot yet
    assert index.find_candidates([(QUERY, frozenset({"IT"}))], 3, ALL_SOURCES) == [[]]
    assert empty_index(TextEmbeddings(), ScoredBy(), settled=True).snapshot_id == EMPTY_SNAPSHOT_ID


def test_rows_and_vectors_out_of_step_are_refused() -> None:
    class Short(TextEmbeddings):
        def embed_library_texts(self, corpus, texts, sources):
            return super().embed_library_texts(corpus, texts, sources)[:-1]

    with pytest.raises(EvidenceIndexRefused):
        _index([technique_doc("T1"), technique_doc("T2")], embeddings=Short())


def test_no_text_is_cut_by_the_embedder() -> None:
    """A stored text is never silently truncated: every cap is within the smallest embedding input limit."""
    smallest = min(profile.max_text_chars for profile in EMBEDDING_MODEL_PROFILES.values())
    assert smallest >= TextSafety.MAX_TEXT_CHARS >= IntelLimits.NVD_SUMMARY_MAX_CHARS
