"""The corpus (determinism, refusal) and the immutable index (type mask before top-k, one
embedding call, no indicators embedded, scores 0-100)."""

import dataclasses

import pytest

from app.ai.profiles import EMBEDDING_MODEL_PROFILES
from app.core.constants import IntelKind, TextSafety
from app.domain.intel.index import (
    EMPTY_SNAPSHOT_ID,
    EvidenceIndexRefused,
    build_corpus,
    build_index,
    empty_index,
    remove_indicators,
)
from app.schemas.intel_records import IntelRecord
from tests.external_intelligence.evidence_fakes import NOW, ScoredBy, TextEmbeddings, technique_doc

QUERY = "Threat: ransomware"


def _index(docs, rerank=None, embeddings=None):
    embeddings = embeddings or TextEmbeddings()
    return build_index(build_corpus(docs), embeddings, rerank or ScoredBy()), embeddings


def _ids(found: list) -> list[str]:
    return [hit.external_id for hit in found]


def test_indicators_are_never_embedded_or_sent_to_the_reranker() -> None:
    text = "Beacon to http://evil.example/x and 10.1.2.3 hash " + "a" * 40 + " mail bad@evil.example. Ransomware."
    record = IntelRecord(
        "mitre_attack_enterprise", "T9", IntelKind.TECHNIQUE, "IT", "t", text, "https://x", "v", data={}
    )
    corpus = build_corpus([dataclasses.replace(record, source="mitre_attack_enterprise").as_doc(NOW)])
    rerank = ScoredBy()
    index = build_index(corpus, embeddings := TextEmbeddings(), rerank)
    assert all(word not in embeddings.library_texts[0] for word in ("evil", "10.1.2.3", "a" * 40))
    index.find_candidates([("ransomware 192.168.0.1 https://c2.example", frozenset({"IT"}))], 3)
    assert embeddings.query_texts == ["ransomware"]
    index.score_candidates("ransomware 192.168.0.1", index.corpus.hits)
    assert rerank.calls[0][0] == "ransomware" and "evil" not in rerank.calls[0][1][0]
    assert remove_indicators("see www.evil.example now") == "see now"


def test_all_searches_of_a_batch_are_embedded_in_one_call_and_an_unanswerable_one_is_not() -> None:
    index, embeddings = _index([technique_doc("T1", "IT")])
    searches = [(QUERY, frozenset({"IT"})), ("Threat: phishing", frozenset({"IT"})), (QUERY, frozenset({"OT"}))]
    answers = index.find_candidates(searches, 3)
    assert embeddings.calls.count("query") == 1 and embeddings.query_texts == [QUERY, "Threat: phishing"]
    assert embeddings.query_corpora == ["external_intelligence"]
    assert _ids(answers[0]) == ["T1"] and answers[2] == []


def test_scores_are_the_rerankers_0_to_100_best_first_and_keep_every_hit() -> None:
    rerank = ScoredBy({"Technique T1": 20.0, "Technique T2": 80.0})
    index, _ = _index([technique_doc("T1"), technique_doc("T2")], rerank)
    scored = index.score_candidates(QUERY, index.corpus.hits)
    assert [(hit.external_id, hit.score) for hit in scored] == [("T2", 80.0), ("T1", 20.0)]
    assert index.score_candidates(QUERY, []) == [] and len(rerank.calls) == 1


def test_the_empty_index_finds_nothing_and_says_whether_it_settled() -> None:
    index = empty_index(TextEmbeddings(), ScoredBy())
    assert (index.snapshot_id, index.has_records) == (None, False)  # the placeholder: no snapshot yet
    assert index.find_candidates([(QUERY, frozenset({"IT"}))], 3) == [[]]
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
    assert smallest >= TextSafety.MAX_TEXT_CHARS
