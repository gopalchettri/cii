"""Applicability from the asset's recorded vendors and products, and the evidence limit keeping every kind."""

from typing import Any

import pytest

from app.core.constants import Applicability, AssetType, EvidenceDecision
from app.domain.external_intelligence.evidence_finder import EvidenceFinder
from app.domain.external_intelligence.rerank_gate import RerankGate
from app.models.external_intelligence.evidence_request import (
    EvidenceRequest,
    RecordedProduct,
    RecordedProducts,
)
from app.search.external_intelligence.corpus_builder import build_corpus
from app.search.external_intelligence.evidence_index import build_index
from tests.external_intelligence.evidence_fakes import (
    ALL_SOURCES,
    ScoredBy,
    TextEmbeddings,
    advisory_doc,
    technique_doc,
    vulnerability_doc,
)

WINCC = {"vendors": ("Siemens",), "products": ("Siemens WinCC",)}
ALL_TYPES = frozenset({"IT", "OT", AssetType.IT_OT})


ENTRY: dict[str, Any] = {"vendor": "Siemens", "product": "WinCC", "versions": [], "fixed": []}
PRODUCT = RecordedProduct(**WINCC)


def verdict(docs: list[dict], *rows: RecordedProduct, scores: dict[str, float] | None = None):
    index = build_index(build_corpus(docs), TextEmbeddings(), ScoredBy(scores or {}))
    finder = EvidenceFinder(lambda: index, 1.0, gate=RerankGate(1), candidates=6, kept_per_threat=3)
    request = EvidenceRequest("Threat: ransomware", ALL_TYPES, RecordedProducts(tuple(rows)))
    (result,), _ = finder.find_evidence([request], approved=ALL_SOURCES)
    return result


def applicability_of(doc: dict, *rows: RecordedProduct) -> Applicability | None:
    result = verdict([doc], *rows)
    return result.evidence[0].applicability if result.evidence else None


def test_an_advisory_is_judged_like_a_vulnerability() -> None:
    doc = advisory_doc("ICSA-24-001-01", ENTRY)
    assert applicability_of(doc, PRODUCT) == Applicability.UNKNOWN
    assert applicability_of(doc, RecordedProduct(("Acme",), ("Acme Hist",))) is None  # left out
    assert applicability_of(advisory_doc("ICSA-24-002-01"), PRODUCT) == Applicability.UNKNOWN


def test_a_vendors_other_product_is_left_out() -> None:
    doc = vulnerability_doc("CVE-7", "Siemens", "Simatic")
    result = verdict([doc], RecordedProduct(("Siemens",), ("Siemens WinCC",)))
    assert result.search.considered[0].decision == EvidenceDecision.NOT_APPLICABLE


@pytest.mark.parametrize("limit_case", ["places", "kind"])
def test_the_limit_keeps_a_record_of_every_kind_that_passed(limit_case: str) -> None:
    docs = [technique_doc(f"T{n}", "OT") for n in range(1, 6)] + [advisory_doc("ICSA-24-009-01", ENTRY)]
    scores = {f"Technique T{n}": 95.0 - n for n in range(1, 6)} | {"ICSA-24-009-01": 80.0}
    if limit_case == "kind":
        scores["ICSA-24-009-01"] = 0.5  # failed the threshold: takes no place
    result = verdict(docs, PRODUCT, scores=scores)
    expected = ["T1", "T2", "ICSA-24-009-01"] if limit_case == "places" else ["T1", "T2", "T3"]
    assert [item.ref for item in result.evidence] == expected
