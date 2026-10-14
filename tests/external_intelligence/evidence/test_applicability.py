"""Applicability from the asset's recorded products (a version is only read beside its own product) and the
evidence limit keeping every kind that passed. Never CONFIRMED from partial data."""

from typing import Any

import pytest

from app.core.constants import Applicability, AssetType, EvidenceDecision
from app.engine.external_intelligence.evidence_finder import EvidenceFinder
from app.engine.external_intelligence.rerank_gate import RerankGate
from app.models.external_intelligence.evidence_request import (
    EvidenceRequest,
    RecordedProduct,
    RecordedProducts,
)
from app.search.external_intelligence.corpus_builder import CorpusBuilder
from app.search.external_intelligence.evidence_index import build_index
from tests.external_intelligence.evidence_fakes import (
    ScoredBy,
    TextEmbeddings,
    advisory_doc,
    technique_doc,
    vulnerability_doc,
)

WINCC = {"vendors": ("Siemens",), "products": ("Siemens WinCC",)}
ALL_TYPES = frozenset({"IT", "OT", AssetType.IT_OT})


def rng(
    start: str | None = None, end: str | None = None, si: bool = True, ei: bool = False
) -> dict[str, Any]:
    return {"start": start, "start_inclusive": si, "end": end, "end_inclusive": ei}


def entry(ranges: list[Any], fixed: list[str] | None = None) -> dict[str, Any]:
    return {"vendor": "Siemens", "product": "WinCC", "versions": ranges, "fixed": fixed or []}


def kev(cve: str, *entries: Any) -> dict[str, Any]:
    return vulnerability_doc(cve, "Siemens", "WinCC", affected=list(entries))


def verdict(docs: list[dict], *rows: RecordedProduct, scores: dict[str, float] | None = None):
    index = build_index(CorpusBuilder().build_corpus(docs), TextEmbeddings(), ScoredBy(scores or {}))
    finder = EvidenceFinder(lambda: index, 1.0, gate=RerankGate(1))
    request = EvidenceRequest("Threat: ransomware", ALL_TYPES, RecordedProducts(tuple(rows)))
    (result,), _ = finder.find_evidence([request], stale=False)
    return result


def product(version: str | None = None, **fields: Any) -> RecordedProduct:
    return RecordedProduct(**({**WINCC, **fields} | ({"versions": (version,)} if version else {})))


def applicability_of(doc: dict, *rows: RecordedProduct) -> Applicability | None:
    result = verdict([doc], *rows)
    return result.evidence[0].applicability if result.evidence else None


def test_a_known_version_inside_a_range_is_confirmed() -> None:
    doc = kev("CVE-1", entry([rng("7.0", "7.5", ei=True)], ["7.6"]))
    assert applicability_of(doc, product("7.2")) == Applicability.CONFIRMED


def test_a_known_version_outside_every_range_or_fixed_is_left_out_with_the_reason() -> None:
    doc = kev("CVE-2", entry([rng("7.0", "7.5", ei=True)], ["7.6"]))
    for version in ("7.6", "6.9", "8.0"):
        result = verdict([doc], product(version))
        assert (
            result.evidence == () and result.search.considered[0].decision == EvidenceDecision.NOT_APPLICABLE
        )
        assert "version" in result.search.considered[0].reason


def test_no_version_an_unreadable_one_or_two_different_ones_stay_unknown() -> None:
    doc = kev("CVE-3", entry([rng("7.0", "7.5", ei=True)]))
    assert applicability_of(doc, product()) == Applicability.UNKNOWN
    assert applicability_of(doc, product("seven")) == Applicability.UNKNOWN
    assert applicability_of(doc, product(versions=("7.1", "9.9"))) == Applicability.UNKNOWN
    assert applicability_of(kev("CVE-4", entry([])), product("7.1")) == Applicability.UNKNOWN


def test_a_version_never_confirms_without_the_whole_product_named() -> None:
    wide = {"vendor": "Siemens", "product": "WinCC Runtime Advanced", "versions": [rng(end="9")]}
    doc = vulnerability_doc("CVE-5", "Siemens", "WinCC Runtime Advanced", affected=[wide])
    assert applicability_of(doc, product("7.1")) == Applicability.UNKNOWN


def test_a_version_of_another_system_is_not_read_with_this_products_name() -> None:
    doc = kev("CVE-6", entry([rng("7.0", "7.5")]))
    other = RecordedProduct(("Acme",), ("Acme Historian",), ("7.1",))
    assert applicability_of(doc, product(), other) == Applicability.UNKNOWN


def test_an_advisory_is_judged_like_a_vulnerability() -> None:
    doc = advisory_doc("ICSA-24-001-01", entry([rng(end="2.3", ei=True)], ["2.4"]))
    assert applicability_of(doc, product("2.1")) == Applicability.CONFIRMED
    assert applicability_of(doc, product()) == Applicability.UNKNOWN
    assert applicability_of(doc, RecordedProduct(("Acme",), ("Acme Hist",))) is None  # left out
    assert applicability_of(advisory_doc("ICSA-24-002-01"), product()) == Applicability.UNKNOWN


def test_a_vendors_other_product_is_left_out() -> None:
    doc = vulnerability_doc("CVE-7", "Siemens", "Simatic")
    result = verdict([doc], RecordedProduct(("Siemens",), ("Siemens WinCC",)))
    assert result.search.considered[0].decision == EvidenceDecision.NOT_APPLICABLE


@pytest.mark.parametrize("limit_case", ["places", "kind"])
def test_the_limit_keeps_a_record_of_every_kind_that_passed(limit_case: str) -> None:
    docs = [technique_doc(f"T{n}", "OT") for n in range(1, 6)] + [advisory_doc("ICSA-24-009-01", entry([]))]
    scores = {f"Technique T{n}": 95.0 - n for n in range(1, 6)} | {"ICSA-24-009-01": 80.0}
    if limit_case == "kind":
        scores["ICSA-24-009-01"] = 0.5  # failed the threshold: takes no place
    result = verdict(docs, product(), scores=scores)
    expected = ["T1", "T2", "ICSA-24-009-01"] if limit_case == "places" else ["T1", "T2", "T3"]
    assert [item.ref for item in result.evidence] == expected
