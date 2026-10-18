"""Applicability from the asset's recorded products (a version is only read beside its own product) and the
evidence limit keeping every kind that passed. Never CONFIRMED from partial data. Versions are compared by the
packaging library: one it cannot read is "not known", never guessed."""

from typing import Any

import pytest

from app.core.constants import Applicability, AssetType, EvidenceDecision
from app.domain.external_intelligence.evidence_finder import EvidenceFinder
from app.domain.external_intelligence.product_link import affected_state
from app.domain.external_intelligence.rerank_gate import RerankGate
from app.models.external_intelligence.evidence_request import (
    EvidenceRequest,
    RecordedProduct,
    RecordedProducts,
)
from app.search.external_intelligence.corpus_builder import build_corpus
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
    index = build_index(build_corpus(docs), TextEmbeddings(), ScoredBy(scores or {}))
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


def test_versions_compare_as_pep_440_versions() -> None:
    upto = entry([rng(end="2.10", ei=False)])
    assert affected_state("2.9", upto) is True and affected_state("2.10.0", upto) is False
    assert affected_state("v1.0", entry([rng("1", "1", ei=True)])) is True
    release = entry([rng(end="2.3", ei=False)])
    assert affected_state("2.3rc1", release) is True and affected_state("1.0-beta2", release) is True


@pytest.mark.parametrize("bad", ["", "latest", "2.3 and earlier", "1.x", "2.3 sp1", None, 7, "9" * 70])
def test_a_version_packaging_cannot_read_is_not_known(bad: Any) -> None:
    assert affected_state(bad, entry([rng(end="9")])) is None
    assert affected_state("2.3", entry([rng(end=bad if isinstance(bad, str) and bad else "n/a")])) is None


def test_range_ends_can_be_inclusive_or_exclusive_and_a_fix_ends_the_range() -> None:
    upto, before = entry([rng(end="2.3", ei=True)]), entry([rng(end="2.3", ei=False)])
    assert (affected_state("2.3", upto), affected_state("2.3", before)) == (True, False)
    between = entry([rng("1.0", "2.0", si=False)])
    assert (affected_state("1.0", between), affected_state("1.5", between)) == (False, True)
    fixed = entry([rng(end="2.4")], ["2.4"])
    assert (affected_state("2.3", fixed), affected_state("2.5", fixed)) == (True, False)


def test_a_record_that_contradicts_itself_or_cannot_be_read_is_never_guessed() -> None:
    assert affected_state("3.0", entry([rng("3.0", "3.9"), rng("2.0", "2.4")], ["2.4"])) is None
    assert affected_state("2.3", entry([rng(end="2.4")], ["soon"])) is None
    for bad in (entry([]), entry([{}]), {"versions": "all"}, {}):
        assert affected_state("2.3", bad) is None
    assert affected_state("2.3", entry(["junk", rng(end="9")])) is True
    assert affected_state("2.3", entry([{"start": "1", "end": "9", "end_inclusive": "yes"}])) is None


def test_a_missing_start_flag_is_inclusive_and_no_bounds_means_every_version() -> None:
    from_two = entry([{"start": "2.0", "end": "3.0", "end_inclusive": False}])
    assert (affected_state("2.0", from_two), affected_state("3.0", from_two)) == (True, False)
    every = [{"start": None, "end": None, "end_inclusive": False}]
    assert (
        affected_state("9.9", entry(every)) is True and affected_state("9.9", entry(every, ["9.0"])) is None
    )
    assert affected_state("9.9", entry(every, ["10.0"])) is True
