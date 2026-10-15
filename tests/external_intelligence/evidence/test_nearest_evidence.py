"""G254 (owner 2026-10-15: "with external intelligence on, if no evidence is identified, provide at least 1
which is nearby; do not make it empty"): when no candidate passes, the search keeps the closest one, never as
evidence: the best technique first, else the best candidate whose product is not ruled out."""

from tests.external_intelligence.evidence.test_evidence_finder import IT, OT, finder_of, one
from tests.external_intelligence.evidence_fakes import ScoredBy, request_of, technique_doc, vulnerability_doc


def test_none_passing_keeps_the_best_technique_as_the_nearest_never_as_evidence() -> None:
    docs = [technique_doc("T1"), technique_doc("T2"), vulnerability_doc("CVE-1", "Siemens", "WinCC")]
    scores = {"Technique T1": 2.0, "Technique T2": 3.0, "CVE-1": 9.0}
    finder, _ = finder_of(docs, ScoredBy(scores), threshold=50.0)
    result, _ = one(finder, request_of(vendors=["Siemens"], products=["Siemens WinCC"]))
    assert result.evidence == () and result.nearest is not None
    assert result.nearest.ref == "T2"  # a technique first, though the weakness scored higher


def test_with_no_technique_the_nearest_is_never_a_product_ruled_out() -> None:
    docs = [
        vulnerability_doc("CVE-1", "Apache", "HTTP Server"),
        vulnerability_doc("CVE-2", "Siemens", "WinCC"),
    ]
    finder, _ = finder_of(docs, ScoredBy({"CVE-1": 9.0, "CVE-2": 4.0}), threshold=50.0)
    result, _ = one(finder, request_of(vendors=["Siemens"], products=["Siemens WinCC"]))
    assert result.evidence == () and result.nearest is not None and result.nearest.ref == "CVE-2"


def test_evidence_that_passes_leaves_no_nearest_and_no_candidate_leaves_none() -> None:
    passing, _ = finder_of([technique_doc("T1")], ScoredBy(default=90.0), threshold=50.0)
    assert one(passing, request_of())[0].nearest is None
    nothing, _ = finder_of([technique_doc("T1", asset_type="IT")], threshold=50.0)
    result, _ = one(nothing, request_of(types=OT - IT))
    assert result.evidence == () and result.nearest is None


def test_an_asset_with_no_recorded_product_never_gets_a_weakness_as_its_nearest() -> None:
    """A weakness tied to no product of the asset says nothing true about it: never shown as its nearest."""
    finder, _ = finder_of(
        [vulnerability_doc("CVE-1", "Siemens", "WinCC")], ScoredBy(default=9.0), threshold=50.0
    )
    result, _ = one(finder, request_of())  # no product recorded
    assert result.evidence == () and result.nearest is None
