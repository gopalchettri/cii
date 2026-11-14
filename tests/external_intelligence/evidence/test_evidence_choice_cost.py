"""Choosing a threat's evidence: an entry is built only for the records kept (EVIDENCE_KEPT_PER_THREAT), and
the choice and every row are what the rules give on a mixed set of candidates."""

from typing import Any

from app.core.constants import Applicability, EvidenceDecision, EvidenceReason, IntelKind, IntelSource
from app.domain.external_intelligence.evidence_finder import EvidenceSelector
from app.domain.external_intelligence.facts import PlainFactWriter
from app.domain.external_intelligence.product_link import ProductLinkChecker
from app.models.external_intelligence.evidence import IntelHit
from tests.external_intelligence.evidence_fakes import request_of

SOURCES = {
    IntelKind.TECHNIQUE: IntelSource.ATTACK_ENTERPRISE,
    IntelKind.VULNERABILITY: IntelSource.CISA_KEV,
    IntelKind.ADVISORY: IntelSource.CISA_ICS,
}
WINCC = {"vendor": "Siemens", "product": "WinCC"}
APACHE = {"vendor": "Apache", "product": "HTTP Server"}
UNKNOWN = Applicability.UNKNOWN


class CountingWriter(PlainFactWriter):
    """Records each record whose facts are written: one per evidence entry built."""

    def __init__(self) -> None:
        super().__init__()
        self.built: list[str] = []

    def write_facts(self, hit: IntelHit) -> tuple[str, ...]:
        self.built.append(hit.external_id)
        return super().write_facts(hit)


def hit_of(ref: str, kind: IntelKind, score: float, **data: Any) -> IntelHit:
    """A reranked candidate, as the selector receives it."""
    text = f"{ref} ransomware encrypts files. Tactics: impact."
    return IntelHit(ref, kind, f"Record {ref}", text, f"https://x/{ref}", SOURCES[kind], "IT", score, data)


def mixed_candidates() -> list[IntelHit]:
    """Best first: used, a duplicate, another product, over the limit, a kind still missing, unlinked, low."""
    return [
        hit_of("T1", IntelKind.TECHNIQUE, 95.0),
        hit_of("CVE-1", IntelKind.VULNERABILITY, 90.0, cve="CVE-1", **WINCC),
        hit_of("T1", IntelKind.TECHNIQUE, 85.0),
        hit_of("T2", IntelKind.TECHNIQUE, 80.0),
        hit_of("CVE-2", IntelKind.VULNERABILITY, 75.0, cve="CVE-2", **APACHE),
        hit_of("T3", IntelKind.TECHNIQUE, 70.0),
        hit_of("ICSA-1", IntelKind.ADVISORY, 65.0, advisory_id="ICSA-1", vendor="Siemens", affected=[WINCC]),
        hit_of("CVE-3", IntelKind.VULNERABILITY, 60.0, cve="CVE-3"),
        hit_of("T4", IntelKind.TECHNIQUE, 20.0),
    ]


def select(scored: list[IntelHit]) -> tuple[Any, Any, CountingWriter]:
    """The selector's choice at threshold 50 with 3 places, for an asset recording Siemens WinCC."""
    writer = CountingWriter()
    recorded = request_of(vendors=["Siemens"], products=["Siemens WinCC"]).recorded_products
    checker = ProductLinkChecker(recorded)
    evidence, considered = EvidenceSelector(50.0, writer, 3).select(scored, checker)
    return evidence, considered, writer


def test_the_choice_on_a_mixed_set_is_what_the_rules_give() -> None:
    """The first 3 usable, then a kind still missing (the advisory) takes the lower technique's place."""
    evidence, considered, _ = select(mixed_candidates())
    assert [(e.ref, e.kind, e.applicability, e.nearest, e.score) for e in evidence] == [
        ("T1", IntelKind.TECHNIQUE, None, False, 95.0),
        ("CVE-1", IntelKind.VULNERABILITY, UNKNOWN, False, 90.0),
        ("ICSA-1", IntelKind.ADVISORY, UNKNOWN, False, 65.0),
    ]
    assert [(e.title, e.url) for e in evidence][0] == ("Record T1", "https://x/T1")
    over = EvidenceReason.OVER_LIMIT.format(limit=3)
    assert [(c.ref, c.decision, c.reason) for c in considered] == [
        ("T1", EvidenceDecision.USED, ""),
        ("CVE-1", EvidenceDecision.USED, ""),
        ("T1", EvidenceDecision.DUPLICATE, EvidenceReason.DUPLICATE.value),
        ("T2", EvidenceDecision.OVER_LIMIT, over),
        ("CVE-2", EvidenceDecision.NOT_APPLICABLE, EvidenceReason.DIFFERENT_PRODUCT.format(**APACHE)),
        ("T3", EvidenceDecision.OVER_LIMIT, over),
        ("ICSA-1", EvidenceDecision.USED, ""),
        ("CVE-3", EvidenceDecision.NO_PRODUCT_LINK, EvidenceReason.NO_PRODUCT_LINK.value),
        ("T4", EvidenceDecision.BELOW_THRESHOLD, "Scored 20.0 of 100, under the 50 needed."),
    ]


def test_the_nearest_choice_marks_each_entry_and_its_row() -> None:
    """None at the threshold: the nearest, by the same rules, each marked and its row giving its score."""
    scored = [hit_of(f"T{n}", IntelKind.TECHNIQUE, 45.0 - n) for n in range(1, 5)]
    scored.insert(1, hit_of("CVE-1", IntelKind.VULNERABILITY, 43.5, cve="CVE-1", **WINCC))
    evidence, considered, _ = select(scored)
    assert [(e.ref, e.applicability, e.nearest) for e in evidence] == [
        ("T1", None, True),
        ("CVE-1", UNKNOWN, True),
        ("T2", None, True),
    ]
    assert [(c.ref, c.decision) for c in considered] == [
        ("T1", EvidenceDecision.USED),
        ("CVE-1", EvidenceDecision.USED),
        ("T2", EvidenceDecision.USED),
        ("T3", EvidenceDecision.OVER_LIMIT),
        ("T4", EvidenceDecision.OVER_LIMIT),
    ]
    assert considered[1].reason == "Scored 43.5 of 100, under the 50 needed."


def test_an_entry_is_built_only_for_the_records_kept() -> None:
    """Building an entry cleans its title, link, facts and mitigations: a usable record over the limit is
    never built, in either pass."""
    evidence, _, writer = select(mixed_candidates())
    assert writer.built == [e.ref for e in evidence] == ["T1", "CVE-1", "ICSA-1"]
    nearest = [hit_of(f"T{n}", IntelKind.TECHNIQUE, 45.0 - n) for n in range(1, 8)]
    evidence, _, writer = select(nearest)
    assert writer.built == [e.ref for e in evidence] == ["T1", "T2", "T3"]
