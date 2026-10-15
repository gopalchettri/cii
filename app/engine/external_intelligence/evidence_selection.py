"""Which of a threat's scored candidates become evidence, and why each other one did not.

The rules run in this order for every candidate, best score first: under the threshold; a product-specific
record (vulnerability, advisory) the asset's recorded products cannot tie; a different product (or a version
outside the affected ones); a duplicate. What passes is cut to the limit, but never so that one kind
(technique, advisory, vulnerability) takes every place while another kind has a record that passed. Every
candidate is returned with its decision. Scores are 0-100 ranking scores of one reranker, compared only with
the threshold set for that reranker."""

from collections.abc import Sequence

from app.core.constants import (
    Applicability,
    EvidenceDecision,
    EvidenceLimits,
    EvidenceReason,
    EvidenceRole,
    IntelKind,
)
from app.engine.external_intelligence.evidence_limit import choose_within_limit
from app.engine.external_intelligence.plain_facts import PlainFactWriter
from app.engine.external_intelligence.product_link import ProductLinkChecker
from app.models.external_intelligence.evidence import Considered, Evidence, IntelHit

#: The kinds whose record says which products and versions it concerns.
_HAS_APPLICABILITY = (IntelKind.VULNERABILITY, IntelKind.ADVISORY)
Judged = tuple[Evidence | None, Considered]


class EvidenceSelector:
    """Holds no request's state: the request's product checker is handed to each call."""

    def __init__(
        self, threshold: float, writer: PlainFactWriter, limit: int = EvidenceLimits.PER_THREAT
    ) -> None:
        self._threshold = threshold
        self._writer = writer
        self._limit = limit

    def select(
        self, scored: Sequence[IntelHit], checker: ProductLinkChecker
    ) -> tuple[tuple[Evidence, ...], tuple[Considered, ...]]:
        """The evidence used (best first, at most the limit) and one row per candidate, in score order."""
        usable: list[Evidence] = []
        rows: list[Considered | Evidence] = []
        for hit in scored:  # best first, so the limit keeps the most relevant
            evidence, row = self._judge(hit, usable, checker)
            if evidence is not None:
                usable.append(evidence)
            rows.append(evidence or row)
        used = choose_within_limit(usable, self._limit)
        return tuple(used), tuple(self._final_row(row, used) for row in rows)

    def _judge(self, hit: IntelHit, usable: list[Evidence], checker: ProductLinkChecker) -> Judged:
        if hit.score < self._threshold:
            reason = EvidenceReason.BELOW_THRESHOLD.format(score=hit.score, threshold=self._threshold)
            return _left_out(hit, EvidenceDecision.BELOW_THRESHOLD, reason)
        applicability = None
        if hit.kind in _HAS_APPLICABILITY:
            if checker.has_no_link(hit):
                return _left_out(hit, EvidenceDecision.NO_PRODUCT_LINK, EvidenceReason.NO_PRODUCT_LINK.value)
            applicability, reason = checker.judge(hit)
            if applicability == Applicability.NOT_APPLICABLE:
                return _left_out(hit, EvidenceDecision.NOT_APPLICABLE, self._writer.safe_reason(reason))
        if any(item.ref == hit.external_id for item in usable):
            return _left_out(hit, EvidenceDecision.DUPLICATE, EvidenceReason.DUPLICATE.value)
        used = Considered(hit.external_id, hit.score, EvidenceDecision.USED)
        return self._evidence(hit, applicability), used

    def nearest(self, scored: Sequence[IntelHit], checker: ProductLinkChecker) -> Evidence | None:
        """G254 (owner 2026-10-15: "if no evidence is identified, provide at least 1 which is nearby"): when
        no candidate passed, the closest one, shown and never cited: the best technique (a method of attack
        says nothing about the asset's product), else the best other candidate whose product is not ruled
        out. None: the search had no candidate at all."""
        techniques = [hit for hit in scored if hit.kind == IntelKind.TECHNIQUE]
        for hit in techniques or scored:  # best first
            applicability = None
            if hit.kind in _HAS_APPLICABILITY:
                if checker.has_no_link(hit):
                    continue
                applicability, _ = checker.judge(hit)
                if applicability == Applicability.NOT_APPLICABLE:
                    continue
            return self._evidence(hit, applicability)
        return None

    def _evidence(self, hit: IntelHit, applicability: Applicability | None) -> Evidence:
        return Evidence(
            hit.external_id,
            hit.kind,
            hit.source,
            self._writer.safe_title(hit),
            self._writer.safe_url(hit),
            hit.score,
            self._writer.write_facts(hit),
            applicability,
            published=hit.modified,
            fetched_at=hit.fetched_at,
            # G229: direct only when the weakness is confirmed in the asset's own product; else context.
            role=EvidenceRole.DIRECT if applicability == Applicability.CONFIRMED else EvidenceRole.CONTEXT,
            mitigations=self._writer.safe_mitigations(hit),  # G234: the control search reads them
        )

    def _final_row(self, row: Considered | Evidence, used: list[Evidence]) -> Considered:
        """A usable record is USED when it fit the limit, else OVER_LIMIT; others stand."""
        if isinstance(row, Considered):
            return row
        if any(row is item for item in used):
            return Considered(row.ref, row.score, EvidenceDecision.USED)
        reason = EvidenceReason.OVER_LIMIT.format(limit=self._limit)
        return Considered(row.ref, row.score, EvidenceDecision.OVER_LIMIT, reason)


def _left_out(hit: IntelHit, decision: EvidenceDecision, reason: str) -> Judged:
    return None, Considered(hit.external_id, hit.score, decision, reason)
