"""One STRIDE category, whole: EVERY library threat of the category is judged,
shortlisted ones first so the likeliest are in the first batches; only when none applies (decided after every
category was judged, threat_finder.py), one AI gap-fill.
A gate batch still unusable after its own retries leaves only its threats NOT JUDGED (relevance_gate.py), with
the reason: a technical gap, never a verdict, never the run's failure; such a category gets no gap-fill (its
gap was never proven) and the plan lists it as not fully assessed (path_selector.py)."""

import dataclasses

from app.core.constants import GapFillOutcome, PlanMessage, StrideCategory
from app.core.tracing import traced
from app.engine.scenarios.finding.ai_gap_fill import GapFiller
from app.engine.scenarios.finding.relevance_gate import RelevanceGate
from app.models.library import LibraryThreat
from app.models.threats import CategoryAudit, CategoryFindings, PlannedThreat


class CategoryChecker:
    def __init__(
        self,
        gate: RelevanceGate,
        gap_filler: GapFiller,
        threats_by_category: dict[StrideCategory, list[LibraryThreat]],
    ) -> None:
        self._gate = gate
        self._gap_filler = gap_filler
        self._threats_by_category = threats_by_category

    @traced("threats.category_check")
    def check_category(self, category: StrideCategory, shortlist: list[LibraryThreat]) -> CategoryFindings:
        """One pass: each gate batch is retried on its own (relevance_gate.py), so a bad batch never costs the
        others their verdicts or a second AI call. An outage (Unavailable) is not caught: the job retries."""
        audit = CategoryAudit(category, shortlisted=len(shortlist), whole_category=True)
        accepted = self._gate.judge_library_threats(
            category, self._whole_category(category, shortlist), audit
        )
        audit.relevant = len(accepted)
        return CategoryFindings(accepted=accepted, ai_threat=None, audit=audit)

    def _whole_category(
        self, category: StrideCategory, shortlist: list[LibraryThreat]
    ) -> list[LibraryThreat]:
        """Every threat of the category, the shortlisted (search order) first, then the rest."""
        shortlisted = {threat.catalogue_id for threat in shortlist}
        rest = [t for t in self._threats_by_category[category] if t.catalogue_id not in shortlisted]
        return [*shortlist, *rest]

    def fill_gap_if_empty(self, found: CategoryFindings) -> CategoryFindings:
        """The gap-fill, asked only after every category was judged and a threat refused under one category
        for a need was refused under all (G209 review: a category emptied that way was never gap-filled)."""
        if found.accepted or found.audit.gap_fill is not None:
            return found
        return dataclasses.replace(found, ai_threat=self._fill_gap(found.audit.category, found.audit))

    def _fill_gap(self, category: StrideCategory, audit: CategoryAudit) -> PlannedThreat | None:
        """The AI is asked only on proof that the library is exhausted: every record of the category judged,
        counted as each verdict came back (never inferred). Not asked, the reason joins any earlier note (the
        threats not judged), never replaces it."""
        records = {threat.catalogue_id for threat in self._threats_by_category[category]}
        judged = audit.judged_ids & records
        if judged == records:
            return self._gap_filler.propose_ai_threat(category, audit)
        audit.gap_fill = GapFillOutcome.NOT_ASSESSED
        not_asked = PlanMessage.GAP_FILL_NOT_ASKED.format(judged=len(judged), records=len(records))
        audit.note = f"{audit.note} {not_asked}" if audit.note else not_asked
        return None
