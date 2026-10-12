"""AI gap-filling (v1 relevance.gap_fill): at most once per STRIDE category, only after
every library threat of it was judged and none applies. One coherent proposal (type, threat, systems) or none.
It must not repeat a library threat or wording a curator rejected or still reviews, it must pass the same
relevance gate, and its type must match a library type, else it is a note for a curator and never a threat.
No attacker is chosen here: the AI's attacker text is never used, and the
actor assigner ranks the library actors linked to its type, as for a library threat."""

from functools import partial
from typing import Any

import structlog

from app.ai import ChatModel, TruncatedAiAnswer, UnreadableAiAnswer
from app.core.config import get_settings
from app.core.constants import (
    AiTask,
    CandidateRejection,
    GapFillOutcome,
    LibraryRowKind,
    LogEvent,
    PlanMessage,
    StrideCategory,
    ThreatFinding,
)
from app.core.tracing import traced
from app.engine.scenarios.finding.library_matcher import LibraryMatcher
from app.engine.scenarios.finding.relevance_gate import RelevanceGate, candidate_for_gate
from app.engine.scenarios.finding.threat_prompts import gap_fill_prompt
from app.engine.shared.ask_ai import ChatPrompt, answer_item_problems, ask_ai_and_check
from app.engine.shared.names import name_match_key, threat_name_without_code
from app.engine.shared.prompt_batches import max_batch_prompt_chars, prompt_length
from app.models.library import LibraryThreatType, ThreatLibrary
from app.models.planner_replies import GapFillResponse
from app.models.threats import CategoryAudit, Landscape, PlannedThreat, Verdict

log = structlog.get_logger(__name__)

_PROPOSAL_FIELDS = ("threat_type", "threat", "attacker", "reason")


def refused_threat_names(library: ThreatLibrary) -> frozenset[str]:
    """The threat names an AI proposal must not repeat: those a curator rejected and those still waiting for
    a curator, as name_match_key keys."""
    pending = [row.name for row in library.pending if row.kind == LibraryRowKind.THREAT]
    rejected = [row.name for row in library.curator_rejected]
    return frozenset(name_match_key(threat_name_without_code(name)) for name in (*pending, *rejected))


class GapFiller:
    def __init__(  # noqa: PLR0913 — the AI, the gate, the library and the landscape: each one is needed
        self,
        chat: ChatModel,
        gate: RelevanceGate,
        matcher: LibraryMatcher,
        landscape: Landscape,
        refused: frozenset[str] = frozenset(),
    ) -> None:
        """`refused`: refused_threat_names(library)."""
        self._chat = chat
        self._gate = gate
        self._matcher = matcher
        self._landscape = landscape
        self._refused = refused
        self._room = max_batch_prompt_chars(chat.max_prompt_chars)

    @traced("threats.gap_fill")
    def propose_ai_threat(self, category: StrideCategory, audit: CategoryAudit) -> PlannedThreat | None:
        """The category's one AI threat, or None; every outcome is recorded on `audit`."""
        proposal = self._ask_twice(category, audit)
        if proposal is None:
            return None
        if not proposal["applies"]:
            audit.gap_fill, audit.note = GapFillOutcome.NONE_APPLIES, proposal["reason"] or None
            return None
        if self._repeats_refused_wording(proposal, audit) or self._repeats_a_library_threat(
            category, proposal, audit
        ):
            return None
        verdict = self._judge_proposal(
            category, proposal, audit
        )  # before the type search: a rejection needs none
        if verdict is None:
            return None
        if not verdict.applies:  # not relevant, or needs what nothing recorded mentions (G209)
            code = CandidateRejection.NEEDS_UNRECORDED if verdict.needs else CandidateRejection.AI_REJECTED
            _refuse(audit, GapFillOutcome.REJECTED, code, proposal, verdict.reason, verdict.needs)
            return None
        library_type = self._matcher.closest_type(proposal["threat_type"], category)
        if library_type is None or library_type[1] < _threat_threshold():
            note = PlanMessage.GAP_FILL_UNTYPED.format(
                threat=proposal["threat"], threat_type=proposal["threat_type"]
            )
            _refuse(audit, GapFillOutcome.UNTYPED, CandidateRejection.AI_UNTYPED, proposal, note)
            audit.note = note
            return None
        audit.gap_fill = GapFillOutcome.ACCEPTED
        return _as_threat(category, proposal, verdict, library_type[0])

    def _judge_proposal(
        self, category: StrideCategory, proposal: dict[str, Any], audit: CategoryAudit
    ) -> Verdict | None:
        """The gate's verdict on the proposal; no attacker is shown (the AI's attacker text is never used:
        the actor assigner ranks the type's linked actors). A verdict the gate cannot give even on its retry
        leaves the GAP not assessed, as an unusable proposal does: the category's library threats were all
        judged and keep their record (review 2026-10-11: they were all re-marked "not judged")."""
        item = candidate_for_gate(
            f"{ThreatFinding.RECORD_SLOT}1", proposal["threat_type"], proposal["threat"], []
        )
        try:
            return self._gate.judge_candidates(category, [item])[item["slot"]]
        except (UnreadableAiAnswer, TruncatedAiAnswer) as exc:
            log.warning(LogEvent.PLANNER_CHECK_NOT_MADE, check=AiTask.RELEVANCE_GATE, error=str(exc))
            audit.gap_fill, audit.note = GapFillOutcome.NOT_ASSESSED, PlanMessage.GAP_FILL_NOT_ASSESSED
            return None

    def _repeats_refused_wording(self, proposal: dict[str, Any], audit: CategoryAudit) -> bool:
        if name_match_key(threat_name_without_code(proposal["threat"])) not in self._refused:
            return False
        reason = PlanMessage.REPEATS_REFUSED_WORDING.format(
            threat=threat_name_without_code(proposal["threat"])
        )
        _refuse(
            audit,
            GapFillOutcome.PREVIOUSLY_REJECTED,
            CandidateRejection.AI_PREVIOUSLY_REJECTED,
            proposal,
            reason,
        )
        return True

    def _ask_twice(self, category: StrideCategory, audit: CategoryAudit) -> dict[str, Any] | None:
        """The proposal; an answer still unusable after its re-ask is asked once more from scratch,
        then the category's gap is recorded as not assessed."""
        prompt = self._prompt(category, audit)
        for attempt in (1, 2):
            try:
                proposal: dict[str, Any] = ask_ai_and_check(
                    self._chat,
                    AiTask.GAP_FILL,
                    prompt,
                    partial(_read_proposal, aliases=self._landscape.system_ids),
                )
            except (UnreadableAiAnswer, TruncatedAiAnswer) as exc:
                log.warning(
                    LogEvent.PLANNER_CHECK_NOT_MADE, check=AiTask.GAP_FILL, attempt=attempt, error=str(exc)
                )
                continue
            return proposal
        audit.gap_fill, audit.note = GapFillOutcome.NOT_ASSESSED, PlanMessage.GAP_FILL_NOT_ASSESSED
        return None

    def _prompt(self, category: StrideCategory, audit: CategoryAudit) -> ChatPrompt:
        """The ask, naming every library threat the gate rejected, as many as fit (the rest counted): a prompt
        over the limit would cost the category its only suggestion."""
        checked = len(audit.judged_ids)
        names = list(
            dict.fromkeys(threat_name_without_code(rejected["threat"]) for rejected in audit.rejected)
        )
        if not names:
            return gap_fill_prompt(self._landscape.text, category, checked)
        empty = prompt_length(gap_fill_prompt(self._landscape.text, category, checked, ["x"]))
        room = self._room - ThreatFinding.MORE_NAMES_LINE_CHARS - empty
        shown: list[str] = []
        for name in names:
            room -= len(name) + 3  # "- ", the name, the line break
            if room < 0:
                break
            shown.append(name)
        if len(shown) < len(names):
            shown.append(f"... and {len(names) - len(shown)} more")
        return gap_fill_prompt(self._landscape.text, category, checked, shown)

    def _repeats_a_library_threat(
        self, category: StrideCategory, proposal: dict[str, Any], audit: CategoryAudit
    ) -> bool:
        match = self._matcher.closest_threat(proposal["threat"], category)
        if match is None or match[1] < _threat_threshold():
            return False
        audit.gap_fill = GapFillOutcome.REDUNDANT  # the library has it, and it was judged not to apply
        reason = PlanMessage.REPEATS_LIBRARY_THREAT.format(threat=threat_name_without_code(match[0].name))
        audit.rejected.append(
            {"threat": proposal["threat"], "library_id": None, "code": CandidateRejection.AI_REDUNDANT}
            | {"reason": reason}
        )
        return True


def _refuse(
    audit: CategoryAudit,
    outcome: GapFillOutcome,
    code: CandidateRejection,
    proposal: dict[str, Any],
    reason: str,
    needs: tuple[str, ...] = (),
) -> None:
    """The refused proposal on the category's record; a need refusal keeps its list, as a library threat's."""
    audit.gap_fill = outcome
    refused = {"threat": proposal["threat"], "library_id": None, "code": code, "reason": reason}
    audit.rejected.append(refused | ({"needs": list(needs)} if needs else {}))


def _as_threat(
    category: StrideCategory, proposal: dict[str, Any], verdict: Verdict, library_type: LibraryThreatType
) -> PlannedThreat:
    """The proposal as a planned threat of the library type it matched; no actors yet (the actor assigner adds
    them, from the actors the library links to that type)."""
    return PlannedThreat(
        key=f"ai:{name_match_key(proposal['threat'])}",  # one AI threat under two categories is one
        catalogue_id=None,
        type_id=library_type.type_id,
        type_name=library_type.name,
        name=proposal["threat"],
        categories=(category,),
        systems=verdict.systems,
        impact=verdict.impact,
        confidence=verdict.confidence,
        reason=verdict.reason,
    )


def _read_proposal(
    answer: dict[str, Any], aliases: dict[str, int]
) -> tuple[dict[str, Any] | None, list[str]]:
    if not isinstance(answer.get("applies"), bool):
        return None, ['the reply must be {"applies": true|false, ...}']
    # "None applies" without its reason has said all that is read from it: never re-asked for that alone.
    checked = answer if answer["applies"] else {"reason": "", **answer}
    if problems := answer_item_problems(GapFillResponse, checked, "the reply"):
        return None, problems
    if not answer["applies"]:
        return {"applies": False, "reason": str(answer.get("reason") or "").strip()}, []
    fields = {name: str(answer.get(name) or "").strip() for name in _PROPOSAL_FIELDS}
    problems = [f"{name} is required" for name, value in fields.items() if not value]
    if len(fields["threat_type"]) + len(fields["threat"]) > ThreatFinding.GAP_FILL_MAX_CHARS:
        problems.append("the proposal is too long")
    systems = answer.get("systems") or []
    if not isinstance(systems, list) or any(not isinstance(a, str) or a not in aliases for a in systems):
        problems.append("systems must be listed aliases only (SYS1, SYS2 ...)")
    return (None, problems) if problems else ({**fields, "applies": True, "systems": systems}, [])


def _threat_threshold() -> float:
    """THREAT_SIMILARITY_THRESHOLD: at or above it, 0-100 on the reranker's scale, an AI proposal IS that
    library threat (redundant) or takes that library type; below it, a new wording or an untyped note."""
    return get_settings().threat_similarity_threshold
