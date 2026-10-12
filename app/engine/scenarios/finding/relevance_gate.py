"""The relevance gate (v1 threat_identification/relevance.py): the AI decides whether each
candidate threat applies to the landscape, batched per STRIDE category. A verdict is never a score, every
verdict carries its reason, and an answer that cannot be read is never "not relevant": its threats are
recorded not judged (judge_candidates raises)."""

import functools
from concurrent.futures import Executor
from typing import Any

import structlog

from app.ai import ChatModel, TruncatedAiAnswer, UnreadableAiAnswer
from app.core.constants import (
    AiTask,
    CandidateRejection,
    LogEvent,
    PlanMessage,
    StrideCategory,
    ThreatFinding,
    Tracing,
)
from app.core.tracing import record_detail, step_detail_enabled, traced
from app.engine.scenarios.finding.threat_prompts import relevance_gate_prompt
from app.engine.shared.ask_ai import answer_item_problems, answers_for_asked_slots, ask_ai_and_check
from app.engine.shared.names import threat_name_without_code
from app.engine.shared.parallel import run_in_parallel, run_in_shared_pool
from app.engine.shared.prompt_batches import batches_that_fit, max_batch_prompt_chars
from app.models.library import LibraryThreat
from app.models.planner_replies import RelevanceVerdict
from app.models.threats import CategoryAudit, Landscape, PlannedThreat, Verdict

log = structlog.get_logger(__name__)

#: A gate batch whose answer stayed unusable after its own retries.
type GateFailure = UnreadableAiAnswer | TruncatedAiAnswer


def candidate_for_gate(slot: str, threat_type: str, threat: str, attackers: list[str]) -> dict[str, Any]:
    """A candidate as the gate is shown it: names without library codes (a code shown here was copied into the
    reason, which a card shows)."""
    return {
        "slot": slot,
        "threat_type": threat_name_without_code(threat_type),
        "threat": threat_name_without_code(threat),
        "attackers": attackers,
    }


def parse_verdict(item: dict[str, Any], aliases: dict[str, int]) -> tuple[Verdict | None, list[str]]:
    """One verdict, checked: known aliases only, a yes/no, an impact for a relevant threat, a confidence of
    0-100 and always a reason (a rejection's too). A rejection's impact is never read, so never judged."""
    slot, systems = item["slot"], item.get("systems") or []
    impact = str(item.get("impact") or "").upper()
    confidence, reason = item.get("confidence"), str(item.get("reason") or "").strip()
    problems = []
    # Any JSON may come back: a list or object in place of an alias is a problem to re-ask, never a crash.
    if not isinstance(systems, list) or any(
        not isinstance(alias, str) or alias not in aliases for alias in systems
    ):
        problems.append(f"{slot}: systems must be listed aliases only (SYS1, SYS2 ...)")
    if not isinstance(item.get("relevant"), bool):
        problems.append(f"{slot}: relevant must be true or false")
    if item.get("relevant") is True and impact not in ThreatFinding.IMPACT_RANK:
        problems.append(f"{slot}: impact must be HIGH, MEDIUM or LOW")
    if isinstance(confidence, bool) or not isinstance(confidence, int | float) or not 0 <= confidence <= 100:
        problems.append(f"{slot}: confidence must be a number from 0 to 100")
    if not reason:
        problems.append(f"{slot}: every verdict needs its reason, a rejection's too")
    needs = item.get("needs") or []
    if not isinstance(needs, list) or any(not isinstance(need, str) for need in needs):
        problems.append(f"{slot}: needs must be a list of names ([] when everything it needs is recorded)")
    if problems:
        return None, problems
    shown = {**item, "impact": impact if item["relevant"] else None, "systems": systems, "needs": needs}
    if problems := answer_item_problems(RelevanceVerdict, shown, slot):
        return None, problems
    return Verdict(
        relevant=item["relevant"],
        systems=tuple(sorted({aliases[alias] for alias in systems})),
        reason=reason[: ThreatFinding.REASON_MAX_CHARS],
        impact=ThreatFinding.IMPACT_RANK.get(impact, 0),
        confidence=float(confidence or 0),
        needs=_needs(needs),
    ), []


def _needs(names: list[str]) -> tuple[str, ...]:
    """What a verdict says its threat needs that nothing recorded mentions, blanks dropped and bounded."""
    kept = [" ".join(name.split())[: ThreatFinding.NEED_MAX_CHARS] for name in names if name.strip()]
    return tuple(kept[: ThreatFinding.NEEDS_MAX_ITEMS])


def accepted_library_threat(
    category: StrideCategory, threat: LibraryThreat, verdict: Verdict
) -> PlannedThreat:
    """An accepted library threat as the plan holds it, before its actors are chosen."""
    return PlannedThreat(
        key=f"lib:{threat.catalogue_id}",
        catalogue_id=threat.catalogue_id,
        type_id=threat.type_id,
        type_name=threat.type_name,
        name=threat.name,
        categories=(category,),
        systems=verdict.systems,
        impact=verdict.impact,
        confidence=verdict.confidence,
        reason=verdict.reason,
    )


class RelevanceGate:
    """Judges candidate threats of one category against one landscape, in batches that fit the model input."""

    def __init__(self, chat: ChatModel, landscape: Landscape, pool: Executor | None = None) -> None:
        """`pool`: shared by every category's batches (ThreatFinder); None = a pool per judge call."""
        self._chat = chat
        self._landscape = landscape
        self._room = max_batch_prompt_chars(chat.max_prompt_chars)
        self._pool = pool

    def judge_candidates(self, category: StrideCategory, items: list[dict[str, Any]]) -> dict[str, Verdict]:
        """{slot: verdict} for every item ({slot, threat_type, threat, attackers}): batches of at most
        GATE_BATCH_MAX_ITEMS, all sent at once (G121: a whole category is judged, fast). A batch still
        unusable after its own retries raises."""
        verdicts, failures = self._judge_in_batches(category, items)
        if failures:
            raise failures[0]
        return verdicts

    def judge_library_threats(
        self, category: StrideCategory, threats: list[LibraryThreat], audit: CategoryAudit
    ) -> list[tuple[LibraryThreat, Verdict]]:
        """The library threats that apply; every rejection goes on the category's record with its reason. A
        batch still unusable after its retries leaves only ITS threats not judged, on the record and in the
        note: the other batches keep their verdicts (G210; before, the whole category lost them)."""
        if not threats:
            return []
        items = [
            candidate_for_gate(
                f"{ThreatFinding.RECORD_SLOT}{position}",
                threat.type_name,
                threat.name,
                [actor.name for actor in threat.linked_actors],
            )
            for position, threat in enumerate(threats, start=1)
        ]
        verdicts, failures = self._judge_in_batches(category, items)
        if step_detail_enabled():
            _trace_verdicts(category, items, verdicts)
        note = PlanMessage.THREATS_NOT_JUDGED.format(
            not_judged=len(items) - len(verdicts), threats=len(items)
        )
        accepted = []
        for item, threat in zip(items, threats, strict=True):
            verdict = verdicts.get(item["slot"])
            if verdict is None:
                audit.rejected.append(_not_judged(threat, note))
                continue
            audit.judged_ids.add(threat.catalogue_id)
            if verdict.applies:
                accepted.append((threat, verdict))
            else:
                audit.rejected.append(_rejection(threat, verdict))
        if failures:
            log.warning(
                LogEvent.PLANNER_THREATS_NOT_JUDGED, category=category, note=note, error=str(failures[0])
            )
            audit.note = note
        return accepted

    def _judge_in_batches(
        self, category: StrideCategory, items: list[dict[str, Any]]
    ) -> tuple[dict[str, Verdict], list[GateFailure]]:
        """Every batch's verdicts, and the error of each batch still unusable after its own retries: one bad
        batch never costs the others their verdicts. An outage is raised: the job retries."""
        build_prompt = functools.partial(relevance_gate_prompt, self._landscape.text, category)
        batches = list(batches_that_fit(build_prompt, items, self._room, ThreatFinding.GATE_BATCH_MAX_ITEMS))
        if step_detail_enabled():
            _trace_batches(category, len(items), self._room, batches)
        work = functools.partial(self._verdicts_or_failure, category)
        judged = (
            run_in_shared_pool(self._pool, work, batches)
            if self._pool is not None
            else run_in_parallel(work, batches, ThreatFinding.AI_BATCHES_AT_ONCE, "gate-batch")
        )
        verdicts = {
            slot: verdict for result in judged if isinstance(result, dict) for slot, verdict in result.items()
        }
        return verdicts, [result for result in judged if not isinstance(result, dict)]

    def _verdicts_or_failure(
        self, category: StrideCategory, batch: list[dict[str, Any]]
    ) -> dict[str, Verdict] | GateFailure:
        try:
            return self._judge_batch(category, batch)
        except (UnreadableAiAnswer, TruncatedAiAnswer) as exc:
            return exc

    @traced("threats.relevance_batch")
    def _judge_batch(
        self, category: StrideCategory, batch: list[dict[str, Any]], last_try: bool = False
    ) -> dict[str, Verdict]:
        """One gate call. Cut off at the output limit: each half asked on its own (the input fits, but the
        answer grows with every verdict). Still unreadable after its re-ask, or a single threat still cut off:
        this batch alone is asked once more from scratch ("retry once before the plan is saved"), so the
        category's other batches keep their verdicts; failing on its last try, it raises."""
        try:
            return self._ask_gate(category, batch)
        except (UnreadableAiAnswer, TruncatedAiAnswer) as exc:
            if isinstance(exc, TruncatedAiAnswer) and len(batch) > 1:
                log.warning(LogEvent.PLANNER_BATCH_SPLIT, category=category, threats=len(batch))
                half = len(batch) // 2
                return {
                    **self._judge_batch(category, batch[:half], last_try),
                    **self._judge_batch(category, batch[half:], last_try),
                }
            if last_try:
                raise
            log.warning(
                LogEvent.PLANNER_BATCH_ASKED_AGAIN, category=category, threats=len(batch), error=str(exc)
            )
            return self._judge_batch(category, batch, last_try=True)

    def _ask_gate(self, category: StrideCategory, batch: list[dict[str, Any]]) -> dict[str, Verdict]:
        asked = {item["slot"] for item in batch}
        prompt = relevance_gate_prompt(self._landscape.text, category, batch)
        verdicts: dict[str, Verdict] = ask_ai_and_check(
            self._chat, AiTask.RELEVANCE_GATE, prompt, functools.partial(self._read_verdicts, asked=asked)
        )
        return verdicts

    def _read_verdicts(self, answer: dict[str, Any], asked: set[str]) -> tuple[dict[str, Verdict], list[str]]:
        items, problems = answers_for_asked_slots(answer, "verdicts", asked)
        verdicts = {}
        for item in items:
            verdict, item_problems = parse_verdict(item, self._landscape.system_ids)
            problems += item_problems
            if verdict is not None:
                verdicts[item["slot"]] = verdict
        return verdicts, problems


def _rejection(threat: LibraryThreat, verdict: Verdict) -> dict[str, Any]:
    """Not relevant; or needing what nothing recorded mentions (G209), kept with its list."""
    rejected = {"threat": threat.name, "library_id": threat.catalogue_id, "reason": verdict.reason}
    if verdict.needs:  # whatever "relevant" says: a listed need is what the cross-category refusal follows
        return rejected | {"code": CandidateRejection.NEEDS_UNRECORDED, "needs": list(verdict.needs)}
    return rejected | {"code": CandidateRejection.NOT_RELEVANT}


def _not_judged(threat: LibraryThreat, reason: str) -> dict[str, Any]:
    """A threat whose batch was still unusable after its retries: no verdict, so neither kept nor refused."""
    return {
        "threat": threat.name,
        "library_id": threat.catalogue_id,
        "code": CandidateRejection.NOT_JUDGED,
        "reason": reason,
    }


def _trace_batches(
    category: StrideCategory, items: int, room: int, batches: list[list[dict[str, Any]]]
) -> None:
    """How one category's candidates were cut into gate calls: each batch's first and last slot."""
    record_detail(
        "batches",
        category,
        given={"items": items, "room": room},
        produced={
            f"b{number}": f"{batch[0]['slot']}-{batch[-1]['slot']} ({len(batch)})"
            for number, batch in enumerate(batches, start=1)
            if batch
        },
    )


def _trace_verdicts(
    category: StrideCategory, items: list[dict[str, Any]], verdicts: dict[str, Verdict]
) -> None:
    """Each library threat's verdict: "yes / HIGH / 80" (relevant, impact, confidence), "needs ...", "not
    relevant", or "not judged" (its batch unusable after its retries)."""
    impacts = {rank: name for name, rank in ThreatFinding.IMPACT_RANK.items()}
    shown = {}
    for item in items[: Tracing.PREVIEW_KEYS]:
        verdict = verdicts.get(item["slot"])
        shown[f"{item['slot']} {item['threat']}"] = (
            "not judged"
            if verdict is None
            else f"yes / {impacts.get(verdict.impact)} / {verdict.confidence:g}"
            if verdict.applies
            else f"needs {', '.join(verdict.needs)}"
            if verdict.needs
            else "not relevant"
        )
    record_detail("verdicts", category, given={"threats": len(items)}, produced=shown)
