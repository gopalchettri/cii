"""A plan's trace: how many candidates each planning stage took in and let out, and each one left out with
its reason, built in memory while planning and saved with the plan; read back with the writing outcomes."""

from collections import Counter
from typing import Any

from app.core.constants import (
    AttackerCheck,
    CandidateRejection,
    PlanLoss,
    PlanStage,
    PlanTraceLimits,
    UnselectedReason,
)
from app.domain.scenario.plan import plan_drop
from app.domain.shared.names import name_match_key, replace_codes_with_names
from app.models.scenario.plan import CategoryAudit, Landscape, ThreatFindings
from app.models.scenario.views import GivenUpPath, PlanTraceView, WriteOutcomes

#: The drops listed first: those that could have been a scenario, then the AI's verdicts, then the filter.
_TELLING_ORDER = (
    (PlanStage.HELD, PlanLoss.ALREADY_HELD),
    (PlanStage.ATTACKER, AttackerCheck.NONE_FITS),
    (PlanStage.ATTACKER, PlanLoss.NO_LINKED_ACTOR),
    (PlanStage.MERGE, CandidateRejection.ASSET_TYPE_MISMATCH),
    (PlanStage.MERGE, PlanLoss.MERGED),
    (PlanStage.CHECKS, PlanLoss.NEEDS_UNRECORDED_ELSEWHERE),
    (PlanStage.CHECKS, CandidateRejection.ASSET_TYPE_MISMATCH),
    *((PlanStage.GAP_FILL, reason) for reason in (PlanLoss.TYPE_UNMATCHED, PlanLoss.NO_LINKED_ACTOR)),
    *((PlanStage.GAP_FILL, reason) for reason in (CandidateRejection.NEEDS_UNRECORDED, PlanLoss.NOT_JUDGED)),
    *((PlanStage.GAP_FILL, reason) for reason in (CandidateRejection.NOT_RELEVANT, PlanLoss.LIBRARY_REPEAT)),
    (PlanStage.GATE, CandidateRejection.NEEDS_UNRECORDED),
    (PlanStage.GATE, PlanLoss.NOT_JUDGED),
    (PlanStage.GATE, CandidateRejection.NOT_RELEVANT),
    (PlanStage.PRE_FILTER, PlanLoss.NO_LINKED_ACTOR),
    (PlanStage.PRE_FILTER, PlanLoss.TYPE_FITS_NO_PLACE),
)
_TELLING_RANK = {pair: position for position, pair in enumerate(_TELLING_ORDER)}


def gate_drops(audits: list[CategoryAudit], system_names: dict[str, str]) -> list[dict[str, Any]]:
    """Each slot the gate or code's checks left out, from the categories' audits; aliases turned to names."""
    drops = []
    for audit in audits:
        kind = str(audit.category)
        for threat in audit.not_judged:
            key = f"lib:{threat.catalogue_id}"
            drops.append(plan_drop(key, threat.name, kind, PlanStage.GATE, PlanLoss.NOT_JUDGED))
        for rejected in audit.rejected:
            detail = replace_codes_with_names(rejected.get("detail") or "", system_names)
            stage, reason = PlanStage.GATE, str(rejected["code"])
            if under := rejected.get("under"):  # refused here for a need found under another kind
                stage, reason = PlanStage.CHECKS, PlanLoss.NEEDS_UNRECORDED_ELSEWHERE
                detail = f"{under}: {detail}"
            elif rejected["code"] == CandidateRejection.ASSET_TYPE_MISMATCH:
                stage = PlanStage.CHECKS
            key = f"lib:{rejected['library_id']}"
            drops.append(plan_drop(key, rejected["threat"], kind, stage, reason, detail))
        if lost := audit.gap_fill_lost:  # the kind's one AI proposal, not kept, its aliases turned to names
            key = f"ai:{name_match_key(lost['threat'])}"
            name = replace_codes_with_names(lost["threat"], system_names)
            detail = replace_codes_with_names(lost["detail"], system_names)
            drops.append(plan_drop(key, name, kind, PlanStage.GAP_FILL, str(lost["reason"]), detail))
    return drops


def build_plan_trace(
    findings: ThreatFindings, plan: dict[str, Any], held: list[dict[str, Any]], first_set: int
) -> dict[str, Any]:
    """The trace saved with the plan: every stage's counts, whether the landscape was cut, and the drops
    (the most telling first, at most PlanTraceLimits.MAX_DROPS; the counts are always whole)."""
    drops = [*findings.drops, *gate_drops(findings.audits, findings.landscape.system_names), *held]
    return {
        "counts": _counts(findings, plan, Counter((str(d["stage"]), str(d["reason"])) for d in drops))
        | {"paths": len(plan["paths"]) + len(held), "already_held": len(held), "first_set": first_set},
        "landscape_cut": findings.landscape.cut,
        "drops": sorted(drops, key=_telling)[: PlanTraceLimits.MAX_DROPS],
        "drops_total": len(drops),
        **_turns_and_groups(plan["paths"], findings.landscape),
    }


def _turns_and_groups(paths: list[dict[str, Any]], landscape: Landscape) -> dict[str, dict[str, int]]:
    """How many paths get in through each system, in turn order and 0 for a system no path gets in through,
    and how many cover each group of systems; by name, with the alias when two systems share one."""
    shared = Counter(landscape.system_names.values())
    names = {
        system_id: name if shared[name] == 1 else f"{name} ({alias})"
        for alias, system_id in landscape.system_ids.items()
        for name in (landscape.system_names[alias],)
    }
    entered = Counter(path["entry_system"] for path in paths if "entry_system" in path)
    turns = {names[system_id]: entered[system_id] for system_id in names}
    if entered[None]:
        turns[PlanTraceLimits.ASSET_ITSELF] = entered[None]
    groups = Counter(
        " + ".join(names.get(system_id, str(system_id)) for system_id in path["systems"])
        or PlanTraceLimits.ASSET_ITSELF
        for path in paths
    )
    return {"turns": turns, "groups": dict(groups.most_common())}


def _counts(findings: ThreatFindings, plan: dict[str, Any], by: Counter[tuple[str, str]]) -> dict[str, int]:
    """Each stage's counts from the drops (`by` stage and reason) and the plan; the held paths aside."""
    asked = sum(len(audit.judged_ids) + len(audit.not_judged) for audit in findings.audits)
    gate = {
        "not_judged": by[(PlanStage.GATE, PlanLoss.NOT_JUDGED)],
        "not_relevant": by[(PlanStage.GATE, CandidateRejection.NOT_RELEVANT)],
        "needs_unrecorded": by[(PlanStage.GATE, CandidateRejection.NEEDS_UNRECORDED)],
        "asset_type_mismatch": by[(PlanStage.CHECKS, CandidateRejection.ASSET_TYPE_MISMATCH)],
        "needs_unrecorded_elsewhere": by[(PlanStage.CHECKS, PlanLoss.NEEDS_UNRECORDED_ELSEWHERE)],
    }
    selected = sum(bool(path["selected"]) for path in plan["paths"])
    return {
        "library_threats": findings.library_threats,
        "type_fits_no_place": by[(PlanStage.PRE_FILTER, PlanLoss.TYPE_FITS_NO_PLACE)],
        "no_linked_actor": by[(PlanStage.PRE_FILTER, PlanLoss.NO_LINKED_ACTOR)],
        "gate_asked": asked,
        **gate,
        "gate_accepted": asked - sum(gate.values()),
        "ai_threats": findings.ai_threats,
        "gap_fill_lost": sum(count for (stage, _), count in by.items() if stage == PlanStage.GAP_FILL),
        "merged": by[(PlanStage.MERGE, PlanLoss.MERGED)],
        "unfit_after_merge": by[(PlanStage.MERGE, CandidateRejection.ASSET_TYPE_MISMATCH)],
        "no_attacker": by[(PlanStage.ATTACKER, AttackerCheck.NONE_FITS)]
        + by[(PlanStage.ATTACKER, PlanLoss.NO_LINKED_ACTOR)],
        "threats": len(plan["threats"]),
        "not_selected": len(plan["paths"]) - selected,
        "selected": selected,
    }


def _telling(drop: dict[str, Any]) -> tuple[int, str, str]:
    """Where a drop is listed: by how telling its reason is, then by threat and kind."""
    rank = _TELLING_RANK.get((drop["stage"], drop["reason"]), len(_TELLING_RANK))
    return rank, drop["threat_key"], drop["kind"] or ""


def plan_trace_view(session_id: str, trace: dict[str, Any], paths: list[dict[str, Any]]) -> PlanTraceView:
    """The stored trace with what became of the planned paths since: served, still to write, given up."""
    replaced = UnselectedReason.REPLACED_AFTER_FAILURE
    given_up = [
        GivenUpPath(
            path_id=path["path_id"],
            threat_key=path["steps"][0],
            kind=path["category"],
            rank=path["rank"],
            reason=path.get("abandoned_reason") or path.get("last_blocker"),
            repeats=path.get("repeats"),
            replaced_by=path.get("replaced_by"),
        )
        for path in paths
        if path.get("abandoned")
    ]
    writing = WriteOutcomes(
        served=sum(bool(path.get("served")) for path in paths),
        still_to_write=sum(
            bool(path["selected"]) and not path.get("served") and not path.get("abandoned") for path in paths
        ),
        given_up=len(given_up),
        replaced=sum(path.get("unselected_reason") == replaced for path in paths),
        given_up_paths=given_up,
    )
    return PlanTraceView.model_validate({"session_id": session_id, **trace, "writing": writing})
