"""One plan version: its input built from the scenario and the register, the AI's answer and code's checks."""

import json
import re
from collections.abc import Mapping, Sequence
from datetime import date, datetime
from decimal import Decimal
from typing import Any

from app.ai import ChatModel, TruncatedAiAnswer, UnreadableAiAnswer
from app.core.asset_types import asset_type_fits
from app.core.constants import (
    AiTask,
    ControlCoverage,
    ControlMatch,
    ControlValidation,
    ErrorCode,
    GapKind,
    ImplementationStatus,
    PlanText,
    PlanWarning,
    Remediation,
    RemediationMessage,
    Status,
    YesNo,
)
from app.core.exceptions import JobFailed
from app.core.prompts import PROMPTS
from app.core.redaction import redact
from app.domain.remediation.schedule import schedule_plan
from app.domain.scenario.library_rules import compatible_asset_types
from app.domain.scenario.plan import raw_system_facts
from app.domain.shared.ask_ai import ChatPrompt, answer_item_problems, ask_ai_and_check
from app.domain.shared.names import name_match_key, shorten_text
from app.domain.shared.prompt_redaction import drop_database_ids, facts_safe_for_prompt, without_platform_note
from app.models.library.library import LibraryControl
from app.models.remediation.plan import DraftValidation, PlanDraft
from app.models.remediation.requests import ControlRef
from app.models.scenario.asset_context import FrozenContext
from app.search.texts import describe_control

#: Fixed for every plan, so the provider can reuse it.
PLAN_SYSTEM_PROMPT: str = PROMPTS["remediation"]["plan"]["text"]
#: Everything after it is data, whatever it says.
_CONTEXT_PREFIX: str = PROMPTS["remediation"]["plan"]["context_prefix"]
#: Snapshot keys the model never reads: code copies the echo into the plan; the warnings are the reviewer's.
_NOT_SHOWN = ("register", "warnings")
_RATINGS = ("likelihood_rating", "impact_rating", "final_risk_rating")
_SYSTEM_LISTS = ("protected_systems", "required_systems")
#: (the request's list of systems, the flag a register stored before that list holds instead).
_RISK_SYSTEMS = ("supporting_systems_applicable_to_risk", "all_supporting_systems_applicable")
_EXISTING_SYSTEMS = (
    "supporting_systems_applicable_to_existing_controls",
    "existing_controls_all_supporting_system_applicable",
)
_STAMPED = (
    "control_id",
    "control_code",
    "control_name",
    "domain",
    "implementation_status",
    "required_systems",
)
_ASSESSED = (
    "control_id",
    "control_code",
    "control_name",
    "domain",
    "match",
    "implementation_status",
    *_SYSTEM_LISTS,
    "validation",
    "validation_reason",
    "replaced_by",
    "replaces",
)
#: The statuses a checked control is recommended for.
_GAPS = (ImplementationStatus.NOT_IMPLEMENTED, ImplementationStatus.PARTIALLY_IMPLEMENTED)
_CODE_FACT = re.compile(Remediation.ACTION_PLAN_CLAIM_PATTERN, re.IGNORECASE)
_EXTENDS = re.compile(Remediation.EXTENDS_PATTERN, re.IGNORECASE)
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+")


def clip(text: str | None, limit: int = Remediation.TEXT_MAX_CHARS) -> str | None:
    """Free text as a snapshot holds it: redacted, then cut at `limit` with a mark."""
    if text is None:
        return None
    cleaned = redact(text)
    return cleaned if len(cleaned) <= limit else cleaned[:limit] + Remediation.TRUNCATED_MARK


def _by_name(controls: Sequence[LibraryControl]) -> dict[str, LibraryControl | None]:
    """Each control by its name: IT/OT twins (same name and description) by the lowest id; a name two
    different controls share by None, so only a code or id says which."""
    by_name: dict[str, LibraryControl | None] = {}
    for control in sorted(controls, key=lambda control: control.control_id):
        key, text = name_match_key(control.name), name_match_key(describe_control(control))
        first = by_name.setdefault(key, control)
        if first is not None and name_match_key(describe_control(first)) != text:
            by_name[key] = None
    return by_name


def resolve_control_refs(
    refs: Sequence[ControlRef], controls: Sequence[LibraryControl]
) -> tuple[list[LibraryControl], list[tuple[int, ControlRef]]]:
    """The library rows `refs` name, once each in first-named order; the refs naming none, with positions."""
    by_id = {row.control_id: row for row in controls}
    by_code = {row.code.casefold(): row for row in controls}
    by_name = _by_name(controls)
    found: dict[int, LibraryControl] = {}
    unresolved: list[tuple[int, ControlRef]] = []
    for position, ref in enumerate(refs):
        # By id (decisive), else code, else name, else the code heading a "CODE · Name" label.
        if ref.control_id is not None:
            row = by_id.get(ref.control_id)
        else:
            row = by_code.get(ref.control_code.casefold()) if ref.control_code else None
            if row is None and ref.control_name:
                row = by_name.get(name_match_key(ref.control_name))
                head = re.match(Remediation.LABEL_CODE_PATTERN, ref.control_name)
                if row is None and head is not None:
                    row = by_code.get(head.group().casefold())
        if row is None:
            unresolved.append((position, ref))
        else:
            found.setdefault(row.control_id, row)
    return list(found.values()), unresolved


def describe_ref(ref: ControlRef) -> str:
    """A reference as a person reads it: "code — name", the one given, or "control_id N"."""
    code, name = ref.control_code or "", ref.control_name or ""
    if code and name and code != name:
        return f"{code} — {name}"
    if code or name:
        return name or code
    return f"control_id {ref.control_id}"


def active_mapped_controls(
    scenario: dict[str, Any], controls_by_id: Mapping[int, LibraryControl]
) -> list[dict[str, Any]]:
    """The scenario's mapped control items still in the library; [] when none is (the job maps them)."""
    controls = scenario.get("controls") or {}
    if controls.get("status") != Status.DONE:
        return []
    return [item for item in controls.get("items") or [] if item["control_id"] in controls_by_id]


def risk_scope(
    scenario: dict[str, Any], context: FrozenContext, register: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(the asset's supporting systems, the ones the risk affects) as {supporting_system_id, name}: those the
    request lists; a register stored before that list: every one when all_supporting_systems_applicable is 1,
    else the scenario's own (the run's if it names none)."""
    systems = [{"supporting_system_id": s["id"], "name": s["name"]} for s in context.linked_systems()]
    listed = register.get("supporting_systems_applicable_to_risk")
    if listed is not None:
        return systems, [system for system in systems if system["supporting_system_id"] in listed]
    if register.get("all_supporting_systems_applicable") == 1:
        return systems, systems
    run = {system["id"] for system in context.systems}
    own = {system["id"] for system in (scenario.get("content") or {}).get("systems") or []} & run or run
    return systems, [system for system in systems if system["supporting_system_id"] in own]


def _protected_systems(
    register: dict[str, Any], controls: Sequence[LibraryControl], system_ids: Sequence[int]
) -> tuple[dict[str, set[int]], list[str]]:
    """Each register control's twin key with the systems it is on: those the request lists for the existing
    controls (none when it lists none); a register stored before the lists: all of them when the existing
    flag is 1, else the control's own supporting_system_ids. The warnings for entries naming no library
    control."""
    shared: Sequence[int] | None = register.get("supporting_systems_applicable_to_existing_controls") or []
    if register.get("supporting_systems_applicable_to_risk") is None:  # stored before the lists
        everywhere = register.get("existing_controls_all_supporting_system_applicable")
        if everywhere is None:  # a register stored before the flag: its Yes/No said the same
            everywhere = int(register.get("existing_controls_all_subsystems") == YesNo.YES)
        shared = system_ids if everywhere == 1 else None
    protected: dict[str, set[int]] = {}
    warnings: list[str] = []
    for entry in register.get("existing_controls") or []:
        own: list[int] = []
        if isinstance(entry, dict):  # stored before the lists, an entry named the systems it was on
            entry = dict(entry)
            own = entry.pop("supporting_system_ids", None) or []
        ref = ControlRef.model_validate(entry)
        named, unresolved = resolve_control_refs([ref], controls)
        if unresolved:
            warnings.append(PlanWarning.CONTROL_UNMATCHED.format(reference=describe_ref(ref)))
            continue
        on = own if shared is None else shared
        protected.setdefault(name_match_key(describe_control(named[0])), set()).update(on)  # IT/OT twins: one
    return protected, warnings


def assess_controls(
    items: list[dict[str, Any]],
    register: dict[str, Any],
    controls: Sequence[LibraryControl],
    systems: list[dict[str, Any]],
    affected: list[dict[str, Any]],
    categories: Mapping[int, str | None],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Each mapped control with its library details, the affected systems of its asset type (`categories`:
    each system's) an existing control is already on and those it is still needed on, and its status from
    them; the unmatched warnings."""
    protected, warnings = _protected_systems(register, controls, [s["supporting_system_id"] for s in systems])
    by_id = {row.control_id: row for row in controls}
    library_mapped = []
    for item in items:
        row = by_id.get(item["control_id"])
        if row is None:
            warnings.append(PlanWarning.CONTROL_UNMATCHED.format(reference=item.get("code")))
            continue
        on = protected.get(name_match_key(describe_control(row)))
        library_mapped.append(_assessed_row(row, item, _of_its_type(row, affected, categories), on))
    return library_mapped, warnings


def assess_alternatives(
    found: Sequence[tuple[LibraryControl, float]],
    register: dict[str, Any],
    controls: Sequence[LibraryControl],
    systems: list[dict[str, Any]],
    affected: list[dict[str, Any]],
    categories: Mapping[int, str | None],
) -> list[dict[str, Any]]:
    """The library alternatives found for the scenario, assessed like its identified controls (the register's
    warnings are already the identified controls')."""
    offered = [
        {
            "control_id": control.control_id,
            "code": control.code,
            "score": score,
            "match": Remediation.ALTERNATIVE_MATCH,
        }
        for control, score in found
    ]
    return assess_controls(offered, register, controls, systems, affected, categories)[0]


def _of_its_type(
    row: LibraryControl, affected: list[dict[str, Any]], categories: Mapping[int, str | None]
) -> list[dict[str, Any]]:
    r"""The affected systems a control applies to: an IT control the IT systems, an OT one the OT systems,
    an IT\OT or untyped one all. None fits (a control named by hand): every affected system."""
    fitting = [s for s in affected if _applies(row.asset_type, categories.get(s["supporting_system_id"]))]
    return fitting or affected


def _applies(asset_type: str | None, category: str | None) -> bool:
    """Whether a control of `asset_type` applies to a system of `category`: any, when none is recorded."""
    allowed = compatible_asset_types(None, [category])
    return not allowed or asset_type_fits(asset_type, allowed)


def _assessed_row(
    row: LibraryControl, item: dict[str, Any], affected: list[dict[str, Any]], on: set[int] | None
) -> dict[str, Any]:
    """One mapped control: its library details, the affected systems an existing control is `on` (None: not
    an existing control) and those it is still needed on, and its status from them (on every one, on some, on
    none). No affected system: the risk is on the asset itself, and an existing control is implemented."""
    covered = [system for system in affected if system["supporting_system_id"] in (on or ())]
    needed = [system for system in affected if system["supporting_system_id"] not in (on or ())]
    status = ImplementationStatus.NOT_IMPLEMENTED
    if covered or (not affected and on is not None):
        status = ImplementationStatus.PARTIALLY_IMPLEMENTED if needed else ImplementationStatus.IMPLEMENTED
    return {
        "control_id": row.control_id,
        "control_code": row.code,
        "asset_type": row.asset_type,
        "domain": row.domain,
        "control_name": row.name,
        "control_description": clip(row.description),
        "mapping_relevance": None if item.get("score") is None else round(item["score"]),
        "match": item.get("match"),
        "implementation_status": status,
        "protected_systems": covered,
        "required_systems": needed,
    }


def build_snapshot(
    scenario: dict[str, Any],
    context: FrozenContext,
    register: dict[str, Any],
    library_mapped: list[dict[str, Any]],
    warnings: list[str],
    affected: list[dict[str, Any]],
    alternatives: list[dict[str, Any]],
) -> dict[str, Any]:
    """The version's frozen input; its keys and their order are part of the stored record."""
    content = scenario.get("content") or {}
    identified = register.get("risk_identification_date")
    identified_at = datetime.fromisoformat(identified).isoformat() if identified else None
    return {
        "asset": clip(context.asset["name"]),
        "asset_context": _capped(facts_safe_for_prompt(context.asset_context)),
        "supporting_systems": [
            _capped(facts_safe_for_prompt(raw_system_facts(system))) for system in context.systems
        ],
        "threat": _threat(content),
        "scenario": _scenario(content),
        "risk_scope": {
            "all_supporting_systems_applicable": _on_every_system(register, context, *_RISK_SYSTEMS),
            "affected_systems": affected,
        },
        "existing_controls": _existing(register, context, library_mapped, alternatives),
        "risk_assessment": _assessment(register),
        "treatment_strategy": Remediation.STRATEGY,
        # The facts code copies into the plan and the AI never sees (the risk owner is a person).
        "register": {
            "risk_identification_date": identified_at,
            "risk_owner": clip(register.get("risk_owner")),
            "impacted_business_division": clip(register.get("impacted_business_division")),
        },
        "warnings": list(warnings),
    }


def _existing(
    register: dict[str, Any],
    context: FrozenContext,
    library_mapped: list[dict[str, Any]],
    alternatives: list[dict[str, Any]],
) -> dict[str, Any]:
    """The scenario's identified controls and the library alternatives that may replace one, each assessed
    against the register; whether the existing controls are on every system, and the justification."""
    return {
        "library_mapped": library_mapped,
        "library_alternatives": alternatives,
        "all_supporting_systems_applicable": _on_every_system(register, context, *_EXISTING_SYSTEMS),
        "justification": clip(register.get("existing_controls_all_subsystems_justification")),
    }


def _on_every_system(register: dict[str, Any], context: FrozenContext, listed: str, flag: str) -> int | None:
    """1 when the request's list `listed` names a system and every supporting system of the asset, else 0; a
    register stored before the lists: its own `flag`."""
    if register.get("supporting_systems_applicable_to_risk") is None:
        return register.get(flag)
    every, named = {system["id"] for system in context.linked_systems()}, set(register.get(listed) or [])
    return int(bool(named) and every <= named)


def _threat(content: dict[str, Any]) -> dict[str, Any]:
    """The scenario's threat, its type, category and attackers."""
    threat = content.get("threat") or {}
    return {
        "category": clip(content.get("category")),
        "type": clip(threat.get("type")),
        "name": clip(threat.get("name")),
        "actors": [
            {"name": clip(actor.get("name")), "role": actor.get("role")}
            for actor in content.get("actors") or []
        ],
    }


def _scenario(content: dict[str, Any]) -> dict[str, Any]:
    """The scenario as written, without code's platform note, with its own systems (the scope
    `applicable_to_all_subsystems` judges)."""
    statement, risk = content.get("statement"), content.get("risk_statement")
    return {
        "title": clip(content.get("title")),
        "statement": clip(statement and without_platform_note(statement), Remediation.STATEMENT_MAX_CHARS),
        "risk_statement": clip(risk and without_platform_note(risk), Remediation.STATEMENT_MAX_CHARS),
        "supporting_systems_involved": [
            {"supporting_system": clip(system.get("name")), "is_entry_point": bool(system.get("entry_point"))}
            for system in content.get("systems") or []
        ],
        "route_status": (content.get("route") or {}).get("status"),
    }


def _assessment(register: dict[str, Any]) -> dict[str, Any]:
    """The stored register's ratings as numbers, its level, division and mitigation window."""
    start, end = register.get("mitigation_start_date"), register.get("mitigation_end_date")
    window = None
    if start and end:
        days = (date.fromisoformat(end) - date.fromisoformat(start)).days + 1  # inclusive
        window = {"timeline_start_date": start, "timeline_end_date": end, "total_days": days}
    return {
        **{rating: _number(register.get(rating)) for rating in _RATINGS},
        "risk_level": clip(register.get("risk_level")),
        "impacted_business_division": clip(register.get("impacted_business_division")),
        "assessment_window": window,
    }


def _number(text: str | None) -> int | float | None:
    """A stored rating as a JSON number, an int when whole (the prompt cites it verbatim: 20, never 20.0)."""
    if text is None:
        return None
    value = Decimal(text)
    return int(value) if value == value.to_integral_value() else float(value)


def _capped(value: Any) -> Any:
    """Every text inside a facts block cut by `clip` (facts_safe_for_prompt already redacted it)."""
    if isinstance(value, str):
        return clip(value)
    if isinstance(value, dict):
        return {key: _capped(inner) for key, inner in value.items()}
    if isinstance(value, list):
        return [_capped(inner) for inner in value]
    return value


def plan_prompt(snapshot: dict[str, Any]) -> ChatPrompt:
    """(system, user): the approved rules, and the snapshot as data without the echo, warnings or ids."""
    shown = {key: value for key, value in snapshot.items() if key not in _NOT_SHOWN}
    # The register's window, when it gave one, as the days the AI plans to fit (owner, 2026-10-21); its dates
    # stay code's, which schedules them and warns past the window. No window: the AI estimates freely.
    risk = {key: value for key, value in shown["risk_assessment"].items() if key != "assessment_window"}
    if window := shown["risk_assessment"].get("assessment_window"):
        risk["assessment_window"] = {"total_days": window["total_days"]}
    shown["risk_assessment"] = risk
    # The prompt knows "exact" and "nearest": a control the person named for a hand-written scenario is exact.
    # Systems are named by their names alone: their ids are the API's, never the model's.
    existing = shown["existing_controls"]
    shown["existing_controls"] = existing | {
        part: [
            row
            | {"match": ControlMatch.EXACT if row["match"] == ControlMatch.GIVEN else row["match"]}
            | {key: _names(row[key]) for key in _SYSTEM_LISTS}
            for row in existing[part]
        ]
        for part in ("library_mapped", "library_alternatives")
    }
    scope = shown["risk_scope"]
    shown["risk_scope"] = scope | {"affected_systems": _names(scope["affected_systems"])}
    context = json.dumps(drop_database_ids(shown), ensure_ascii=False, separators=(",", ":"))
    return PLAN_SYSTEM_PROMPT, _CONTEXT_PREFIX + context


def _names(systems: list[dict[str, Any]]) -> list[str]:
    return [system["name"] for system in systems]


def write_plan(chat: ChatModel, snapshot: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """The finished plan and the version's warnings; JobFailed when the AI gives no usable plan."""
    first: list[dict[str, Any]] = []  # a usable first answer: kept when the re-ask drops every action

    def check_first_answer(answer: dict[str, Any]) -> list[str]:
        first.append(answer)
        return _gap_problems(snapshot, answer) + _prose_problems(snapshot, answer)

    try:
        draft: PlanDraft = ask_ai_and_check(
            chat,
            AiTask.REMEDIATION_PLAN,
            plan_prompt(snapshot),
            _read_answer,
            check_first_answer,
            reuse_earlier_answer=True,  # a retry after a crash reads back the plan its epoch already got
        )
    except (UnreadableAiAnswer, TruncatedAiAnswer) as exc:
        reason = shorten_text(str(exc), Remediation.REASON_MAX_CHARS)
        message = RemediationMessage.PLAN_UNUSABLE.format(reason=reason)
        raise JobFailed(ErrorCode.GENERATION_FAILED, message) from exc
    if first and not draft.remediation_action_plan:
        draft = PlanDraft.model_validate(first[0])
    plan, warnings = _finish(draft, snapshot)
    return plan, [*snapshot["warnings"], *warnings, *schedule_plan(plan, snapshot)]


def _read_answer(answer: dict[str, Any]) -> tuple[PlanDraft | None, list[str]]:
    """The answer as a PlanDraft, or its shape problems."""
    problems = answer_item_problems(PlanDraft, answer, "the reply")
    return (None, problems) if problems else (PlanDraft.model_validate(answer), [])


def _key(code: str) -> str:
    return code.strip().casefold()


def _checks(snapshot: dict[str, Any], draft: PlanDraft) -> dict[str, DraftValidation]:
    """The AI's check of each identified control by its code: the first one given for a code."""
    identified = {_key(row["control_code"]) for row in snapshot["existing_controls"]["library_mapped"]}
    checks: dict[str, DraftValidation] = {}
    for check in draft.control_validation:
        if _key(check.control_code) in identified:
            checks.setdefault(_key(check.control_code), check)
    return checks


def _weighed(snapshot: dict[str, Any], draft: PlanDraft) -> tuple[list[dict[str, Any]], list[str]]:
    """Every control the plan weighs, as its assessment row: each identified control with its check (a flagged
    one unverified), then each library alternative chosen to replace one; the warnings for a check not given
    or naming no alternative, whose control is flagged for review."""
    existing = snapshot["existing_controls"]
    offered = {_key(row["control_code"]): row for row in existing.get("library_alternatives") or []}
    checks = _checks(snapshot, draft)
    rows: list[dict[str, Any]] = []
    chosen: dict[str, dict[str, Any]] = {}
    warnings: list[str] = []
    for row in existing["library_mapped"]:
        check = checks.get(_key(row["control_code"]))
        reason = clip(check.reason) if check else None
        weighed = row | {"validation": ControlValidation.FLAGGED_FOR_REVIEW, "validation_reason": reason}
        weighed |= {"replaced_by": None, "replaces": []}
        if check is None:
            warnings.append(PlanWarning.VALIDATION_NOT_GIVEN.format(code=row["control_code"]))
        elif check.validation != ControlValidation.REPLACED:
            weighed["validation"] = check.validation
        elif (alternative := offered.get(_key(check.replacement_code or ""))) is None:
            replacement = check.replacement_code
            warnings.append(
                PlanWarning.REPLACEMENT_REFUSED.format(code=row["control_code"], replacement=replacement)
            )
        else:
            weighed |= {"validation": ControlValidation.REPLACED, "replaced_by": alternative["control_code"]}
            fresh = alternative | {
                "validation": None,
                "validation_reason": reason,
                "replaced_by": None,
                "replaces": [],
            }
            chosen.setdefault(alternative["control_code"], fresh)["replaces"].append(row["control_code"])
        if weighed["validation"] == ControlValidation.FLAGGED_FOR_REVIEW:
            weighed["implementation_status"] = ImplementationStatus.UNVERIFIED
        rows.append(weighed)
    return rows + list(chosen.values()), warnings


def _all_implemented(validated: list[dict[str, Any]]) -> bool:
    """Whether checked controls exist and every one is implemented: the plan is "covered"."""
    return bool(validated) and all(
        row["implementation_status"] == ImplementationStatus.IMPLEMENTED for row in validated
    )


def _validated(row: dict[str, Any]) -> bool:
    """A control the check kept: an identified one retained, or an alternative chosen to replace one."""
    return row["validation"] == ControlValidation.RETAINED or bool(row["replaces"])


def _gap_problems(snapshot: dict[str, Any], answer: dict[str, Any]) -> list[str]:
    """A shape-valid first answer's faults: an identified control left unchecked, or replaced by a code
    outside the alternatives; a kept gap left out; an implemented, replaced or flagged control named."""
    draft = PlanDraft.model_validate(answer)
    checks = _checks(snapshot, draft)
    offered = {
        _key(row["control_code"]) for row in snapshot["existing_controls"].get("library_alternatives") or []
    }
    problems = []
    for row in snapshot["existing_controls"]["library_mapped"]:
        code, check = row["control_code"], checks.get(_key(row["control_code"]))
        if check is None:
            problems.append(RemediationMessage.VALIDATION_MISSING.format(code=code))
        elif check.validation == ControlValidation.REPLACED and not check.replacement_code:
            problems.append(RemediationMessage.REPLACEMENT_REQUIRED.format(code=code))
        elif (
            check.validation == ControlValidation.REPLACED
            and _key(check.replacement_code or "") not in offered
        ):
            problems.append(
                RemediationMessage.REPLACEMENT_UNKNOWN.format(code=code, replacement=check.replacement_code)
            )
    listed = {_key(control.control_code) for control in draft.controls_to_be_implemented}
    named = listed | {
        _key(code) for action in draft.remediation_action_plan for code in action.implements_controls
    }
    for row in _weighed(snapshot, draft)[0]:
        code, status, key = row["control_code"], row["implementation_status"], _key(row["control_code"])
        if _validated(row) and status in _GAPS and key not in listed:
            problems.append(RemediationMessage.GAP_REQUIRED.format(code=code, status=status))
        elif status == ImplementationStatus.IMPLEMENTED and key in named:
            problems.append(RemediationMessage.IMPLEMENTED_LISTED.format(code=code))
        elif not _validated(row) and key in named:
            problems.append(
                RemediationMessage.NOT_VALIDATED_LISTED.format(code=code, validation=row["validation"])
            )
    return problems


def _prose_problems(snapshot: dict[str, Any], answer: dict[str, Any]) -> list[str]:
    """A shape-valid first answer's prose faults: a partial control described as new or a not implemented one
    as extended, an interim action when covered, an action_plan of nothing but code's facts (`_finish` removes
    those sentences itself, so only an action_plan they would empty is asked again)."""
    draft = PlanDraft.model_validate(answer)
    claims = dict.fromkeys(match.group(0) for match in _CODE_FACT.finditer(draft.action_plan))
    if _without_code_facts(draft.action_plan):  # something is left once code's sentences go: no re-ask
        claims = {}
    problems = [RemediationMessage.CODE_FACT_IN_ACTION_PLAN.format(claim=claim) for claim in claims]
    rows, _ = _weighed(snapshot, draft)
    status_of = {_key(row["control_code"]): row["implementation_status"] for row in rows}
    for control in draft.controls_to_be_implemented:
        status, extends = status_of.get(_key(control.control_code)), _EXTENDS.search(control.description)
        if status == ImplementationStatus.PARTIALLY_IMPLEMENTED and not extends:
            problems.append(RemediationMessage.PARTIAL_NOT_EXTENDED.format(code=control.control_code))
        elif status == ImplementationStatus.NOT_IMPLEMENTED and extends:
            problems.append(RemediationMessage.MISSING_EXTENDED.format(code=control.control_code))
    if _all_implemented([row for row in rows if _validated(row)]):
        problems += [
            RemediationMessage.INTERIM_WHEN_COVERED.format(action=action.action_id)
            for action in draft.remediation_action_plan
            if action.action.strip().casefold().startswith("interim")
        ]
    return problems


def _without_code_facts(text: str) -> str:
    """`text` without a sentence stating the schedule or the library: those are code's.
    ponytail: whole sentences go; a text of nothing but such sentences comes back empty."""
    sentences = _SENTENCE_END.split(text.strip())
    return " ".join(sentence for sentence in sentences if not _CODE_FACT.search(sentence))


def _finish(draft: PlanDraft, snapshot: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """The plan as stored, before its schedule: the checked gaps kept and stamped; coverage, title,
    assessment, each action's systems and the unresolved gaps code's."""
    plan = draft.model_dump(mode="json", exclude={"control_validation", "uncovered_risks"})
    if not plan["remediation_action_plan"]:
        raise JobFailed(ErrorCode.INVALID_PLAN, RemediationMessage.PLAN_WITHOUT_ACTION)
    plan["action_plan"] = _without_code_facts(plan["action_plan"])  # the schedule and the library are code's
    rows, warnings = _weighed(snapshot, draft)
    gaps = {_key(r["control_code"]): r for r in rows if _validated(r) and r["implementation_status"] in _GAPS}
    controls, kept_warnings = _kept_controls(plan["controls_to_be_implemented"], rows, gaps)
    recommended = [control["control_code"] for control in controls]
    validated = [row for row in rows if _validated(row)]
    covered = _all_implemented(validated)
    named = validated if covered else [row for row in rows if row["control_code"] in recommended]
    every_system = snapshot["risk_scope"]["all_supporting_systems_applicable"] == 1
    plan |= {
        "title": _title(named, covered) or plan["title"],
        "applicable_to_all_subsystems": YesNo.YES if every_system else YesNo.NO,  # the risk flag's, for v1
        "controls_to_be_implemented": {
            "control_coverage": ControlCoverage.COVERED if covered else ControlCoverage.GAPS,
            "controls": controls,
        },
        # Code's keys last, so nothing the AI wrote can stand in for the strategy or the register's facts.
        "treatment_strategy": Remediation.STRATEGY,
        **snapshot["register"],
        "control_assessment": [
            {key: row[key] for key in _ASSESSED} | {"recommended": row["control_code"] in recommended}
            for row in rows
        ],
        "unresolved_gaps": _unresolved_gaps(rows, validated, draft.uncovered_risks),
    }
    warnings += kept_warnings + [
        PlanWarning.GAP_NOT_ADDRESSED.format(code=row["control_code"], status=row["implementation_status"])
        for row in gaps.values()
        if row["control_code"] not in recommended
    ]
    return plan, warnings + _finish_actions(
        plan, snapshot, [row for row in rows if row["control_code"] in recommended]
    )


def _finish_actions(
    plan: dict[str, Any], snapshot: dict[str, Any], recommended: list[dict[str, Any]]
) -> list[str]:
    """Each action's implements_controls cut to the recommended codes and its systems set; the warnings."""
    actions = plan["remediation_action_plan"]
    warnings = _delivery_warnings(actions, [row["control_code"] for row in recommended])
    return warnings + _action_systems(actions, snapshot["risk_scope"]["affected_systems"], recommended)


def _unresolved_gaps(
    rows: list[dict[str, Any]], validated: list[dict[str, Any]], uncovered: list[str]
) -> list[dict[str, Any]]:
    """What no checked control closes: each control flagged for review, no checked control at all, and the
    parts of the risk the AI says the checked controls leave uncovered (without code's facts)."""
    gaps: list[dict[str, Any]] = [
        {
            "kind": GapKind.FLAGGED_CONTROL,
            "control_code": row["control_code"],
            "detail": PlanText.GAP_FLAGGED.format(code=row["control_code"], name=row["control_name"]),
        }
        for row in rows
        if row["validation"] == ControlValidation.FLAGGED_FOR_REVIEW
    ]
    if not validated:
        gaps.append(
            {
                "kind": GapKind.NO_VALIDATED_CONTROL,
                "control_code": None,
                "detail": PlanText.GAP_NONE_VALIDATED,
            }
        )
    texts = dict.fromkeys(clip(_without_code_facts(text)) or "" for text in uncovered)
    return gaps + [
        {"kind": GapKind.UNCOVERED_RISK, "control_code": None, "detail": text} for text in texts if text
    ]


def _title(controls: list[dict[str, Any]], covered: bool) -> str | None:
    """The plan's name from the library domains of the controls it recommends (verifies, when covered), in
    mapping order; None when none has a domain, and the AI's name stays."""
    domains = list(dict.fromkeys(row["domain"] for row in controls if row.get("domain")))
    if not domains:
        return None
    joined = domains[0] if len(domains) == 1 else ", ".join(domains[:-1]) + " and " + domains[-1]
    return (PlanText.VERIFICATION_TITLE if covered else PlanText.REMEDIATION_TITLE).format(domains=joined)


def _kept_controls(
    drafted: list[dict[str, Any]], rows: list[dict[str, Any]], gaps: dict[str, dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[str]]:
    """The recommended controls that are checked gaps of this scenario, once each, stamped from their row."""
    by_code = {_key(row["control_code"]): row for row in rows}
    kept: list[dict[str, Any]] = []
    seen: set[int] = set()
    warnings: list[str] = []
    for control in drafted:
        key = _key(control["control_code"])
        row = by_code.get(key)
        if row is None:
            warnings.append(PlanWarning.CONTROL_NOT_IN_LIBRARY.format(code=control["control_code"]))
        elif row["implementation_status"] == ImplementationStatus.IMPLEMENTED:
            warnings.append(PlanWarning.CONTROL_IN_REGISTER.format(code=row["control_code"]))
        elif key not in gaps:
            warnings.append(
                PlanWarning.CONTROL_NOT_VALIDATED.format(
                    code=row["control_code"], validation=row["validation"]
                )
            )
        elif row["control_id"] in seen:
            warnings.append(PlanWarning.CONTROL_LISTED_TWICE.format(code=row["control_code"]))
        else:
            seen.add(row["control_id"])
            kept.append(control | {key: row[key] for key in _STAMPED})
    return kept, warnings


def _action_systems(
    actions: list[dict[str, Any]], affected: list[dict[str, Any]], recommended: list[dict[str, Any]]
) -> list[str]:
    """Each action's supporting systems as the API shows them: the affected systems the AI named; none named,
    those its controls are still needed on, else every affected system. The warnings for other names."""
    by_name = {name_match_key(system["name"]): system for system in affected}
    needed = {row["control_code"]: row["required_systems"] for row in recommended}
    warnings: list[str] = []
    for position, action in enumerate(actions):
        label = str(action.get("action_id") or "").strip() or f"remediation_action_plan[{position}]"
        named: set[int] = set()
        for given in action.get("supporting_systems") or []:
            system = by_name.get(name_match_key(str(given)))
            if system is None:
                warnings.append(PlanWarning.ACTION_SYSTEM_UNKNOWN.format(action=label, system=given))
            else:
                named.add(system["supporting_system_id"])
        if not named:
            named = {
                s["supporting_system_id"]
                for code in action["implements_controls"]
                for s in needed.get(code, [])
            }
        action["supporting_systems"] = [s for s in affected if s["supporting_system_id"] in named] or list(
            affected
        )
    return warnings


def _delivery_warnings(actions: list[dict[str, Any]], recommended: list[str]) -> list[str]:
    """Each action's implements_controls cut to recommended codes, spelt as the library does; the warnings."""
    known = {code.strip().casefold(): code for code in recommended}
    warnings: list[str] = []
    delivered: set[str] = set()
    for position, action in enumerate(actions):
        name = str(action.get("action_id") or "").strip() or f"remediation_action_plan[{position}]"
        codes = []
        for echoed in (str(code).strip() for code in action["implements_controls"]):
            canonical = known.get(echoed.casefold())
            if canonical is None:
                warnings.append(PlanWarning.IMPLEMENTS_UNKNOWN.format(action=name, code=echoed))
            else:
                codes.append(canonical)
        action["implements_controls"] = codes
        delivered.update(codes)
    return warnings + [
        PlanWarning.CONTROL_NOT_IMPLEMENTED.format(code=code) for code in recommended if code not in delivered
    ]
