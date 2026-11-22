"""One plan version: its input built from the scenario and the register, the AI's answer and code's checks."""

import json
import re
from collections.abc import Mapping, Sequence
from datetime import date, datetime, timedelta
from decimal import Decimal
from typing import Annotated, Any

from pydantic import AfterValidator, BaseModel, BeforeValidator

from app.ai import ChatModel, TruncatedAiAnswer, UnreadableAiAnswer
from app.core.asset_types import asset_type_fits, compatible_asset_types
from app.core.constants import (
    ActionPriority,
    AiTask,
    AnswerProblem,
    ControlCoverage,
    ControlMatch,
    ControlType,
    ControlValidation,
    ErrorCode,
    GapKind,
    ImplementationStatus,
    PlanText,
    PlanWarning,
    Remediation,
    Status,
    YesNo,
)
from app.core.exceptions import JobFailed
from app.core.prompts import PROMPTS
from app.core.redaction import redact
from app.domain.shared.ask_ai import ChatPrompt, answer_item_problems, ask_ai_and_check
from app.domain.shared.names import name_match_key, shorten_text
from app.domain.shared.prompt_redaction import drop_database_ids, facts_safe_for_prompt, without_platform_note
from app.schemas.library import LibraryControl
from app.schemas.remediation import ControlRef, Doc
from app.schemas.scenario_internal import FrozenContext
from app.search.snapshot import describe_control

PLAN_SYSTEM_PROMPT: str = PROMPTS["remediation"]["plan"]["text"]
_CONTEXT_PREFIX: str = PROMPTS["remediation"]["plan"]["context_prefix"]
_NOT_SHOWN = ("register", "warnings")
_RATINGS = ("likelihood_rating", "impact_rating", "final_risk_rating")
_SYSTEM_LISTS = ("protected_systems", "required_systems")
_LABEL = ("control_id", "control_code", "control_name", "domain")
_STAMPED = (*_LABEL, "implementation_status", "required_systems")
_CHECKED = ("validation", "validation_reason", "replaced_by", "replaces")
_ASSESSED = (*_LABEL, "match", "implementation_status", *_SYSTEM_LISTS, *_CHECKED)
_GAPS = (ImplementationStatus.NOT_IMPLEMENTED, ImplementationStatus.PARTIALLY_IMPLEMENTED)
_CODE_FACT = re.compile(
    (
        r"\b(?:\d+|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen"
        r"|sixteen|seventeen|eighteen|nineteen|twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety|hundred)"
        r"(?:\s*-\s*|\s+)(?:calendar\s+|working\s+|business\s+)?(?:day|week|month)s?\b"
        r"|\b\d{4}-\d{2}-\d{2}\b|\bcritical[\s-]+path\b|\bdeadlines?\b"
        r"|\b(?<!maintenance\s)(?<!change\s)(?<!outage\s)windows?\b"
        r"|\b(?:parallel|concurrent(?:ly)?|simultaneous(?:ly)?|sequential(?:ly)?|in\s+sequence)\b"
        r"|\blibrar(?:y|ies)\b"
    ),
    re.IGNORECASE,
)
_EXTENDS = re.compile(r"\b(?:extend|expand|broaden)", re.IGNORECASE)
_VALIDATION_MISSING = "control_validation must give one entry for {code}: retained, replaced or flagged_for_review"
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+")
_ControlLookup = tuple[dict[int, LibraryControl], dict[str, LibraryControl], dict[str, LibraryControl | None]]
# ponytail: one slot (one active library per process); two libraries used by turns would rebuild each time.
_last_lookup: list[tuple[Sequence[LibraryControl], _ControlLookup]] = []


def _given(value: str) -> str:
    if not value.strip():
        raise ValueError(AnswerProblem.TEXT_REQUIRED)
    return value


Given = Annotated[str, AfterValidator(_given)]


def _the_controls(value: Any) -> Any:
    return value.get("controls", value) if isinstance(value, dict) else value


def _keep_first_known_type(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    parts = (part.strip() for part in re.split(r"[/,]", value))
    return next((part for part in parts if part in ControlType), value)


class DraftControl(BaseModel):
    control_type: Annotated[ControlType, BeforeValidator(_keep_first_known_type)]
    control_name: Given
    description: str
    priority: ActionPriority
    control_code: Given  # a library_mapped code, verbatim; code stamps the library id


class DraftAction(BaseModel):
    action_id: str
    action: Given
    owner: Given
    priority: ActionPriority
    dependencies: str
    depends_on: list[str]
    duration_days: int  # repaired by the scheduler when below 1 or above Remediation.MAX_ACTION_DAYS
    implements_controls: list[str]
    supporting_systems: list[str] = []  # the affected systems it works on, by name; code checks them
    success_criteria: Given


class DraftValidation(BaseModel):
    control_code: Given  # a library_mapped code, verbatim
    validation: ControlValidation
    replacement_code: str | None = None  # "replaced": a library_alternatives code, verbatim
    reason: Given  # why; for an implemented control, how the existing control already reduces this risk


class PlanDraft(BaseModel):
    title: str = ""  # a fallback only: code names the plan from its controls' domains (glm leaves it out)
    control_validation: list[DraftValidation]
    controls_to_be_implemented: Annotated[list[DraftControl], BeforeValidator(_the_controls)]
    remediation_action_plan: list[DraftAction]
    action_plan: Given
    mitigation_owner: Given
    uncovered_risks: list[str] = []  # parts of the risk no checked control reduces


def redact_and_shorten_text(text: str | None, limit: int = Remediation.TEXT_MAX_CHARS) -> str | None:
    """Free text as a snapshot holds it: redacted, then cut at `limit` with a mark."""
    if text is None:
        return None
    cleaned = redact(text)
    return cleaned if len(cleaned) <= limit else cleaned[:limit] + Remediation.TRUNCATED_MARK


def _index_controls(controls: Sequence[LibraryControl]) -> _ControlLookup:
    cached = next((lookup for library, lookup in _last_lookup if library is controls), None)
    if cached is not None:
        return cached
    by_id = {row.control_id: row for row in controls}
    by_code = {row.code.casefold(): row for row in controls}
    # IT/OT twins (same name and description) go to the lowest id; a name two different controls share
    # names neither, so only a code or id says which.
    by_name: dict[str, LibraryControl | None] = {}
    for control in sorted(controls, key=lambda control: control.control_id):
        key, text = name_match_key(control.name), name_match_key(describe_control(control))
        first = by_name.setdefault(key, control)
        if first is not None and name_match_key(describe_control(first)) != text:
            by_name[key] = None
    lookup = (by_id, by_code, by_name)
    if isinstance(controls, tuple):  # a list can change in place: never kept
        _last_lookup[:] = [(controls, lookup)]
    return lookup


def resolve_control_refs(
    refs: Sequence[ControlRef], controls: Sequence[LibraryControl]
) -> tuple[list[LibraryControl], list[tuple[int, ControlRef]]]:
    """The library rows `refs` name, once each in first-named order; the refs naming none, with positions."""
    by_id, by_code, by_name = _index_controls(controls)
    found: dict[int, LibraryControl] = {}
    unresolved: list[tuple[int, ControlRef]] = []
    for position, ref in enumerate(refs):
        if ref.control_id is not None:
            row = by_id.get(ref.control_id)
        else:
            row = by_code.get(ref.control_code.casefold()) if ref.control_code else None
            if row is None and ref.control_name:
                row = by_name.get(name_match_key(ref.control_name))
                head = re.match(r"[^\s·•|:—–]+", ref.control_name)
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


def active_mapped_controls(scenario: Doc, controls_by_id: Mapping[int, LibraryControl]) -> list[Doc]:
    """The scenario's mapped control items still in the library; [] when none is (the job maps them)."""
    controls = scenario.get("controls") or {}
    if controls.get("status") != Status.DONE:
        return []
    return [item for item in controls.get("items") or [] if item["control_id"] in controls_by_id]


def list_affected_systems(context: FrozenContext, register: Doc) -> list[Doc]:
    """The asset's supporting systems the register's risk list names, in the asset's order."""
    listed = set(register["supporting_systems_applicable_to_risk"])
    return [
        {"supporting_system_id": system["id"], "name": system["name"]}
        for system in context.linked_systems()
        if system["id"] in listed
    ]


def assess_controls(
    items: list[Doc],
    register: Doc,
    controls: Sequence[LibraryControl],
    affected: list[Doc],
    categories: Mapping[int, str | None],
) -> tuple[list[Doc], list[str]]:
    """Each mapped control with its library details and status on the affected systems, plus warnings."""
    covered_systems = set(register["supporting_systems_applicable_to_existing_controls"])
    refs = [ControlRef.model_validate(entry) for entry in register.get("existing_controls") or []]
    named, unresolved = resolve_control_refs(refs, controls)
    warnings = [PlanWarning.CONTROL_UNMATCHED.format(reference=describe_ref(ref)) for _, ref in unresolved]
    existing = {name_match_key(describe_control(row)) for row in named}  # IT/OT twins are one
    by_id = _index_controls(controls)[0]
    library_mapped = []
    for item in items:
        row = by_id.get(item["control_id"])
        if row is None:
            warnings.append(PlanWarning.CONTROL_UNMATCHED.format(reference=item.get("code")))
            continue
        on = covered_systems if name_match_key(describe_control(row)) in existing else None
        library_mapped.append(_assessed_row(row, item, affected, categories, on))
    return library_mapped, warnings


def existing_controls_not_for_this_risk(
    register: Doc, controls: Sequence[LibraryControl], considered_ids: Sequence[int]
) -> list[str]:
    """A warning for each library control the register says is in place that is none of the controls the plan
    weighs (the scenario's and their alternatives, IT/OT twins as one), so the person sees it was not counted."""
    by_id = _index_controls(controls)[0]
    considered = set()
    for control_id in considered_ids:
        if control_id in by_id:
            considered.add(name_match_key(describe_control(by_id[control_id])))
    refs = [ControlRef.model_validate(entry) for entry in register.get("existing_controls") or []]
    warnings = []
    for row in resolve_control_refs(refs, controls)[0]:
        if name_match_key(describe_control(row)) not in considered:
            reference = f"{row.code} — {row.name}"
            warnings.append(PlanWarning.EXISTING_CONTROL_NOT_FOR_THIS_RISK.format(reference=reference))
    return warnings


def _assessed_row(
    row: LibraryControl, item: Doc, affected: list[Doc], categories: Mapping[int, str | None], on: set[int] | None
) -> Doc:
    # An IT control counts on the IT systems, an OT one on the OT systems, an IT\OT or untyped one on all; a
    # system of no recorded category takes any. None fits (a control named by hand): every affected system.
    fitting = []
    for system in affected:
        allowed = compatible_asset_types(None, [categories.get(system["supporting_system_id"])])
        if not allowed or asset_type_fits(row.asset_type, allowed):
            fitting.append(system)
    affected = fitting or affected
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
        "control_description": redact_and_shorten_text(row.description),
        "mapping_relevance": None if item.get("score") is None else round(item["score"]),
        "match": item.get("match"),
        "implementation_status": status,
        "protected_systems": covered,
        "required_systems": needed,
    }


def build_snapshot(
    scenario: Doc,
    context: FrozenContext,
    register: Doc,
    library_mapped: list[Doc],
    warnings: list[str],
    affected: list[Doc],
    alternatives: list[Doc],
) -> Doc:
    """The version's frozen input; its keys and their order are part of the stored record."""
    content = scenario.get("content") or {}
    identified = register.get("risk_identification_date")
    identified_at = datetime.fromisoformat(identified).isoformat() if identified else None
    return {
        "asset": redact_and_shorten_text(context.asset["name"]),
        "asset_context": _shorten_all_texts(facts_safe_for_prompt(context.asset_context)),
        "supporting_systems": [
            _shorten_all_texts(facts_safe_for_prompt(FrozenContext.read_system_facts(system)))
            for system in context.systems
        ],
        "threat": _threat(content),
        "scenario": _scenario(content),
        "risk_scope": {
            "all_supporting_systems_applicable": _on_every_system(
                context, register["supporting_systems_applicable_to_risk"]
            ),
            "affected_systems": affected,
        },
        "existing_controls": _existing(register, context, library_mapped, alternatives),
        "risk_assessment": _assessment(register),
        "treatment_strategy": Remediation.STRATEGY,
        "register": {
            "risk_identification_date": identified_at,
            "risk_owner": redact_and_shorten_text(register.get("risk_owner")),
            "impacted_business_division": redact_and_shorten_text(register.get("impacted_business_division")),
        },
        "warnings": list(warnings),
    }


def _existing(register: Doc, context: FrozenContext, library_mapped: list[Doc], alternatives: list[Doc]) -> Doc:
    return {
        "library_mapped": library_mapped,
        "library_alternatives": alternatives,
        "all_supporting_systems_applicable": _on_every_system(
            context, register["supporting_systems_applicable_to_existing_controls"]
        ),
        "justification": redact_and_shorten_text(register.get("existing_controls_all_subsystems_justification")),
    }


def _on_every_system(context: FrozenContext, listed: Sequence[int]) -> int:
    every, named = {system["id"] for system in context.linked_systems()}, set(listed)
    return int(bool(named) and every <= named)


def _threat(content: Doc) -> Doc:
    threat = content.get("threat") or {}
    return {
        "category": redact_and_shorten_text(content.get("category")),
        "type": redact_and_shorten_text(threat.get("type")),
        "name": redact_and_shorten_text(threat.get("name")),
        "actors": [
            {"name": redact_and_shorten_text(actor.get("name")), "role": actor.get("role")}
            for actor in content.get("actors") or []
        ],
    }


def _scenario(content: Doc) -> Doc:
    statement, risk = content.get("statement"), content.get("risk_statement")
    return {
        "title": redact_and_shorten_text(content.get("title")),
        "statement": redact_and_shorten_text(
            statement and without_platform_note(statement), Remediation.STATEMENT_MAX_CHARS
        ),
        "risk_statement": redact_and_shorten_text(
            risk and without_platform_note(risk), Remediation.STATEMENT_MAX_CHARS
        ),
        "supporting_systems_involved": [
            {
                "supporting_system": redact_and_shorten_text(system.get("name")),
                "is_entry_point": bool(system.get("entry_point")),
            }
            for system in content.get("systems") or []
        ],
        "route_status": (content.get("route") or {}).get("status"),
    }


def _assessment(register: Doc) -> Doc:
    start, end = register.get("mitigation_start_date"), register.get("mitigation_end_date")
    window = None
    if start:
        days = (date.fromisoformat(end) - date.fromisoformat(start)).days + 1 if end else None  # inclusive
        window = {"timeline_start_date": start, "timeline_end_date": end, "total_days": days}
    return {
        **{rating: _rating_text_to_number(register.get(rating)) for rating in _RATINGS},
        "risk_level": redact_and_shorten_text(register.get("risk_level")),
        "impacted_business_division": redact_and_shorten_text(register.get("impacted_business_division")),
        "assessment_window": window,
    }


def _rating_text_to_number(text: str | None) -> int | float | None:
    if text is None:
        return None
    value = Decimal(text)
    return int(value) if value == value.to_integral_value() else float(value)


def _shorten_all_texts(value: Any) -> Any:
    if isinstance(value, str):
        return redact_and_shorten_text(value)
    if isinstance(value, dict):
        return {key: _shorten_all_texts(inner) for key, inner in value.items()}
    if isinstance(value, list):
        return [_shorten_all_texts(inner) for inner in value]
    return value


def plan_prompt(snapshot: Doc) -> ChatPrompt:
    """(system, user): the approved rules, and the snapshot as data without the echo, warnings or ids."""
    shown = {key: value for key, value in snapshot.items() if key not in _NOT_SHOWN}
    risk = {key: value for key, value in shown["risk_assessment"].items() if key != "assessment_window"}
    window = shown["risk_assessment"].get("assessment_window") or {}
    if window.get("total_days"):
        risk["assessment_window"] = {"total_days": window["total_days"]}
    shown["risk_assessment"] = risk
    # Systems are named by their names alone: their ids are the API's, never the model's.
    existing = shown["existing_controls"]
    shown["existing_controls"] = existing | {
        part: [
            row
            | {"match": ControlMatch.EXACT if row["match"] == ControlMatch.GIVEN else row["match"]}
            | {key: [system["name"] for system in row[key]] for key in _SYSTEM_LISTS}
            for row in existing[part]
        ]
        for part in ("library_mapped", "library_alternatives")
    }
    affected_names = [system["name"] for system in shown["risk_scope"]["affected_systems"]]
    shown["risk_scope"] = shown["risk_scope"] | {"affected_systems": affected_names}
    context = json.dumps(drop_database_ids(shown), ensure_ascii=False, separators=(",", ":"))
    return PLAN_SYSTEM_PROMPT, _CONTEXT_PREFIX + context


def write_plan(chat: ChatModel, snapshot: Doc) -> tuple[Doc, list[str]]:
    """The finished plan and the version's warnings; JobFailed when the AI gives no usable plan."""
    first: list[Doc] = []  # a usable first answer: kept when the re-ask drops every action

    def check_first_answer(answer: Doc) -> list[str]:
        first.append(answer)
        draft = PlanDraft.model_validate(answer)
        rows, _ = _apply_ai_verdicts(snapshot, draft)
        return _gap_problems(snapshot, draft, rows) + _prose_problems(draft, rows)

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
        reason = shorten_text(str(exc), 300)
        message = f"The AI could not write a usable remediation plan: {reason}"
        raise JobFailed(ErrorCode.GENERATION_FAILED, message) from exc
    if first and not draft.remediation_action_plan:
        draft = PlanDraft.model_validate(first[0])
    plan, warnings = _build_final_plan(draft, snapshot)
    return plan, [*snapshot["warnings"], *warnings, *schedule_plan(plan, snapshot)]


def _read_answer(answer: Doc) -> tuple[PlanDraft | None, list[str]]:
    problems = answer_item_problems(PlanDraft, answer, "the reply")
    return (None, problems) if problems else (PlanDraft.model_validate(answer), [])


def _normalise_code(code: str) -> str:
    return code.strip().casefold()


def _ai_verdict_for_each_control(snapshot: Doc, draft: PlanDraft) -> dict[str, DraftValidation]:
    identified = {_normalise_code(row["control_code"]) for row in snapshot["existing_controls"]["library_mapped"]}
    checks: dict[str, DraftValidation] = {}
    for check in draft.control_validation:
        if _normalise_code(check.control_code) in identified:
            checks.setdefault(_normalise_code(check.control_code), check)
    return checks


def _apply_ai_verdicts(snapshot: Doc, draft: PlanDraft) -> tuple[list[Doc], list[str]]:
    existing = snapshot["existing_controls"]
    offered = {_normalise_code(row["control_code"]): row for row in existing.get("library_alternatives") or []}
    checks = _ai_verdict_for_each_control(snapshot, draft)
    rows: list[Doc] = []
    chosen: dict[str, Doc] = {}
    warnings: list[str] = []
    for row in existing["library_mapped"]:
        check = checks.get(_normalise_code(row["control_code"]))
        reason = redact_and_shorten_text(check.reason) if check else None
        weighed = row | {"validation": ControlValidation.FLAGGED_FOR_REVIEW, "validation_reason": reason}
        weighed |= {"replaced_by": None, "replaces": []}
        if check is None:
            warnings.append(PlanWarning.VALIDATION_NOT_GIVEN.format(code=row["control_code"]))
        elif check.validation != ControlValidation.REPLACED:
            weighed["validation"] = check.validation
        elif (alternative := offered.get(_normalise_code(check.replacement_code or ""))) is None:
            replacement = check.replacement_code
            warnings.append(PlanWarning.REPLACEMENT_REFUSED.format(code=row["control_code"], replacement=replacement))
        else:
            weighed |= {"validation": ControlValidation.REPLACED, "replaced_by": alternative["control_code"]}
            fresh = alternative | {"validation": None, "validation_reason": reason, "replaced_by": None, "replaces": []}
            chosen.setdefault(alternative["control_code"], fresh)["replaces"].append(row["control_code"])
        if weighed["validation"] == ControlValidation.FLAGGED_FOR_REVIEW:
            weighed["implementation_status"] = ImplementationStatus.UNVERIFIED
        rows.append(weighed)
    return rows + list(chosen.values()), warnings


def _all_implemented(validated: list[Doc]) -> bool:
    return bool(validated) and all(
        row["implementation_status"] == ImplementationStatus.IMPLEMENTED for row in validated
    )


def _is_kept_after_ai_check(row: Doc) -> bool:
    return row["validation"] == ControlValidation.RETAINED or bool(row["replaces"])


def _gap_problems(snapshot: Doc, draft: PlanDraft, rows: list[Doc]) -> list[str]:
    checks = _ai_verdict_for_each_control(snapshot, draft)
    existing = snapshot["existing_controls"]
    controls = [*existing["library_mapped"], *(existing.get("library_alternatives") or [])]
    known = {_normalise_code(row["control_code"]) for row in controls}
    problems = []
    for row in existing["library_mapped"]:
        code, check = row["control_code"], checks.get(_normalise_code(row["control_code"]))
        if check is None:
            problems.append(_VALIDATION_MISSING.format(code=code))
        elif check.validation == ControlValidation.REPLACED and not check.replacement_code:
            problems.append(f"{code} is replaced: give its replacement_code, one of library_alternatives")
        elif (
            check.validation == ControlValidation.REPLACED
            and _normalise_code(check.replacement_code or "") not in known
        ):
            problems.append(f"{code} is replaced by {check.replacement_code}, which is not one of library_alternatives")
    listed = {_normalise_code(control.control_code) for control in draft.controls_to_be_implemented}
    implemented = {code for action in draft.remediation_action_plan for code in action.implements_controls}
    named = listed | {_normalise_code(code) for code in implemented}
    for row in rows:
        code, status = row["control_code"], row["implementation_status"]
        key = _normalise_code(code)
        if _is_kept_after_ai_check(row) and status in _GAPS and key not in listed:
            problems.append(f"controls_to_be_implemented must include {code}: it is {status} for this scenario")
        elif status == ImplementationStatus.IMPLEMENTED and key in named:
            problems.append(
                f"{code} is already implemented: remove it from controls_to_be_implemented and "
                "from every implements_controls"
            )
        elif not _is_kept_after_ai_check(row) and key in named:
            problems.append(
                f"{code} is {row['validation']}: remove it from controls_to_be_implemented and from every"
                " implements_controls"
            )
    return problems


def _prose_problems(draft: PlanDraft, rows: list[Doc]) -> list[str]:
    claims = dict.fromkeys(match.group(0) for match in _CODE_FACT.finditer(draft.action_plan))
    if _without_code_facts(draft.action_plan):  # something is left once code's sentences go: no re-ask
        claims = {}
    problems = [
        (
            f"action_plan says only what the application states itself ('{claim}'): describe "
            "the actions and how they reduce the risk, with no schedule and nothing about the"
            " library"
        )
        for claim in claims
    ]
    status_of = {_normalise_code(row["control_code"]): row["implementation_status"] for row in rows}
    for control in draft.controls_to_be_implemented:
        status = status_of.get(_normalise_code(control.control_code))
        extends = _EXTENDS.search(control.description)
        if status == ImplementationStatus.PARTIALLY_IMPLEMENTED and not extends:
            problems.append(
                f"{control.control_code} is partially implemented: describe what to extend and where, "
                "never a new deployment"
            )
        elif status == ImplementationStatus.NOT_IMPLEMENTED and extends:
            problems.append(
                f"{control.control_code} is on no affected system yet: describe implementing it, not extending it"
            )
    if _all_implemented([row for row in rows if _is_kept_after_ai_check(row)]):
        problems += [
            (
                f"{action.action_id} is an interim action, but every control is implemented: when covered, "
                "actions only verify, test or evidence the implemented controls"
            )
            for action in draft.remediation_action_plan
            if action.action.strip().casefold().startswith("interim")
        ]
    return problems


def _without_code_facts(text: str) -> str:
    sentences = _SENTENCE_END.split(text.strip())
    return " ".join(sentence for sentence in sentences if not _CODE_FACT.search(sentence))


def _build_final_plan(draft: PlanDraft, snapshot: Doc) -> tuple[Doc, list[str]]:
    plan = draft.model_dump(mode="json", exclude={"control_validation", "uncovered_risks"})
    if not plan["remediation_action_plan"]:
        message = "The AI's remediation plan has no action, so there is nothing to schedule or do."
        raise JobFailed(ErrorCode.INVALID_PLAN, message)
    plan["action_plan"] = _without_code_facts(plan["action_plan"])  # the schedule and the library are code's
    rows, warnings = _apply_ai_verdicts(snapshot, draft)
    validated = [row for row in rows if _is_kept_after_ai_check(row)]
    gaps = {_normalise_code(r["control_code"]): r for r in validated if r["implementation_status"] in _GAPS}
    controls, kept_warnings = _kept_controls(plan["controls_to_be_implemented"], rows, gaps)
    recommended = [control["control_code"] for control in controls]
    covered = _all_implemented(validated)
    named = validated if covered else [row for row in rows if row["control_code"] in recommended]
    every_system = snapshot["risk_scope"]["all_supporting_systems_applicable"] == 1
    plan |= {
        "title": _plan_title(named, covered, plan["title"], snapshot),
        "applicable_to_all_subsystems": YesNo.YES if every_system else YesNo.NO,  # the risk flag's, for v1
        "controls_to_be_implemented": {
            "control_coverage": ControlCoverage.COVERED if covered else ControlCoverage.GAPS,
            "controls": controls,
        },
        # Code's keys last, so nothing the AI wrote can stand in for the strategy or the register's facts.
        "treatment_strategy": Remediation.STRATEGY,
        **snapshot["register"],
        "control_assessment": [
            {key: row[key] for key in _ASSESSED} | {"recommended": row["control_code"] in recommended} for row in rows
        ],
        "unresolved_gaps": _unresolved_gaps(rows, validated, draft.uncovered_risks),
    }
    warnings += kept_warnings + [
        PlanWarning.GAP_NOT_ADDRESSED.format(code=row["control_code"], status=row["implementation_status"])
        for row in gaps.values()
        if row["control_code"] not in recommended
    ]
    actions, affected = plan["remediation_action_plan"], snapshot["risk_scope"]["affected_systems"]
    recommended_rows = [row for row in rows if row["control_code"] in recommended]
    warnings += _delivery_warnings(actions, recommended)  # first: it cuts the codes _action_systems reads
    warnings += _action_systems(actions, affected, recommended_rows)
    return plan, warnings


def _unresolved_gaps(rows: list[Doc], validated: list[Doc], uncovered: list[str]) -> list[Doc]:
    gaps: list[Doc] = [
        {
            "kind": GapKind.FLAGGED_CONTROL,
            "control_code": row["control_code"],
            "detail": PlanText.GAP_FLAGGED.format(code=row["control_code"], name=row["control_name"]),
        }
        for row in rows
        if row["validation"] == ControlValidation.FLAGGED_FOR_REVIEW
    ]
    if not validated:
        gaps.append({"kind": GapKind.NO_VALIDATED_CONTROL, "control_code": None, "detail": PlanText.GAP_NONE_VALIDATED})
    texts = dict.fromkeys(redact_and_shorten_text(_without_code_facts(text)) or "" for text in uncovered)
    return gaps + [{"kind": GapKind.UNCOVERED_RISK, "control_code": None, "detail": text} for text in texts if text]


def _plan_title(named: list[Doc], covered: bool, drafted: str, snapshot: Doc) -> str:
    domains = list(dict.fromkeys(row["domain"] for row in named if row.get("domain")))
    if not domains:
        return drafted or snapshot["scenario"]["title"] or snapshot["threat"]["name"] or ""
    joined = domains[0] if len(domains) == 1 else ", ".join(domains[:-1]) + " and " + domains[-1]
    return (PlanText.VERIFICATION_TITLE if covered else PlanText.REMEDIATION_TITLE).format(domains=joined)


def _kept_controls(drafted: list[Doc], rows: list[Doc], gaps: dict[str, Doc]) -> tuple[list[Doc], list[str]]:
    by_code = {_normalise_code(row["control_code"]): row for row in rows}
    kept: list[Doc] = []
    seen: set[int] = set()
    warnings: list[str] = []
    for control in drafted:
        key = _normalise_code(control["control_code"])
        row = by_code.get(key)
        if row is None:
            warnings.append(PlanWarning.CONTROL_NOT_IN_LIBRARY.format(code=control["control_code"]))
        elif row["implementation_status"] == ImplementationStatus.IMPLEMENTED:
            warnings.append(PlanWarning.CONTROL_IN_REGISTER.format(code=row["control_code"]))
        elif key not in gaps:
            warnings.append(
                PlanWarning.CONTROL_NOT_VALIDATED.format(code=row["control_code"], validation=row["validation"])
            )
        elif row["control_id"] in seen:
            warnings.append(PlanWarning.CONTROL_LISTED_TWICE.format(code=row["control_code"]))
        else:
            seen.add(row["control_id"])
            kept.append(control | {key: row[key] for key in _STAMPED})
    return kept, warnings


def _action_systems(actions: list[Doc], affected: list[Doc], recommended: list[Doc]) -> list[str]:
    by_name = {name_match_key(system["name"]): system for system in affected}
    needed = {row["control_code"]: row["required_systems"] for row in recommended}
    warnings: list[str] = []
    for position, action in enumerate(actions):
        named: set[int] = set()
        for given in action.get("supporting_systems") or []:
            system = by_name.get(name_match_key(str(given)))
            if system is None:
                label = _action_name_or_position(action, position)
                warnings.append(PlanWarning.ACTION_SYSTEM_UNKNOWN.format(action=label, system=given))
            else:
                named.add(system["supporting_system_id"])
        if not named:
            named = {s["supporting_system_id"] for code in action["implements_controls"] for s in needed.get(code, [])}
        action["supporting_systems"] = [s for s in affected if s["supporting_system_id"] in named] or list(affected)
    return warnings


def _delivery_warnings(actions: list[Doc], recommended: list[str]) -> list[str]:
    known = {_normalise_code(code): code for code in recommended}
    warnings: list[str] = []
    delivered: set[str] = set()
    for position, action in enumerate(actions):
        codes = []
        for echoed in (str(code).strip() for code in action["implements_controls"]):
            canonical = known.get(_normalise_code(echoed))
            if canonical is None:
                name = _action_name_or_position(action, position)
                warnings.append(PlanWarning.IMPLEMENTS_UNKNOWN.format(action=name, code=echoed))
            else:
                codes.append(canonical)
        action["implements_controls"] = codes
        delivered.update(codes)
    return warnings + [
        PlanWarning.CONTROL_NOT_IMPLEMENTED.format(code=code) for code in recommended if code not in delivered
    ]


def _action_name_or_position(action: Doc, position: int) -> str:
    return str(action.get("action_id") or "").strip() or f"remediation_action_plan[{position}]"


def schedule_plan(plan: Doc, snapshot: Doc) -> list[str]:
    """Writes dates, timelines and the critical path onto the plan and its actions; returns warnings."""
    window = (snapshot.get("risk_assessment") or {}).get("assessment_window")
    actions = plan["remediation_action_plan"]
    action_ids = [str(action.get("action_id") or "").strip() for action in actions]
    names = [_action_name_or_position(action, position) for position, action in enumerate(actions)]
    anchor = date.fromisoformat(window["timeline_start_date"]) if window else None
    limit = Remediation.MAX_ACTION_DAYS
    warnings: list[str] = []
    for action, name in zip(actions, names, strict=True):
        days = action["duration_days"]
        if days < 1:
            warnings.append(PlanWarning.DURATION_REPAIRED.format(action=name, value=days))
        elif days > limit:
            warnings.append(PlanWarning.DURATION_CAPPED.format(action=name, days=days, limit=limit))
        action["duration_days"] = min(max(days, 1), limit)
    prerequisites, dependency_warnings = _prerequisites(actions, names, action_ids)
    total, path = _date_actions(actions, prerequisites, anchor)
    critical_path = [names[position] for position in path]
    return warnings + dependency_warnings + _date_plan(plan, critical_path, total, anchor, window)


def _prerequisites(actions: list[Doc], names: list[str], action_ids: list[str]) -> tuple[list[list[int]], list[str]]:
    positions_of: list[list[int]] = []
    warnings: list[str] = []
    first_holder: dict[str, int] = {}
    for index, (action, name, own_id) in enumerate(zip(actions, names, action_ids, strict=True)):
        accepted: list[int] = []
        for reference in dict.fromkeys(str(entry).strip() for entry in action["depends_on"]):
            earlier = None if reference == own_id else first_holder.get(reference)
            if earlier is None:
                warnings.append(PlanWarning.DEPENDENCY_NOT_EARLIER.format(action=name, reference=reference))
            else:
                accepted.append(earlier)
        action["depends_on"] = [action_ids[position] for position in accepted]
        positions_of.append(accepted)
        if own_id and own_id in first_holder:
            position = first_holder[own_id]
            warnings.append(PlanWarning.ACTION_ID_REPEATED.format(action=name, action_id=own_id, position=position))
        elif own_id:
            first_holder[own_id] = index
    return positions_of, warnings


def _date_actions(actions: list[Doc], prerequisites: list[list[int]], anchor: date | None) -> tuple[int, list[int]]:
    finish: list[int] = []
    via: list[int | None] = []
    for action, positions in zip(actions, prerequisites, strict=True):
        start = max((finish[p] for p in positions), default=0)
        days, ids = action["duration_days"], action["depends_on"]
        finish.append(start + days)
        via.append(max(positions, key=lambda p: finish[p]) if positions else None)
        span = _spell_days(days)
        after = ""
        if ids:
            listed = ids[0] if len(ids) == 1 else ", ".join(ids[:-1]) + f" and {ids[-1]}"
            after = PlanText.AFTER.format(ids=listed) + ("s" if len(ids) == 1 else "")
        if anchor is None:
            action["start_date"] = action["end_date"] = None
            action["timeline"] = PlanText.UNDATED.format(span=span, after=after)
            continue
        first, last = (
            _add_days_within_calendar(anchor, start).isoformat(),
            _add_days_within_calendar(anchor, start + days - 1).isoformat(),
        )
        action["start_date"], action["end_date"] = first, last
        action["timeline"] = PlanText.DATED.format(start=first, end=last, span=span, after=after)
    path: list[int] = []
    node: int | None = finish.index(max(finish))
    while node is not None:
        path.append(node)
        node = via[node]
    return max(finish), path[::-1]


def _date_plan(plan: Doc, critical_path: list[str], total: int, anchor: date | None, window: Doc | None) -> list[str]:
    chain = " → ".join(critical_path)
    plan["critical_path"] = critical_path
    plan["mitigation_timeline_days"] = total
    if anchor is None or not window:
        plan["mitigation_end_date_planned"] = None
        plan["mitigation_timeline"] = PlanText.PLAN_UNDATED.format(total=_spell_days(total), chain=chain)
        return [PlanWarning.NO_WINDOW.format(total=total)]
    planned_end = _add_days_within_calendar(anchor, total - 1)
    end = planned_end.isoformat()
    plan["mitigation_end_date_planned"] = end
    plan["mitigation_timeline"] = PlanText.PLAN_DATED.format(
        start=anchor.isoformat(), end=end, total=_spell_days(total), chain=chain
    )
    warnings = []
    fit = (date.max - anchor).days + 1
    if total > fit:
        last, anchored = date.max.isoformat(), anchor.isoformat()
        warnings.append(PlanWarning.PAST_CALENDAR.format(total=total, anchor=anchored, fit=_spell_days(fit), last=last))
    if not window.get("timeline_end_date"):  # a start alone: dated, but no deadline to finish by
        return warnings
    deadline = date.fromisoformat(window["timeline_end_date"])
    if planned_end > deadline:
        late = _spell_days((planned_end - deadline).days)
        warnings.append(PlanWarning.PAST_WINDOW.format(end=end, days=late, deadline=deadline.isoformat()))
    return warnings


def _spell_days(days: int) -> str:
    return PlanText.DAYS.format(days=days) + ("s" if days != 1 else "")


def _add_days_within_calendar(anchor: date, offset: int) -> date:
    try:
        return anchor + timedelta(days=offset)
    except OverflowError:
        return date.max
