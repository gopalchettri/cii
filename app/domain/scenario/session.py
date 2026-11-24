"""A run's start checks, frozen context, plan progress, review rules, status board, cards and plan trace."""

import json
from collections import Counter
from collections.abc import Collection, Iterable
from datetime import date, datetime
from decimal import Decimal
from typing import Any, Final

from app.core import constants as c
from app.core.asset_types import place_asset_label
from app.core.config import get_settings
from app.core.exceptions import Conflict, Forbidden, Invalid, NotFound, SetupError
from app.domain.shared.names import name_match_key, threat_name_key
from app.domain.shared.prompt_redaction import DATABASE_KEYS, facts_safe_for_prompt
from app.schemas import scenarios as views
from app.schemas.intel import cited_evidence
from app.schemas.jobs import controls_retry_notice_of, retry_notice_of
from app.schemas.library import ThreatLibrary
from app.schemas.scenario_internal import AssetContextRows, FrozenContext, Row, control_view

ScenarioTargets = list[dict[str, Any]]
LibraryNameMatch = tuple[c.PromotionOutcome, int | None, int | None]


_RESERVED_FACT_NAMES: Final = (frozenset(c.ContextProperties.ALWAYS_USED) | DATABASE_KEYS) - set(
    c.ContextProperties.HEAD
)
_ALWAYS_REQUIRED_FACTS: Final = frozenset({"name"})  # every prompt, card and search names the asset and its systems


def build_run_context(request: views.StartRunRequest, rows: AssetContextRows) -> FrozenContext:
    """Checks the start request against the procedure's rows and freezes the asset's facts for the run."""
    for kind, found in (("asset", [rows.asset] if rows.asset else []), ("supporting system", rows.systems)):
        extra = set(found[0]) - set(c.ContextProperties.HEAD) if found else set()  # every row has its columns
        if reserved := sorted(extra & _RESERVED_FACT_NAMES):
            raise SetupError(c.PropertyMessage.RESERVED.format(columns=", ".join(reserved), rows=kind))
    option_key = "id" if rows.options and "value" not in rows.options[0] else "value"  # names by value or by id
    _check_asset_systems_service_and_sector(request, rows)
    assert rows.asset is not None
    options: dict[str, dict[int, str]] = {}  # {code in lower case (SQL compares them so): {number: name}}
    for option in rows.options:
        if (option["name"] or "").strip():  # a blank option name names nothing
            options.setdefault(str(option["code"]).strip().lower(), {})[option[option_key]] = option["name"]
    rows_by_id = {row["id"]: row for row in rows.systems}
    asset, asset_facts = _read_row_facts(rows.asset, options)
    systems = []
    for position, system_id in enumerate(request.supporting_system_ids, start=1):
        head, facts = _read_row_facts(rows_by_id[system_id], options)
        systems.append({"id": head["id"], "alias": f"{c.ThreatFinding.SYSTEM_ALIAS}{position}", **head, **facts})
    check_required_facts(request, {"name": asset["name"], **asset_facts}, systems)
    linked = _list_linked_systems(request.supporting_system_ids, rows_by_id)
    return FrozenContext(asset, asset_facts, systems, linked)


def _list_linked_systems(asked: list[int], rows_by_id: dict[int, Row]) -> list[dict[str, Any]]:
    linked: list[dict[str, Any]] = []
    seen: set[str] = set()
    for system_id in [*asked, *sorted(set(rows_by_id) - set(asked))]:
        name = _collapse_spaces(rows_by_id[system_id]["name"] or "")
        name = name or c.ContextProperties.UNNAMED_SYSTEM.format(id=system_id)
        unique = f"{name} ({system_id})" if name_match_key(name) in seen else name
        linked.append({"id": system_id, "name": unique, "category_code": rows_by_id[system_id]["category_code"]})
        seen.add(name_match_key(name))
    return linked


def _check_asset_systems_service_and_sector(request: views.StartRunRequest, rows: AssetContextRows) -> None:
    if rows.asset is None:
        message = c.SessionMessage.ASSET_NOT_OWNED.format(asset_id=request.asset_id)
        raise Forbidden(message, reason=c.ConflictReason.ASSET_NOT_OWNED)
    linked = {row["id"] for row in rows.systems}
    if unlinked := [system_id for system_id in request.supporting_system_ids if system_id not in linked]:
        message = c.SessionMessage.SYSTEMS_NOT_LINKED.format(system_ids=unlinked, asset_id=request.asset_id)
        raise Forbidden(message, reason=c.ConflictReason.SYSTEM_NOT_LINKED, details={"system_ids": unlinked})
    if request.service_id is not None and not any(row["id"] == request.service_id for row in rows.services):
        raise NotFound(c.SessionMessage.SERVICE_NOT_FOUND.format(service_id=request.service_id))
    asked_sector = request.subsector_id or request.sector_id
    if asked_sector is not None and rows.sector is None:
        raise NotFound(c.SessionMessage.SECTOR_NOT_FOUND.format(sector_id=asked_sector))
    sector = rows.sector
    if sector is not None and request.subsector_id is not None and request.sector_id is not None:
        top_id = sector["parent_id"] if sector["parent_id"] is not None else sector["id"]
        if top_id != request.sector_id:
            message = c.SessionMessage.SECTOR_NOT_PARENT.format(
                sector_id=request.sector_id, subsector_id=request.subsector_id, parent_id=top_id
            )
            field = f"{request.FIELD_PREFIX}.sector_id"
            raise Invalid(message, errors=[{"field": field, "message": message}])


def _collapse_spaces(value: Any) -> Any:
    return " ".join(value.split()) if isinstance(value, str) else value


def _translate_option_codes_to_names(
    column: str, raw: Any, options: dict[str, dict[int, str]]
) -> str | list[str] | None:
    if column in c.ContextProperties.SINGLE_SELECT_CODES_WITH_PRIORITY:
        code = c.ContextProperties.SINGLE_SELECT_CODES_WITH_PRIORITY[column]
        if isinstance(raw, str):
            try:
                raw = int(raw)
            except ValueError:  # a name the procedure already gave
                return _collapse_spaces(raw) or None
        if not raw:  # NULL or the form's 0: unanswered
            return None
        return options.get(code, {}).get(raw)
    code, text = c.ContextProperties.MULTI_SELECT_CODES[column], (raw or "").strip()
    try:
        items = json.loads(text) if text else []
    except ValueError:  # not an array: the names the procedure already joined
        if text.startswith("["):
            return None
        return [name for name in (part.strip() for part in text.split(",")) if name] or None
    known: dict[Any, str] = options.get(code, {})  # a NULL saved number is a key too
    names = []
    for item in items if isinstance(items, list) else []:
        try:
            number: int | None = int(str(item))
        except ValueError:
            number = None
        if number in known:
            names.append(known[number])
    return names or None


def _read_row_facts(row: Row, options: dict[str, dict[int, str]]) -> tuple[dict[str, Any], dict[str, Any]]:
    facts: dict[str, Any] = {}
    for column, value in row.items():
        if column in c.ContextProperties.HEAD:
            continue
        if column in c.ContextProperties.SINGLE_SELECT_CODES_WITH_PRIORITY or (
            column in c.ContextProperties.MULTI_SELECT_CODES
        ):
            facts[column] = _translate_option_codes_to_names(column, value, options)
        elif column in c.ContextProperties.NAME_FACTS:
            facts[column] = _collapse_spaces(value)
        elif value is None or isinstance(value, bool | int | float | str):
            facts[column] = value
        elif isinstance(value, Decimal):
            facts[column] = float(value)
        elif isinstance(value, date):  # a datetime too; SQL Server's minimum date means "never"
            facts[column] = None if value.year <= c.ContextProperties.NEVER_TESTED_YEAR else value.isoformat()
        elif isinstance(value, bytes | bytearray | memoryview):
            facts[column] = None
        else:
            facts[column] = str(value)
    head = {"id": row["id"], "name": _collapse_spaces(row["name"]), "category_code": row["category_code"]}
    return head, facts


def check_required_facts(
    request: views.StartRunRequest, asset_facts: dict[str, Any], systems: list[dict[str, Any]]
) -> None:
    """Raises 500 when a required fact is no procedure column, else 422 naming each one not recorded."""
    settings = get_settings()
    asset_required = settings.required_asset_properties | _ALWAYS_REQUIRED_FACTS
    system_required = settings.required_system_properties | _ALWAYS_REQUIRED_FACTS
    for setting, required, facts in (
        (c.ContextProperties.ASSET_REQUIRED_SETTING, asset_required, asset_facts),
        *((c.ContextProperties.SYSTEM_REQUIRED_SETTING, system_required, system) for system in systems[:1]),
    ):  # every system row has the procedure's same columns
        if absent := sorted(required - facts.keys()):
            raise SetupError(c.PropertyMessage.NOT_RETURNED.format(setting=setting, names=", ".join(absent)))
    by_field: dict[str, list[str]] = {}  # sector & co come from the request's own fields
    for name in asset_facts:
        if name in asset_required and not facts_safe_for_prompt({"fact": asset_facts[name]}):
            field = c.ContextProperties.REQUEST_FIELDS.get(name, "asset_id")
            by_field.setdefault(f"{request.FIELD_PREFIX}.{field}", []).append(name)
    gaps = [(field, f"asset {request.asset_id}", names) for field, names in by_field.items()]
    for index, system in enumerate(systems):
        unrecorded = [name for name in system if name in system_required]
        if names := [name for name in unrecorded if not facts_safe_for_prompt({"fact": system[name]})]:
            gaps.append((f"{request.FIELD_PREFIX}.supporting_system_id.{index}", f"system {system['id']}", names))
    if not gaps:
        return
    errors = [
        {"field": field, "message": c.PropertyMessage.NOT_RECORDED.format(owner=owner, names=", ".join(names))}
        for field, owner, names in gaps
    ]
    detail = c.PropertyMessage.REQUIRED_MISSING.format(
        gaps="; ".join(f"{owner}: {', '.join(names)}" for _, owner, names in gaps)
    )
    raise Invalid(detail, reason=c.ConflictReason.REQUIRED_FACTS_MISSING, errors=errors)


def find_library_threat_by_name(library: ThreatLibrary, name: str) -> LibraryNameMatch | None:
    """Finds a live, pending or curator-rejected library threat with this name; None for a new name."""
    key = threat_name_key(name)
    for threat in library.threats:
        if threat_name_key(threat.name) == key:
            return c.PromotionOutcome.EXISTING, threat.type_id, threat.catalogue_id
    for row in library.pending:
        if row.kind == c.LibraryRowKind.THREAT and threat_name_key(row.name) == key:
            return c.PromotionOutcome.EXISTING, row.type_id, row.row_id
    if any(threat_name_key(row.name) == key for row in library.curator_rejected):
        return c.PromotionOutcome.CURATOR_REJECTED, None, None
    return None


def list_active_or_pending_threat_ids(library: ThreatLibrary) -> frozenset[int]:
    """Lists the ids of every threat the library still holds: live or waiting for a curator."""
    pending = (row.row_id for row in library.pending if row.kind == c.LibraryRowKind.THREAT)
    return frozenset(
        (*(threat.catalogue_id for threat in library.threats), *library.threats_without_category, *pending)
    )


def is_still_to_write(path: dict[str, Any], reopen: bool = False) -> bool:
    """Not written yet, and not given up unless `reopen`."""
    return not path["served"] and (reopen or not path["abandoned"])


def pick_next_paths_to_write(
    paths: Iterable[dict[str, Any]], size: int | None = None
) -> tuple[list[str], list[dict[str, Any]]]:
    """Picks the next `size` open paths, best rank first, and the first batch of them to write."""
    open_paths = sorted(
        (path for path in paths if path["selected"] and is_still_to_write(path)), key=lambda path: path["rank"]
    )[:size]
    batch = sorted(open_paths, key=lambda path: (path["attempts"] > 0, path["rank"]))[: c.Generation.WRITER_BATCH]
    return [path["path_id"] for path in open_paths], [{"path_id": path["path_id"], "replaces": None} for path in batch]


def count_plan_paths(paths: Iterable[dict[str, Any]]) -> dict[str, int]:
    """Counts the plan's paths: planned, still to write, given up, outage cards to regenerate."""
    paths = list(paths)
    selected = [path for path in paths if path["selected"]]
    return {
        "planned": len(selected),
        "remaining": sum(is_still_to_write(path) for path in selected),
        "abandoned": sum(bool(path["abandoned"]) for path in selected),
        # ponytail: a path given up before its give-up named the AI outage reads "unavailable" and is not
        "outage_cards": sum(
            bool(path["abandoned"]) and not path["served"] and path.get("abandoned_reason") in c.AiOutage
            for path in paths
        ),
    }


def find_why_no_path_left(paths: Iterable[dict[str, Any]]) -> c.ConflictReason:
    """Finds why no path is left: some given up, some left out by the scenario count, or all written."""
    paths = list(paths)
    if any(path["selected"] and path["abandoned"] for path in paths):
        return c.ConflictReason.SCENARIOS_ABANDONED
    not_by_count = (c.UnselectedReason.REPLACED_AFTER_FAILURE, c.UnselectedReason.NO_FURTHER_RISK)
    if any(not path["selected"] and path.get("unselected_reason") not in not_by_count for path in paths):
        return c.ConflictReason.TARGET_REACHED
    return c.ConflictReason.NOTHING_LEFT


def summarise_finished_set(in_set: list[dict[str, Any]], paths: list[dict[str, Any]], outcome: str) -> dict[str, Any]:
    """Summarises a finished next set: its outcome, paths written, why it stopped, and what is left."""
    remaining = sum(path["selected"] and is_still_to_write(path) for path in paths)
    reason: c.ConflictReason | None = None
    if any(path["selected"] and path["abandoned"] for path in in_set):
        reason = c.ConflictReason.SCENARIOS_ABANDONED
    elif not remaining:
        reason = find_why_no_path_left(paths)
    delivered = sum(bool(path["served"]) for path in in_set if path["selected"])
    return {"outcome": outcome, "delivered": delivered, "reason": reason, "remaining": remaining}


def pick_replacement_path(
    paths: Iterable[dict[str, Any]], threats: dict[str, dict[str, Any]], in_set: Collection[str]
) -> dict[str, Any] | None:
    """Picks the best path to write in a failed path's place within the set's call budget; else None."""
    paths = list(paths)
    set_paths = [path for path in paths if path["path_id"] in in_set]
    own = sum(not path.get("replaces") for path in set_paths)
    spent = sum(path["attempts"] + (1 if path["served"] else 0) for path in set_paths)
    if spent >= own * c.Generation.MAX_PATH_ATTEMPTS:
        return None
    writable = []
    for path in paths:
        threat = (threats.get(path["steps"][0]) or {}) if path["steps"] else {}
        if threat.get("attacker_check") != c.AttackerCheck.NONE_FITS:
            writable.append(path)
    left_out = [
        path
        for path in writable
        if not path["selected"] and path.get("unselected_reason") == c.UnselectedReason.TARGET_REACHED
    ]
    later = [
        path for path in writable if path["selected"] and is_still_to_write(path) and path["path_id"] not in in_set
    ]
    return min(left_out or later, key=lambda path: path["rank"], default=None)


def get_session_owned_by_caller(record: dict[str, Any] | None, session_id: str, entity_id: int) -> dict[str, Any]:
    """Returns the caller's scenario session: 404 when there is none, 403 when another entity's."""
    if record is None:
        raise NotFound(c.SessionMessage.NOT_FOUND.format(session_id=session_id))
    if record["entity_id"] != entity_id:
        raise Forbidden(c.SessionMessage.OTHER_ENTITY.format(session_id=session_id))
    return record


def check_session_ready_for_review(run: views.SessionStatus) -> None:
    """Raises 409 while the run generates, or when it failed or was cancelled finding threats."""
    if run.status in (c.Status.QUEUED, c.Status.RUNNING):
        message = c.ReviewMessage.GENERATION_IN_PROGRESS.format(session_id=run.session_id)
        raise Conflict(message, reason=c.ConflictReason.GENERATION_IN_PROGRESS)
    if run.status == c.Status.FAILED and run.step == c.Step.THREATS:
        message = c.ReviewMessage.RUN_FAILED.format(session_id=run.session_id)
        raise Conflict(message, reason=c.ConflictReason.RUN_FAILED)
    if run.status == c.Status.CANCELLED and run.step == c.Step.THREATS:
        message = c.ReviewMessage.RUN_CANCELLED.format(session_id=run.session_id)
        raise Conflict(message, reason=c.ConflictReason.RUN_CANCELLED)


def get_scenarios_to_decide(
    scenario_ids: list[str], targets: dict[str, dict[str, Any]], decision: c.Decision, held_threat_ids: Collection[int]
) -> ScenarioTargets:
    """Returns the scenarios to accept or reject, in the order sent; 409 naming every id at fault."""
    versions_per_path = Counter(target["path_id"] for target in targets.values())
    accepting = decision == c.Decision.ACCEPTED
    errors = []
    for scenario_id in scenario_ids:
        target = targets.get(scenario_id)
        reason: c.TargetProblem | None = None
        if target is None:
            reason = c.TargetProblem.UNKNOWN
        elif target["status"] != c.ScenarioStatus.DONE:
            reason = c.TargetProblem.FAILURE_SCENARIO
        elif target["decision"] == decision:
            pass
        elif target["decision"] != c.Decision.PENDING:
            reason = c.TargetProblem.ALREADY_REJECTED if accepting else c.TargetProblem.ALREADY_ACCEPTED
        elif accepting and versions_per_path[target["path_id"]] > 1:
            reason = c.TargetProblem.DUPLICATE_VERSION
        elif accepting and not _is_threat_still_in_library(target, held_threat_ids):
            reason = c.TargetProblem.LIBRARY_INACTIVE
        if reason is not None:
            errors.append({"scenario_id": scenario_id, "reason": reason})
    if errors:
        message = c.ReviewMessage.NOT_DECIDABLE.format(decision=decision)
        raise Conflict(message, reason=c.ConflictReason.SCENARIOS_NOT_DECIDABLE, errors=errors)
    return [targets[scenario_id] for scenario_id in scenario_ids]


def _is_threat_still_in_library(target: dict[str, Any], held_threat_ids: Collection[int]) -> bool:
    threat = (target.get("content") or {}).get("threat") or {}
    library_id = threat.get("library_id")
    return bool(threat.get("ai_generated")) or library_id is None or library_id in held_threat_ids


def pick_scenarios_for_accept_all(
    rows: ScenarioTargets, accepted: dict[str, str], held_threat_ids: Collection[int]
) -> tuple[ScenarioTargets, list[views.TargetSkipped]]:
    """Picks accept-all's scenarios and the ones it skips (another version accepted, retired threat)."""
    taken = dict(accepted)
    targets, skipped = [], []
    for row in rows:
        if row["decision"] == c.Decision.ACCEPTED:  # listed again, whatever has changed since
            targets.append(row)
        elif taken.setdefault(row["path_id"], row["_id"]) != row["_id"]:
            skipped.append(views.TargetSkipped(scenario_id=row["_id"], reason=c.TargetProblem.DUPLICATE_VERSION))
        elif not _is_threat_still_in_library(row, held_threat_ids):
            skipped.append(views.TargetSkipped(scenario_id=row["_id"], reason=c.TargetProblem.LIBRARY_INACTIVE))
        else:
            targets.append(row)
    return targets, skipped


def find_versions_to_replace(targets: ScenarioTargets, accepted: dict[str, str], replace: bool) -> list[str]:
    """Finds the other accepted versions of the targets' paths to reset; 409 when replace is off."""
    wanted = {target["path_id"]: target["_id"] for target in targets}
    others = {path_id: sid for path_id, sid in accepted.items() if sid != wanted[path_id]}
    if others and not replace:
        errors = [{"scenario_id": wanted[path_id], "reason": c.TargetProblem.DUPLICATE_VERSION} for path_id in others]
        message = c.ReviewMessage.ANOTHER_VERSION_ACCEPTED
        raise Conflict(message, reason=c.ConflictReason.DUPLICATE_VERSION, errors=errors)
    return list(others.values())


def read_decision_results(
    ids: list[str], pending: list[str], now: dict[str, dict[str, Any]], decision: c.Decision, decision_id: str
) -> tuple[list[str], list[str], list[views.TargetSkipped]]:
    """Reads, after a partial update, the ids holding the decision, newly given it, and lost to a race."""
    holding = [scenario_id for scenario_id in ids if now.get(scenario_id, {}).get("decision") == decision]
    mine = {scenario_id for scenario_id, row in now.items() if row.get("decision_id") == decision_id}
    newly = [scenario_id for scenario_id in pending if scenario_id in mine]
    raced = [
        views.TargetSkipped(scenario_id=scenario_id, reason=c.TargetProblem.CHANGED_CONCURRENTLY)
        for scenario_id in ids
        if scenario_id not in holding
    ]
    return holding, newly, raced


def build_regenerate_batch(scenario_ids: list[str], targets: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Builds the write batch that regenerates the chosen scenarios; 409 naming each one that cannot be."""
    versions_per_path = Counter(target["path_id"] for target in targets.values())
    outage_cards = {
        scenario_id
        for scenario_id, target in targets.items()
        if target["status"] == c.ScenarioStatus.FAILED and (target.get("failure") or {}).get("reason") in c.AiOutage
    }
    errors = []
    for scenario_id in scenario_ids:
        target = targets.get(scenario_id)
        reason: c.TargetProblem | None = None
        if target is None:
            reason = c.TargetProblem.UNKNOWN
        elif target["status"] != c.ScenarioStatus.DONE and scenario_id not in outage_cards:
            reason = c.TargetProblem.FAILURE_SCENARIO
        elif target.get("source") == c.RunKind.MANUAL:
            reason = c.TargetProblem.HAND_WRITTEN
        elif target.get("superseded_by"):
            reason = c.TargetProblem.VERSION_NOT_CURRENT
        elif versions_per_path[target["path_id"]] > 1:
            reason = c.TargetProblem.DUPLICATE_VERSION
        if reason is not None:
            errors.append({"scenario_id": scenario_id, "reason": reason})
    if errors:
        message = c.ReviewMessage.NOT_REGENERABLE
        raise Conflict(message, reason=c.ConflictReason.SCENARIOS_NOT_REGENERABLE, errors=errors)
    return [
        {"path_id": targets[sid]["path_id"], "replaces": None if sid in outage_cards else sid} for sid in scenario_ids
    ]


_SESSION_STATE: Final = {
    c.Status.QUEUED: c.SessionState.ACTIVE,
    c.Status.RUNNING: c.SessionState.ACTIVE,
    c.Status.DONE: c.SessionState.COMPLETED,
    c.Status.FAILED: c.SessionState.FAILED,
    c.Status.CANCELLED: c.SessionState.CANCELLED,
}
_STAGE_STATE: Final = {
    c.Status.QUEUED: c.StageState.RUNNING,
    c.Status.RUNNING: c.StageState.RUNNING,
    c.Status.DONE: c.StageState.COMPLETE,
    c.Status.FAILED: c.StageState.ERROR,
    c.Status.CANCELLED: c.StageState.CANCELLED,
}


def build_status_board(run: views.SessionStatus) -> views.RunBoard:
    """Returns the status body every caller sees: each stage, what to do now, times, errors and counts."""
    if run.step != c.Step.THREATS:  # scenarios, or controls (read while a done run maps them)
        threats, scenarios = c.StageState.COMPLETE, _STAGE_STATE[run.status]
    elif run.status == c.Status.QUEUED and run.attempts == 0:  # threats are PENDING before their first try only
        threats, scenarios = c.StageState.PENDING, c.StageState.PENDING
    else:
        threats, scenarios = _STAGE_STATE[run.status], c.StageState.PENDING
    controls, overall = _read_controls_and_next_step(run, threats, scenarios)
    messages, outage, error = _collect_stage_errors(run, controls)
    timings = {
        stage: round(run.timings[f"{stage}_s"], 1)
        if state == c.StageState.COMPLETE and f"{stage}_s" in run.timings
        else None
        for stage, state in (("threats", threats), ("scenarios", scenarios), ("controls", controls))
    }
    progress = views.Progress(
        threats=threats,
        scenarios=scenarios,
        controls=controls,
        overall=overall,
        timings=views.StageTimings(**timings),
        error_message=messages,
        error_reason=outage,
        retrying=retry_notice_of(run.status, run.retry, run.step)
        or controls_retry_notice_of(run.counts, run.controls_retry),
        last_next_set=_summarise_last_action(run, c.RunActionKind.NEXT_SET, run.last_next_set),
        last_regen=_summarise_last_action(run, c.RunActionKind.REGENERATE, run.last_regen),
        scenario_count=_count_scenarios(run, threats),
    )
    header = run.model_dump(include={"session_id", "entity_id", "asset_id", "asset_name", "user_id", "updated_at"})
    return views.RunBoard(**header, session_status=_SESSION_STATE[run.status], progress=progress, error=error)


def _read_controls_and_next_step(
    run: views.SessionStatus, threats: c.StageState, scenarios: c.StageState
) -> tuple[c.StageState, c.RunOverall]:
    counts, session = run.counts, _SESSION_STATE[run.status]
    if counts.get("controls_waiting", 0):
        controls = c.StageState.RUNNING
    elif not counts.get("written", 0):
        controls = c.StageState.COMPLETE if scenarios == c.StageState.COMPLETE else c.StageState.PENDING
    elif scenarios == c.StageState.RUNNING:
        controls = c.StageState.RUNNING
    elif counts.get("controls_failed", 0):
        controls = c.StageState.ERROR
    else:
        controls = c.StageState.CANCELLED if counts.get("controls_cancelled", 0) else c.StageState.COMPLETE
    if session == c.SessionState.FAILED:
        overall = c.RunOverall.IN_PROGRESS if controls == c.StageState.RUNNING else c.RunOverall.ERROR
    elif session == c.SessionState.CANCELLED:
        overall = c.RunOverall.CANCELLED
    elif threats == c.StageState.PENDING:
        overall = c.RunOverall.PENDING
    elif session == c.SessionState.ACTIVE:
        overall = c.RunOverall.IN_PROGRESS
    elif counts.get("pending", 0):
        overall = c.RunOverall.AWAITING_REVIEW
    elif counts.get("remaining", 0):
        overall = c.RunOverall.AWAITING_NEXT_SET
    elif counts.get("outage_cards", 0):  # a regenerate can still write them
        overall = c.RunOverall.AWAITING_REVIEW
    elif controls == c.StageState.RUNNING:
        overall = c.RunOverall.IN_PROGRESS
    else:  # from the count, not the stage: a cancel leaves controls failed for good as they are
        overall = c.RunOverall.CANCELLED if counts.get("controls_cancelled", 0) else c.RunOverall.COMPLETE
    return controls, overall


def _collect_stage_errors(
    run: views.SessionStatus, controls: c.StageState
) -> tuple[dict[str, str], c.AiOutage | None, views.RunError | None]:
    messages: dict[str, str] = {}
    if run.status == c.Status.FAILED and run.error:
        messages[str(run.step)] = run.error.get("message") or run.error.get("code") or ""
    if abandoned := run.counts.get("abandoned", 0):
        messages.setdefault(str(c.Step.SCENARIOS), c.BoardMessage.ABANDONED.format(abandoned=abandoned))
    if not_judged := run.counts.get("not_judged", 0):
        messages.setdefault(str(c.Step.THREATS), c.BoardMessage.NOT_JUDGED.format(not_judged=not_judged))
    if controls == c.StageState.ERROR:
        manual = run.kind == c.RunKind.MANUAL  # only its plan job maps it, never the background
        unmatched = c.BoardMessage.CONTROLS_FAILED_MANUAL if manual else c.BoardMessage.CONTROLS_FAILED
        messages[str(c.Step.CONTROLS)] = unmatched.format(failed=run.counts["controls_failed"])
    if run.cancelled:  # who cancelled the run and when, to the second, in UTC
        at = run.cancelled.get("at")
        when = at.strftime("%Y-%m-%d %H:%M:%S") if isinstance(at, datetime) else str(at)
        stage = str(run.step) if run.status == c.Status.CANCELLED else str(c.Step.CONTROLS)
        messages.setdefault(stage, c.BoardMessage.CANCELLED.format(user=run.cancelled.get("user_id"), at=when))
    if controls == c.StageState.CANCELLED:
        cancelled = c.BoardMessage.CONTROLS_CANCELLED.format(cancelled=run.counts["controls_cancelled"])
        messages.setdefault(str(c.Step.CONTROLS), cancelled)
    stored = (run.error or {}).get("reason") if run.status == c.Status.FAILED else None
    outage = c.AiOutage(stored) if stored and stored in c.AiOutage else None
    if run.status != c.Status.FAILED or not run.error:
        return messages, outage, None
    given_up = c.AbandonReason(stored) if stored and stored in c.AbandonReason else None
    error = views.RunError(
        code=run.error.get("code", ""), message=run.error.get("message", ""), reason=outage or given_up
    )
    return messages, outage, error


def _count_scenarios(run: views.SessionStatus, threats: c.StageState) -> views.ScenarioCount:
    counts = run.counts
    served = counts.get("written", 0)
    total: int | None = None
    if threats == c.StageState.COMPLETE:
        total = served if run.kind == c.RunKind.MANUAL else counts.get("planned", 0)
    remaining = None if total is None else counts.get("remaining", 0)
    return views.ScenarioCount(
        total=total,
        served=served,
        remaining=remaining,
        complete=remaining == 0 and not counts.get("outage_cards", 0),
        pending_review=counts.get("pending", 0),
        accepted=counts.get("accepted", 0),
        rejected=counts.get("rejected", 0),
    )


def _summarise_last_action(
    run: views.SessionStatus, kind: c.RunActionKind, summary: dict[str, Any] | None
) -> dict[str, Any] | None:
    action = run.last_action or {}
    if summary is None:
        return None
    if action.get("kind") == kind:
        return summary | {"outcome": action.get("outcome")}
    if summary.get("outcome") == c.RunActionOutcome.RUNNING:
        return summary | {"outcome": c.RunActionOutcome.FAILED}
    return summary


def scenario_asset_type(content: dict[str, Any], context: FrozenContext | None) -> str | None:
    """IT or OT for a scenario's threat in the library (owner 2026-11-24: the scenario's own). A MITRE scenario is OT
    when one of its techniques is ICS (a path that attacks OT carries one), else IT; any other is the type of the
    place it attacks: its systems, or the asset when it names none (None without the run's asset facts)."""
    techniques = (content.get("mitre") or {}).get("attack_techniques")
    if techniques:
        attacks_ot = any(technique.get("domain") == "ics" for technique in techniques)
        return c.AssetType.OT.value if attacks_ot else c.AssetType.IT.value
    if context is None:
        return None
    systems = context.find_systems(system["id"] for system in content.get("systems") or [])
    return place_asset_label(context.asset.get("category_code"), (system.get("category_code") for system in systems))


def build_scenario_view(
    record: dict[str, Any], accepted_elsewhere: str | None = None, older: list[dict[str, Any]] | None = None
) -> views.ScenarioView:
    """Builds a stored scenario's API view in the v1 format, with its accepted and replaced versions."""
    content, controls = record.get("content") or {}, record.get("controls") or {}
    generated = record.get("source") != c.RunKind.MANUAL
    failed = record.get("status") == c.ScenarioStatus.FAILED
    controls_fields = _build_controls_fields(controls, generated, failed)
    match_status, mitre = controls_fields["control_match_status"], content.get("mitre") or {}
    return views.ScenarioView(
        scenario_id=record["_id"],
        scenario=None if failed else _build_scenario_text(content),
        threat=_build_threat_block(content),
        actors=views.actor_views(content),
        attack_techniques=mitre.get("attack_techniques") or [],
        procedures=mitre.get("procedures") or [],
        mitigations=mitre.get("mitigations") or [],
        controls=[control_view(item) for item in controls.get("items") or []],
        replaces_accepted_version=accepted_elsewhere,
        scenario_source=record["source"],
        replaced_scenarios=[build_scenario_view(version) for version in older or []],
        session_id=record["session_id"],
        version=record["version"],
        status=record["status"],
        failure=record.get("failure"),
        regenerate_error=record.get("regenerate_error"),
        created_at=record["created_at"],
        replaced_by=record.get("superseded_by"),
        evidence_mode=content.get("evidence_mode"),
        evidence=cited_evidence(content),
        evidence_search=content.get("intel_search"),
        **controls_fields,
        **_build_review_fields(record, content, controls, match_status, generated),
        **_build_generation_and_library_fields(record, content, generated, failed),
    )


def _build_controls_fields(controls: dict[str, Any], generated: bool, failed: bool) -> dict[str, Any]:
    status, attempts = controls.get("status"), controls.get("attempts")
    attempts_left = isinstance(attempts, int) and attempts < c.Controls.MAX_ATTEMPTS
    exhausted = status == c.Status.FAILED and not attempts_left
    matches = [item.get("match") for item in controls.get("items") or []]
    if not generated or failed or status == c.Status.FAILED:
        match_status: c.ControlMatchStatus | None = None
    elif status != c.Status.DONE:
        match_status = c.ControlMatchStatus.PENDING
    elif not matches:
        match_status = c.ControlMatchStatus.CONTROL_LIBRARY_GAP
    elif c.ControlMatch.EXACT in matches:
        match_status = c.ControlMatchStatus.EXACT
    else:
        match_status = c.ControlMatchStatus.NEAREST_ONLY
    return {
        "controls_status": status,
        "controls_error": controls.get("error") if status in (c.Status.QUEUED, c.Status.FAILED) else None,
        "controls_unavailable": False,
        "controls_mapped": status == c.Status.DONE,
        "controls_mapping_exhausted": exhausted,
        "controls_mapping_exhaustion_reason": c.CONTROLS_EXHAUSTED if exhausted else None,
        "control_match_status": match_status,
    }


def _build_review_fields(
    record: dict[str, Any],
    content: dict[str, Any],
    controls: dict[str, Any],
    match_status: c.ControlMatchStatus | None,
    generated: bool,
) -> dict[str, Any]:
    findings, failure = record.get("findings") or [], record.get("failure")
    warnings = [str(item.get("message")) for item in findings if item.get("severity") == c.FindingSeverity.WARNING]
    notes = [str(item.get("message")) for item in findings if item.get("severity") == c.FindingSeverity.NOTE]
    if record["status"] == c.ScenarioStatus.FAILED:
        status, errors = c.ValidationStatus.WARNING, [str(failure["message"])] if failure else []
    else:
        status, errors = (c.ValidationStatus.WARNING if warnings else c.ValidationStatus.OK), warnings
    threat = content.get("threat") or {}
    shown = [
        (c.ReviewFlag.AI_PROPOSED_TYPE, bool(threat) and threat.get("type_id") is None),
        (c.ReviewFlag.AI_PROPOSED_THREAT, bool(threat) and threat.get("library_id") is None),
        (c.ReviewFlag.ASSUMED_ROUTE, (content.get("route") or {}).get("status") == c.Route.UNKNOWN),
        (c.ReviewFlag.VALIDATION_EXCEPTION, status == c.ValidationStatus.WARNING),
        (c.ReviewFlag.PLAN_CHECK, bool(notes)),
        (
            c.ReviewFlag.NEAREST_CONTROL,
            any(item.get("match") == c.ControlMatch.NEAREST for item in controls.get("items") or []),
        ),
        (c.ReviewFlag.CONTROL_LIBRARY_GAP, match_status == c.ControlMatchStatus.CONTROL_LIBRARY_GAP),
    ]
    flags = [flag for flag, is_shown in shown if is_shown and (generated or flag == c.ReviewFlag.PLAN_CHECK)]
    return {"validation_status": status, "validation_errors": errors, "validation_notes": notes, "review_flags": flags}


def _build_generation_and_library_fields(
    record: dict[str, Any], content: dict[str, Any], generated: bool, failed: bool
) -> dict[str, Any]:
    generation = record.get("generation") or {}
    started, finished = generation.get("started_at"), generation.get("finished_at")
    seconds = round((finished - started).total_seconds(), 2) if started and finished else None
    decision, by, at = record.get("decision"), record.get("decided_by"), record.get("decided_at")
    accepted, rejected = decision == c.Decision.ACCEPTED, decision == c.Decision.REJECTED
    threat = content.get("threat") or {}
    acting = next((actor for actor in content.get("actors") or [] if actor.get("role") == "acting"), None)
    unsupported = acting is not None and failed and acting.get("selection") == c.AttackerCheck.NONE_FITS
    sources = {
        field: (c.ThreatSource.LIBRARY if threat.get(key) is not None else c.ThreatSource.AI_PROPOSED)
        if generated and threat
        else None
        for field, key in (("threat_source", "library_id"), ("threat_type_source", "type_id"))
    }
    return {
        "generation_epoch": generation.get("epoch"),
        "gen_started_at": started,
        "gen_finished_at": finished,
        "gen_seconds": seconds if seconds is None or seconds >= 0 else None,
        "accepted": accepted,
        "accepted_by": by if accepted else None,
        "accepted_at": at if accepted else None,
        "rejected_by": by if rejected else None,
        "rejected_at": at if rejected else None,
        "scenario_number": record["version"],
        "library": None if generated else _build_library_view(threat),
        "scope": _build_scope_view(content) if generated else None,
        "actor": None if acting is None or unsupported else acting.get("name"),
        **sources,
    }


def _build_scope_view(content: dict[str, Any]) -> views.ScopeView:
    ids = sorted(system["id"] for system in content.get("systems") or [])
    kind = c.ScopeType.ASSET if not ids else c.ScopeType.SYSTEM if len(ids) == 1 else c.ScopeType.COMBINATION
    return views.ScopeView(
        scope_key="+".join([c.SCOPE_ASSET_KEY, *map(str, ids)]), scope_type=kind, supporting_system_ids=ids, evidence=[]
    )


def _build_scenario_text(content: dict[str, Any]) -> views.ScenarioText:
    threat, status = content.get("threat") or {}, (content.get("route") or {}).get("status")
    applicability = content.get("system_applicability")
    systems = []
    for system in applicability or content.get("systems") or []:
        reason = system.get("reason") or ""
        judged: dict[str, Any] = {"justification": reason, "is_applicable": bool(system.get("applicable"))}
        involved = views.SystemInvolved(
            supporting_system_id=system["id"],
            supporting_system=system["name"],
            is_entry_point=bool(system.get("entry_point")),
            **(judged if applicability else {}),
        )
        systems.append(involved)
    note = c.Writing.PLATFORM_NOTE.removeprefix(" - ").casefold()  # one already carrying it is shown as stored
    assumptions = [
        text if note in text.casefold() else text.rstrip(". ") + c.Writing.PLATFORM_NOTE
        for text in content.get("assumptions") or []
        if text.strip()
    ]
    return views.ScenarioText(
        threat_category=content.get("category"),
        contributing_categories=content.get("contributing_categories") or [],
        threat_type=threat.get("type"),
        threat_name=threat.get("name"),
        supporting_systems_involved=systems,
        scenario_title=content.get("title"),
        scenario_statement=content.get("statement"),
        risk_statement=content.get("risk_statement"),
        assumptions=assumptions,
        route_status=c.ROUTE_WORDS.get(str(status), str(status).upper()) if status else None,
        also_applies=content.get("also_applies") or [],
        threat_scenario_description=(content.get("mitre") or {}).get("threat_scenario_description"),
    )


def _build_threat_block(content: dict[str, Any]) -> views.ThreatBlock:
    threat, category = content.get("threat") or {}, content.get("category")
    library_id, confidence = threat.get("library_id"), threat.get("confidence")
    name, own_id = threat.get("category") or category, threat.get("category_id")
    kinds_id = content.get("category_id") if str(name or "").casefold() == str(category or "").casefold() else None
    verified = library_id is not None and threat.get("library_status") in (None, c.LibraryStatus.ACTIVE)
    grounding = None if not threat else c.GroundingStatus.VERIFIED if verified else c.GroundingStatus.UNVERIFIED
    return views.ThreatBlock(
        threat_id=None if threat.get("ai_generated") else threat.get("key"),  # owner 2026-11-23: no id for an AI one
        threat_category=name,
        threat_category_id=own_id if own_id is not None else kinds_id,
        threat_type=threat.get("type"),
        threat_name=threat.get("name"),
        threat_type_id=threat.get("type_id"),
        library_threat_type=threat.get("type") if threat.get("type_id") is not None else None,
        library_threat_name=threat.get("name") if library_id is not None else None,
        grounding_status=grounding,
        threat_catalogue_id=library_id,
        is_threat_type_ai_generated=False,
        is_threat_ai_generated=threat.get("ai_generated"),
        grounding_score=confidence,
        score=confidence,
        scope_rank=threat.get("rank"),
    )


def _build_library_view(threat: dict[str, Any]) -> views.LibraryView | None:
    if not threat.get("name"):
        return None
    message: str | None = None
    status = c.LibraryOutcome.EXISTING
    if threat.get("library_status") == c.LibraryStatus.PENDING:
        status, message = c.LibraryOutcome.INSERTED, c.LibraryBanner.PROPOSED
    elif threat.get("library_status") == c.LibraryStatus.CURATOR_REJECTED:
        status, message = c.LibraryOutcome.REJECTED_BY_CURATOR, c.LibraryBanner.REJECTED.format(name=threat["name"])
    kind = c.LibraryOutcome.EXISTING if threat.get("type_id") is not None else c.LibraryOutcome.NOT_PROPOSED
    return views.LibraryView(
        threat=views.LibraryEntry(name=threat["name"], status=status),
        threat_type=views.LibraryEntry(name=threat.get("type") or "", status=kind),
        message=message,
    )


def build_plan_trace_view(session_id: str, trace: dict[str, Any], paths: list[dict[str, Any]]) -> views.PlanTraceView:
    """Builds the plan trace view: the stored trace and what became of each planned path."""
    replaced = c.UnselectedReason.REPLACED_AFTER_FAILURE
    given_up = [
        views.GivenUpPath(
            path_id=path["path_id"],
            threat_key=path["steps"][0],
            kind=path["category"],
            rank=path["rank"],
            reason=path.get("abandoned_reason"),
            repeats=path.get("repeats"),
            replaced_by=path.get("replaced_by"),
        )
        for path in paths
        if path.get("abandoned")
    ]
    writing = views.WriteOutcomes(
        served=sum(bool(path.get("served")) for path in paths),
        still_to_write=count_plan_paths(paths)["remaining"],
        given_up=len(given_up),
        replaced=sum(path.get("unselected_reason") == replaced for path in paths),
        given_up_paths=given_up,
    )
    return views.PlanTraceView.model_validate({"session_id": session_id, **trace, "writing": writing})
