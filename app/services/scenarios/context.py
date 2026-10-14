"""The frozen asset context of a run (v1 app/pipeline/context.py): checked against the caller's
request, then built once from tsg_GetAssetContext's result sets and never changed. Its facts are the
procedure's columns (owner 2026-10-11): a column added there is used from the next run, one removed is not."""

import json
from datetime import date
from decimal import Decimal
from typing import Any, Final

import structlog

from app.core.constants import (
    ConflictReason,
    ContextProperties,
    LogEvent,
    PropertyMessage,
    SessionMessage,
    ThreatFinding,
)
from app.core.exceptions import Forbidden, Invalid, NotFound, SetupError
from app.core.tracing import traced_step
from app.engine.shared.prompt_redaction import DATABASE_KEYS, facts_safe_for_prompt
from app.models.asset_context import AssetContextRows, FrozenContext, Row
from app.models.scenarios import StartRunRequest
from app.services.scenarios.property_selection import check_required

log = structlog.get_logger(__name__)

#: Coded columns that hold one saved option value (option_value.value), and the option code naming it.
SINGLE_SELECT_CODES: Final = {
    "accessability_channel": "acc-channel",
    "hosting_location": "hosting-location",
    "network_connectivity_primary_dr": "network-connectivity",
    "dr_drill_frequency": "dr-drill",
    "managed_by": "managed-by",
}
#: Coded columns that hold a JSON array of saved option values, e.g. "[6, 9]", or the names the procedure
#: already made of them, e.g. "Historian, Windows" (the owner's procedure does, G217).
MULTI_SELECT_CODES: Final = {
    "technology_used": "technology-used",
    "database_platforms": "database-platforms",
    "targeted_users": "targeted-users",
    "saas_platform_list": "saas-platforms",
    "public_cloud_platforms": "pub-c-platforms",
}
_SINGLE_CODES: Final = {**SINGLE_SELECT_CODES, "asset_priority": "priority"}
#: Facts that are names: shown with their runs of spaces collapsed, as every name is.
_NAME_FACTS: Final = ("critical_service", "sector", "sub_sector")
_NEVER_TESTED_YEAR: Final = 1900  # SQL Server's minimum date: "never" (e.g. a DR test), not a real date
#: Names a fact column may not have: the app's own (alias) and the keys every prompt drops (DATABASE_KEYS).
_RESERVED_NAMES: Final = (frozenset(ContextProperties.ALWAYS_USED) | DATABASE_KEYS) - set(
    ContextProperties.HEAD
)


def freeze_context(request: StartRunRequest, rows: AssetContextRows) -> FrozenContext:
    """403 asset_not_owned / system_not_linked, 404 service or sector, 422 sector_id or
    required_facts_missing (a name is always required), 500 setup_error when the procedure lacks a head column
    or a required one, returns a reserved name, or returns dropdown names without code, name and value (or
    id); else the context. Traced with the request and the frozen
    context only: the raw rows hold them too."""
    with traced_step("run.freeze_context", request=request) as trace:
        _check_procedure_columns(rows)
        _check_ownership(request, rows)
        assert rows.asset is not None
        _check_sector(request, rows.sector)
        _warn_unlinked_service(request, rows.services)
        options = _option_names(rows.options)
        systems_by_id = {row["id"]: row for row in rows.systems}
        asset_facts = _facts(rows.asset, options)
        systems = [
            _frozen_system(systems_by_id[system_id], f"{ThreatFinding.SYSTEM_ALIAS}{position}", options)
            for position, system_id in enumerate(request.supporting_system_ids, start=1)
        ]
        asset = _head(rows.asset)
        check_required(request, {"name": asset["name"], **asset_facts}, systems)
        context = FrozenContext(asset, asset_facts, systems, _missing_facts(systems))
        trace.set_output(context)
        return context


def display_name(value: Any) -> Any:
    """A name as every prompt and card shows it: runs of whitespace collapsed to one space."""
    return " ".join(value.split()) if isinstance(value, str) else value


def _check_procedure_columns(rows: AssetContextRows) -> None:
    """A procedure edited without id, name or category_code, or returning a fact under a reserved name (alias
    would replace SYS1..n; id-like names are never shown to the AI, so such a fact would count as recorded
    while the AI never saw it), is a set-up mistake named at once, never a wrong run."""
    for kind, found in (("asset", [rows.asset] if rows.asset else []), ("supporting system", rows.systems)):
        if not found:
            continue
        if any(column not in row for row in found for column in ContextProperties.HEAD):
            columns = ", ".join(ContextProperties.HEAD)
            raise SetupError(PropertyMessage.HEAD_MISSING.format(columns=columns, rows=kind))
        facts = set(found[0]) - set(ContextProperties.HEAD)  # one result set: every row has its columns
        if reserved := sorted(facts & _RESERVED_NAMES):
            raise SetupError(PropertyMessage.RESERVED.format(columns=", ".join(reserved), rows=kind))
    # The dropdown names: by value or by id, as the installed procedure returns them (2026-10-12: one by id
    # was a bare 500, KeyError 'value'); anything else is named at once, never a wrong run.
    if rows.options and not _option_key(rows.options[0]):
        raise SetupError(PropertyMessage.OPTIONS_OUT_OF_DATE.format(found=", ".join(rows.options[0])))


def _check_ownership(request: StartRunRequest, rows: AssetContextRows) -> None:
    if rows.asset is None:
        raise Forbidden(
            SessionMessage.ASSET_NOT_OWNED.format(asset_id=request.asset_id),
            reason=ConflictReason.ASSET_NOT_OWNED,
        )
    linked = {row["id"] for row in rows.systems}
    unlinked = [system_id for system_id in request.supporting_system_ids if system_id not in linked]
    if unlinked:
        message = SessionMessage.SYSTEMS_NOT_LINKED.format(system_ids=unlinked, asset_id=request.asset_id)
        raise Forbidden(message, reason=ConflictReason.SYSTEM_NOT_LINKED, details={"system_ids": unlinked})
    if request.service_id is not None and not any(row["id"] == request.service_id for row in rows.services):
        raise NotFound(SessionMessage.SERVICE_NOT_FOUND.format(service_id=request.service_id))
    asked_sector = request.subsector_id or request.sector_id
    if asked_sector is not None and rows.sector is None:
        raise NotFound(SessionMessage.SECTOR_NOT_FOUND.format(sector_id=asked_sector))


def _check_sector(request: StartRunRequest, row: Row | None) -> None:
    """A sector_id sent with a sub-sector must be its parent (422), never resolved in favour of one of the
    two. The names themselves are the asset row's sector and sub_sector columns."""
    if row is None or request.subsector_id is None or request.sector_id is None:
        return
    top_id = row["parent_id"] if row["parent_id"] is not None else row["id"]
    if top_id != request.sector_id:
        message = SessionMessage.SECTOR_NOT_PARENT.format(
            sector_id=request.sector_id, subsector_id=request.subsector_id, parent_id=top_id
        )
        raise Invalid(message, errors=[{"field": f"{request.FIELD_PREFIX}.sector_id", "message": message}])


def _warn_unlinked_service(request: StartRunRequest, rows: list[Row]) -> None:
    """The asked service is used even when the asset is not linked to it: logged."""
    if request.service_id is not None and not any(row["linked"] for row in rows):
        log.warning(
            LogEvent.CONTEXT_SERVICE_NOT_LINKED, asset_id=request.asset_id, service_id=request.service_id
        )


def _option_names(rows: list[Row]) -> dict[str, dict[int, str]]:
    """{option code (lower case): {saved number: name}}: SQL compares codes case-insensitively. The number is
    the one the procedure's dropdown facts hold, under the name it returns it (value, or id)."""
    names: dict[str, dict[int, str]] = {}
    key = _option_key(rows[0]) if rows else None
    for row in rows:
        if key and (row["name"] or "").strip():  # a blank option name names nothing: reads as unanswered
            names.setdefault(str(row["code"]).strip().lower(), {})[row[key]] = row["name"]
    return names


def _option_key(row: Row) -> str | None:
    """The column a dropdown-names row holds its number in, when it also has its code and name; else None."""
    if any(column not in row for column in ContextProperties.OPTION_COLUMNS):
        return None
    return next((key for key in ContextProperties.OPTION_KEYS if key in row), None)


def _unanswered(raw: int | None) -> bool:
    """A coded single-select nobody answered: NULL, or the platform form's 0 placeholder (no option is saved
    as 0)."""
    return raw is None or raw == 0


def _single(raw: int | str | None, code: str, options: dict[str, dict[int, str]]) -> str | None:
    """The option's name: its saved value named through PART 5, or the name the procedure already gave (a
    text that is not a number, G217); None when unanswered, or when a saved value is unknown (logged: seed
    data, not a gap)."""
    if isinstance(raw, str):
        number = _whole(raw)
        if number is None:  # the name the procedure already gave
            return display_name(raw) or None
        raw = number
    if raw is None or _unanswered(raw):
        return None
    name = options.get(code, {}).get(raw)
    if name is None:
        log.warning(LogEvent.CONTEXT_OPTION_VALUE_NOT_FOUND, code=code, value=raw)
    return name


def _multi(raw: str | None, code: str, options: dict[str, dict[int, str]]) -> list[str] | None:
    """Names of a JSON array of saved values; an item that is not a known whole number is dropped alone, as
    the platform's TRY_CAST does (a raw number would read as a fact); bad JSON = none. A text that is not a
    JSON array is the names the procedure already made ("Historian, Windows": STRING_AGG, G217): kept."""
    text = (raw or "").strip()
    try:
        items = json.loads(text) if text else []
    except ValueError:
        if text.startswith("["):  # a broken array: none
            return None
        return [name for name in (part.strip() for part in text.split(",")) if name] or None
    known = options.get(code, {})
    values = map(_whole, items if isinstance(items, list) else [])
    names = [known[value] for value in values if value in known]
    return names or None


def _whole(item: Any) -> int | None:
    """6 or "6" -> 6; null, true, 6.5 or "x" -> None (as SQL's TRY_CAST(... AS INT))."""
    try:
        return int(str(item))
    except ValueError:
        return None


def _stored(value: Any) -> Any:
    """A column's value as MongoDB stores it and a prompt reads it: a DECIMAL as a number (MongoDB stores no
    Decimal), a date as an ISO date (SQL Server's 1900 minimum = unknown), any other type as text."""
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, date):  # a datetime too
        return None if value.year <= _NEVER_TESTED_YEAR else value.isoformat()
    if isinstance(value, bytes | bytearray | memoryview):
        return None  # binary (varbinary, rowversion) holds no words a person or the AI could read
    return str(value)  # a time or a GUID as its text


def _fact(column: str, value: Any, options: dict[str, dict[int, str]]) -> Any:
    if column in _SINGLE_CODES:
        return _single(value, _SINGLE_CODES[column], options)
    if column in MULTI_SELECT_CODES:
        return _multi(value, MULTI_SELECT_CODES[column], options)
    if column in _NAME_FACTS:
        return display_name(value)
    return _stored(value)


def _facts(row: Row, options: dict[str, dict[int, str]]) -> dict[str, Any]:
    """Every column of a procedure row but its head, in the procedure's order: the facts the prompts get."""
    return {
        column: _fact(column, value, options)
        for column, value in row.items()
        if column not in ContextProperties.HEAD
    }


def _head(row: Row) -> dict[str, Any]:
    return {"id": row["id"], "name": display_name(row["name"]), "category_code": row["category_code"]}


def _frozen_system(row: Row, alias: str, options: dict[str, dict[int, str]]) -> dict[str, Any]:
    return {"id": row["id"], "alias": alias, **_head(row), **_facts(row, options)}


def _missing_facts(systems: list[dict[str, Any]]) -> list[str]:
    """The supporting-system facts the procedure returns that NOT ONE system in scope records, as the AI would
    be shown them (v1 _unrecorded_facts, for every column: owner 2026-10-11, the columns are dynamic; 0 and No
    are recorded values): information for the reviewer, never a reason to refuse a run."""
    first = systems[0] if systems else {}  # one result set: every system has the procedure's same columns
    columns = [column for column in first if column not in ContextProperties.ALWAYS_USED]
    return sorted(
        column
        for column in columns
        if not any(facts_safe_for_prompt({"fact": system.get(column)}) for system in systems)
    )
