"""Which facts a run uses (owner 2026-10-11): every column dbo.tsg_GetAssetContext returns for the asset and
its systems, nothing else, in every step; and the required facts (ASSET_/SYSTEM_PROPERTIES_REQUIRED). Pure:
the procedure's rows are built in memory."""

import dataclasses
import json
from datetime import date, datetime
from decimal import Decimal
from typing import Any

import pytest

from app.core.config import get_settings
from app.core.constants import StrideCategory
from app.core.exceptions import Invalid, SetupError
from app.engine.scenarios.control_query import control_query
from app.engine.scenarios.finding.asset_landscape import (
    describe_asset_for_ai,
    library_search_queries,
    raw_system_facts,
)
from app.models.asset_context import AssetContextRows, FrozenContext
from app.models.scenarios import StartRunRequest
from app.services.scenarios import context as context_module
from app.services.scenarios.property_selection import check_required

LOCATION, TECHNOLOGY = "Marker location Site Alpha", "Marker technology Stack Omega"
NEW_FACT = "Marker recovery notes Gamma"
OPTIONS = [
    {"code": "priority", "value": 11, "name": "High"},
    {"code": "technology-used", "value": 21, "name": TECHNOLOGY},
]
REQUEST = StartRunRequest(asset_id=1206, supporting_system_ids=[1567, 1568])
CONTENT = {"category": "Tampering", "threat": {"type": "Malware", "name": "Ransomware"}, "title": "t"}


def _asset_row(**changes: Any) -> dict[str, Any]:
    """The asset row as the procedure returns it (scripts/sql/tsg_GetAssetContext.sql)."""
    row: dict[str, Any] = {
        "id": 1206, "name": "Grid  Centre", "category_code": "OT", "cii_asset_description": "Runs the grid.",
        "critical_service": "Electricity  supply", "sector": "Energy", "sub_sector": None,
        "data_handled": "Telemetry", "asset_type": "Control system", "operating_system": "Windows",
        "location": LOCATION, "target_rto_hours": Decimal(4), "target_rpo_hours": Decimal(1),
        "asset_priority": 11, "entity_technology_context": None,
    }  # fmt: skip
    return row | changes


def _system_row(system_id: int, **changes: Any) -> dict[str, Any]:
    """A system row as the procedure returns it, most facts unanswered."""
    row: dict[str, Any] = {
        "id": system_id, "name": f"System {system_id}", "category_code": "IT", "category_name": "IT",
        "past_incidents": None, "technology_used": "[21]", "dr_location": None,
        "last_dr_test_date": datetime(1900, 1, 1), "rto_target_mins": Decimal(0),
        **dict.fromkeys(context_module.SINGLE_SELECT_CODES),
        **dict.fromkeys(("backup_tested", "backup_multi_site", "document_drp_exists")),
    }  # fmt: skip
    return row | changes


def _rows(asset: dict[str, Any] | None = None, *systems: dict[str, Any]) -> AssetContextRows:
    return AssetContextRows(
        asset=asset or _asset_row(),
        services=[{"id": 1624, "name": "Electricity supply", "linked": True}],
        sector=None,
        systems=list(systems) or [_system_row(1567), _system_row(1568, dr_location="Site B")],
        options=list(OPTIONS),  # a copy: a test changing its rows never changes the next test's
    )


def _without(row: dict[str, Any], column: str) -> dict[str, Any]:
    return {key: value for key, value in row.items() if key != column}


def _texts(context: FrozenContext) -> str:
    """Everything the steps send on: the stored record, the landscape, the library search queries, the
    control query, and each system's facts as the brief and the remediation snapshot read them."""
    return "\n".join(
        [
            json.dumps(context.to_record(), default=str),
            describe_asset_for_ai(context, 30_000).text,
            *library_search_queries(context, StrideCategory.TAMPERING),
            control_query(CONTENT, context, context.systems).text,
            *(json.dumps(raw_system_facts(system), default=str) for system in context.systems),
        ]
    )


def _freeze(rows: AssetContextRows) -> FrozenContext:
    return context_module.freeze_context(REQUEST, rows)


def test_a_column_removed_from_the_procedure_reaches_no_step() -> None:
    assert LOCATION in _texts(_freeze(_rows())) and TECHNOLOGY in _texts(_freeze(_rows()))
    systems = [_without(_system_row(system_id), "technology_used") for system_id in (1567, 1568)]
    asset = _without(_without(_asset_row(), "location"), "critical_service")
    context = _freeze(_rows(asset, *systems))
    texts = _texts(context)
    assert LOCATION not in texts and TECHNOLOGY not in texts and "Electricity" not in texts
    assert "critical_service" not in context.asset_context  # one place for each fact, no copy left behind


def test_a_column_added_to_the_procedure_reaches_every_step() -> None:
    """No app change: a new system column and a new asset column are facts of the run, in the landscape, the
    search queries, the control query, the brief and the snapshot."""
    systems = [_system_row(1567, recovery_notes=NEW_FACT), _system_row(1568, recovery_notes=None)]
    context = _freeze(_rows(_asset_row(site_notes="Marker site notes Delta"), *systems))
    assert context.systems[0]["recovery_notes"] == NEW_FACT
    for text in (
        describe_asset_for_ai(context, 30_000).text,
        json.dumps(raw_system_facts(context.systems[0])),
    ):
        assert NEW_FACT in text
    assert any(NEW_FACT in query for query in library_search_queries(context, StrideCategory.TAMPERING))
    controls_text = control_query(CONTENT, context, context.systems).text  # owner 2026-10-11: controls too
    assert NEW_FACT in controls_text and "site_notes: Marker site notes Delta" in controls_text


def test_the_head_columns_are_not_facts_and_the_asset_name_is_searched() -> None:
    """id, name and category_code stay out of the facts the prompts get; the asset's search query carries its
    name (owner 2026-10-11) with its spaces collapsed."""
    context = _freeze(_rows())
    assert context.asset == {"id": 1206, "name": "Grid Centre", "category_code": "OT"}
    assert not {"id", "name", "category_code"} & set(context.asset_context)
    assert list(context.systems[0])[:4] == ["id", "alias", "name", "category_code"]
    assert "Grid Centre" in library_search_queries(context, StrideCategory.TAMPERING)[-1]


@pytest.mark.parametrize("missing", ["id", "name", "category_code"])
def test_a_procedure_without_a_head_column_is_a_setup_error(missing: str) -> None:
    with pytest.raises(SetupError) as asset_refused:
        _freeze(_rows(_without(_asset_row(), missing)))
    assert "asset rows" in asset_refused.value.detail and asset_refused.value.status == 500
    with pytest.raises(SetupError) as system_refused:
        _freeze(_rows(None, _system_row(1567), _without(_system_row(1568), missing)))
    assert "supporting system rows" in system_refused.value.detail


def test_dropdown_names_follow_the_installed_procedure_by_value_or_by_id() -> None:
    """2026-10-12 (owner: "use what is there in the updated stored procedure"): the installed procedure
    returned its dropdown names by id (code, id, name) and the start failed with a bare 500 (KeyError
    'value').
    By value or by id, the same names; any other shape is named at once, never a bare error."""
    by_id = _rows()
    by_id.options[:] = [{"code": row["code"], "id": row["value"], "name": row["name"]} for row in OPTIONS]
    assert _freeze(by_id) == _freeze(_rows())
    unknown = _rows()
    unknown.options[:] = [{"code": "managed-by", "number": 31, "name": "In-house"}]
    with pytest.raises(SetupError) as refused:
        _freeze(unknown)
    assert refused.value.status == 500 and "value (or id)" in refused.value.detail


def test_values_are_stored_as_mongodb_and_a_prompt_read_them() -> None:
    """Saved dropdown values as names (a bad list item dropped alone, as SQL's TRY_CAST), decimals as numbers,
    SQL Server's 1900 minimum date as unknown, a real date as ISO, names' spaces collapsed, a binary column
    dropped, a blank option name unanswered."""
    systems = [
        _system_row(1567, last_dr_test_date=date(2026, 3, 1)),
        _system_row(1568, row_version=b"\x00\x01", technology_used='[null, "21", "x", 6.5, true]'),
    ]
    rows = _rows(None, *systems)
    rows.options.append({"code": "managed-by", "value": 31, "name": "  "})
    rows.systems[0]["managed_by"] = 31
    context = _freeze(rows)
    assert context.asset_context["asset_priority"] == "High"
    rto = context.asset_context["target_rto_hours"]
    assert rto == 4.0 and type(rto) is float  # MongoDB stores no Decimal
    assert context.systems[0]["technology_used"] == context.systems[1]["technology_used"] == [TECHNOLOGY]
    assert context.systems[0]["last_dr_test_date"] == "2026-03-01"
    assert context.systems[1]["last_dr_test_date"] is None
    facts = context.asset_context
    assert (facts["critical_service"], facts["sector"], facts["sub_sector"]) == (
        "Electricity supply",
        "Energy",
        None,
    )
    assert context.systems[1]["row_version"] is None and context.systems[0]["managed_by"] is None
    assert FrozenContext.from_record(context.to_record()) == context


def test_a_context_stored_before_the_copies_were_removed_still_loads() -> None:
    """Runs frozen before 2026-10-11 hold top-level copies (critical_service, sector, ...): read, ignored."""
    stored = _freeze(_rows()).to_record()
    old = stored | {"critical_service": "x", "sector": "x", "sub_sector": None, "entity_technology": None}
    assert FrozenContext.from_record(old) == FrozenContext.from_record(stored)


@pytest.mark.parametrize(
    ("row", "column"), [("asset", "criticality"), ("system", "alias"), ("system", "type_id")]
)
def test_a_fact_under_a_reserved_name_is_a_setup_error(row: str, column: str) -> None:
    """Review 2026-10-11: `alias` would replace SYS1..n; id-like names are dropped from every prompt, so such
    a fact would count as recorded while the AI never saw it."""
    rows = (
        _rows(_asset_row(**{column: "x"}))
        if row == "asset"
        else _rows(None, _system_row(1567, **{column: "x"}), _system_row(1568, **{column: "x"}))
    )
    with pytest.raises(SetupError) as refused:
        _freeze(rows)
    assert column in refused.value.detail and "reserved" in refused.value.detail


@pytest.mark.parametrize("name", [None, "  ", "N/A"])
def test_an_asset_or_system_without_a_name_is_refused_before_any_run(name: Any) -> None:
    """Review 2026-10-11: every prompt, card and search names them; a nameless one failed in the worker."""
    with pytest.raises(Invalid) as asset_refused:
        _freeze(_rows(_asset_row(name=name)))
    assert asset_refused.value.errors == [
        {"field": "body.asset_id", "message": "asset 1206: name not recorded."}
    ]
    with pytest.raises(Invalid) as system_refused:
        _freeze(_rows(None, _system_row(1567), _system_row(1568, name=name)))
    assert system_refused.value.errors[0]["field"] == "body.supporting_system_id.1"


def test_a_date_column_is_no_search_text() -> None:
    """Review 2026-10-11: any date column the procedure returns, not only the DR test date."""
    context = _freeze(_rows(_asset_row(commissioned_on=date(2019, 5, 2))))
    assert context.asset_context["commissioned_on"] == "2019-05-02"
    assert not any(
        "2019-05-02" in query for query in library_search_queries(context, StrideCategory.TAMPERING)
    )


def test_missing_facts_name_only_columns_the_procedure_returns() -> None:
    systems = [_without(_system_row(1567), "backup_tested"), _without(_system_row(1568), "backup_tested")]
    missing = _freeze(_rows(None, *systems)).missing_facts
    assert "hosting_location" in missing and "backup_multi_site" in missing and "backup_tested" not in missing
    # Every column counts, none picked by name (owner 2026-10-11): a text no system records is missing too;
    # a value of 0 is a recorded value, never "missing"
    assert "past_incidents" in missing and "rto_target_mins" not in missing


@pytest.mark.parametrize(
    ("value", "recorded"),
    [
        (0, True),  # a count of 0 is a fact
        (False, True),  # a real "No"
        ("Site B", True),
        (None, False),
        ("   ", False),
        ("N/A", False),
        ([], False),
        (["None"], False),  # a list holding only a placeholder
    ],
)
def test_recorded_means_what_the_ai_would_be_shown(
    monkeypatch: pytest.MonkeyPatch, value: Any, recorded: bool
) -> None:
    monkeypatch.setattr(get_settings(), "system_properties_required", "dr_location")
    systems = [{"id": 1567, "name": "SCADA", "dr_location": value}]
    if recorded:
        check_required(REQUEST, {"name": "Grid Centre"}, systems)
    else:
        with pytest.raises(Invalid):
            check_required(REQUEST, {"name": "Grid Centre"}, systems)


def test_the_refusal_names_every_gap_once_in_a_fixed_order(monkeypatch: pytest.MonkeyPatch) -> None:
    """The asset's gaps (one entry per request field: sector is the request's sector_id), then each system's
    in request order, names in the procedure's column order whatever order the setting gives; names and ids
    only."""
    monkeypatch.setattr(
        get_settings(), "asset_properties_required", "location, sector, cii_asset_description"
    )
    monkeypatch.setattr(get_settings(), "system_properties_required", "dr_location, technology_used")
    asset = {"name": "Grid Centre", "cii_asset_description": None, "location": "", "sector": None}
    systems = [
        {"id": 1567, "name": "SCADA", "technology_used": ["Windows"], "dr_location": None},
        {"id": 1568, "name": "Historian", "technology_used": None, "dr_location": None},
    ]
    with pytest.raises(Invalid) as refused:
        check_required(REQUEST, asset, systems)
    assert refused.value.reason == "required_facts_missing"
    assert refused.value.errors == [
        {"field": "body.asset_id", "message": "asset 1206: cii_asset_description, location not recorded."},
        {"field": "body.sector_id", "message": "asset 1206: sector not recorded."},
        {"field": "body.supporting_system_id.0", "message": "system 1567: dr_location not recorded."},
        {
            "field": "body.supporting_system_id.1",
            "message": "system 1568: technology_used, dr_location not recorded.",
        },
    ]
    assert refused.value.detail == (
        "Required properties are not recorded: asset 1206: cii_asset_description, location; asset 1206: "
        "sector; system 1567: dr_location; system 1568: technology_used, dr_location."
    )


def test_a_required_name_the_procedure_does_not_return_is_a_setup_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every run would be refused: the operator is told which setting names which missing column, at once."""
    monkeypatch.setattr(get_settings(), "asset_properties_required", "location")
    with pytest.raises(SetupError) as refused:
        _freeze(_rows(_without(_asset_row(), "location")))
    assert "ASSET_PROPERTIES_REQUIRED names location" in refused.value.detail
    monkeypatch.setattr(get_settings(), "asset_properties_required", "")
    monkeypatch.setattr(get_settings(), "system_properties_required", "recovery_notes")
    with pytest.raises(SetupError) as system_refused:
        _freeze(_rows())
    assert "SYSTEM_PROPERTIES_REQUIRED names recovery_notes" in system_refused.value.detail


def test_the_control_query_names_the_asset_without_empty_brackets() -> None:
    """With asset_type not returned (or not recorded) the reranker's text reads "Asset: <name>", never
    "Asset: <name> ()"; with it, "Asset: <name> (<type>)"."""
    typed = control_query(CONTENT, _freeze(_rows()), []).text
    assert "Asset: Grid Centre (Control system)" in typed
    untyped = control_query(CONTENT, _freeze(_rows(_without(_asset_row(), "asset_type"))), []).text
    assert "Asset: Grid Centre\n" in untyped and "()" not in untyped


def test_a_placeholder_asset_type_is_no_type_in_the_control_query() -> None:
    """Review 2026-10-11: "N/A" or blanks are not a type: "Asset: <name>", as for a type not recorded."""
    context = _freeze(_rows())
    placeholder = dataclasses.replace(context, asset_context=context.asset_context | {"asset_type": " N/A "})
    text = control_query(CONTENT, placeholder, []).text
    assert "Asset: Grid Centre\n" in text and "N/A" not in text


def test_dropdown_names_the_procedure_already_gave_are_kept() -> None:
    """G217: the owner's procedure names dropdowns itself (by option id): "Historian, Windows" and "In-house"
    reached the app as text and were dropped as unknown saved values."""
    options = {"technology-used": {1: "SCADA"}, "managed-by": {1: "In-house"}}
    assert context_module._multi("Historian, Windows", "technology-used", options) == ["Historian", "Windows"]
    assert context_module._multi("[1]", "technology-used", options) == ["SCADA"]  # saved values, as before
    assert context_module._multi("[1, x", "technology-used", options) is None  # a broken array: none
    assert context_module._single("In-house", "managed-by", options) == "In-house"
    assert context_module._single(1, "managed-by", options) == "In-house"
