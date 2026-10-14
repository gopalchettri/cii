"""G227 (owner 2026-10-13): the control query keeps every system and the asset's facts in view however long
the scenario and the risk are; one long system description never pushes the others out; what was shortened is
recorded (labels only); the mapper searches exactly CONTROL_CANDIDATES candidates."""

from types import SimpleNamespace
from typing import Any

import pytest

from app.core.config import Settings
from app.core.constants import Controls
from app.engine.scenarios import control_selection
from app.engine.scenarios.control_mapper import ControlMapper
from app.engine.scenarios.control_query import control_query
from tests.planner_samples import CONTEXT
from tests.test_control_mapping import _CONTROLS, _OT_CONTEXT, _SCENARIO, _ScoresByText

SYSTEMS = [
    {"id": n, "name": name, "category_code": "OT", "description": f"{name} runs the city traffic network."}
    for n, name in (
        (1448, "Command Centre"),
        (1449, "Traffic Systems"),
        (1450, "Signal Control"),
        (1451, "Incident Response"),
    )
]


def _content(statement_chars: int = 2600, risk_chars: int = 1300) -> dict[str, Any]:
    return {
        "category": "Spoofing",
        "threat": {"type": "Credential misuse", "name": "Credential abuse"},
        "title": "Loss of control",
        "statement": ("story " * statement_chars)[:statement_chars],
        "risk_statement": ("impact " * risk_chars)[:risk_chars],
        "actors": [{"name": "an organised criminal group", "role": "acting"}],
    }


def test_long_texts_never_push_the_systems_or_the_asset_facts_out() -> None:
    """Built narrative first and cut from the end, a 400-word scenario and a 200-word risk left no system."""
    query = control_query(_content(), CONTEXT, SYSTEMS)
    assert len(query.text) <= Controls.QUERY_MAX_CHARS
    for system in SYSTEMS:
        assert (
            f"System {system['name']}: description: {system['name']} runs the city traffic network."
            in query.text
        )
    assert "Asset facts:" in query.text and "Scenario: story" in query.text and "Risk: impact" in query.text
    assert "scenario" in query.shortened and not any(label.startswith("system") for label in query.shortened)


def test_one_long_system_description_never_pushes_the_others_out() -> None:
    systems = [{**SYSTEMS[0], "description": "x " * 2500}, *SYSTEMS[1:]]
    query = control_query(_content(300, 200), CONTEXT, systems)
    assert all(f"System {system['name']}:" in query.text for system in systems)
    assert query.shortened == ("system 1448",) and len(query.text) <= Controls.QUERY_MAX_CHARS


def test_a_query_that_fits_is_whole_in_priority_order_and_the_same_every_time() -> None:
    first = control_query(_content(300, 200), CONTEXT, SYSTEMS)
    assert first.shortened == () and first == control_query(_content(300, 200), CONTEXT, SYSTEMS)
    text = first.text
    assert (
        text.index("Title:")
        < text.index("System Command Centre")
        < text.index("Scenario:")
        < text.index("Risk:")
    )


def test_the_mapper_searches_the_configured_candidates_and_records_what_was_shortened(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    asked: list[int] = []

    class Snapshot:
        library = SimpleNamespace(control_library=_CONTROLS)

        def find_controls(self, queries: list[str], limit: int, allowed: Any) -> list[list[Any]]:
            asked.append(limit)
            return [[(control, 0.0) for control in _CONTROLS]]

    settings = Settings(CONTROL_CANDIDATES=25)  # type: ignore[call-arg]
    monkeypatch.setattr(control_selection, "get_settings", lambda: settings)
    rerank = _ScoresByText({"Backup of controller logic": 87.0})
    scenario = {**_SCENARIO, "content": {**_SCENARIO["content"], "statement": "story " * 900}}
    mapping = ControlMapper(rerank).map_controls(scenario, _OT_CONTEXT, Snapshot())  # type: ignore[arg-type]
    assert asked == [25] and "scenario" in mapping.query_shortened
