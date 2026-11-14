"""The scenario lists' total (GET /v1/entities/{id}/scenarios, a session's results): one aggregate over an
index alone, equal to the served-and-current count_documents it replaced, which read every document."""

import copy
import json
import uuid
from types import SimpleNamespace
from typing import Any

import pytest

from app import container
from app.core.constants import Collection, Decision, ScenarioStatus
from app.core.database import get_mongodb
from app.data_access.scenario.threat_scenario_repository import ThreatScenarioRepository
from app.services.scenario.threat_scenario_service import ThreatScenarioService


@pytest.fixture
def scenarios() -> ThreatScenarioRepository:
    repository = container.get_threat_scenario_repository()
    repository.create_indexes()
    return repository


def _mixed_entity(scenarios: ThreatScenarioRepository) -> tuple[int, str]:
    """A new entity whose cards mix every case the current-version test separates; it and its first run."""
    entity_id, first, second = int(uuid.uuid4().hex[:12], 16), *(f"run-{uuid.uuid4().hex}" for _ in "12")
    cards: list[tuple[str, str, dict[str, Any]]] = [
        (first, "p1:v1", {"superseded_by": "p1", "decision": Decision.PENDING}),  # replaced, pending: hidden
        (first, "p1", {"superseded_by": None, "decision": Decision.PENDING}),
        (first, "p2:v1", {"superseded_by": "p2", "decision": Decision.ACCEPTED}),  # replaced, decided: shown
        (first, "p2", {"superseded_by": None, "decision": Decision.PENDING}),
        (first, "p3:v1", {"superseded_by": "p3", "decision": Decision.REJECTED}),
        (first, "p3", {"superseded_by": None, "decision": Decision.REJECTED}),
        (first, "p4", {"status": ScenarioStatus.BLOCKED, "decision": Decision.PENDING}),  # never served
        (second, "p1", {"status": ScenarioStatus.FAILED}),  # neither superseded_by nor decision stored
        (second, "p2", {"decision": Decision.ACCEPTED}),
    ]
    scenarios.collection.insert_many(
        [
            {
                "_id": f"{session_id}:{card}",
                "session_id": session_id,
                "entity_id": entity_id,
                "path_id": card.split(":")[0],
                "status": ScenarioStatus.DONE,
                "created_at": number,
            }
            | fields
            for number, (session_id, card, fields) in enumerate(cards)
        ]
    )
    return entity_id, first


@pytest.mark.parametrize(
    ("decision", "expected"),
    [(None, 7), (Decision.PENDING, 2), (Decision.ACCEPTED, 2), (Decision.REJECTED, 2)],
)
def test_the_total_equals_the_served_current_count(
    scenarios: ThreatScenarioRepository, decision: Decision | None, expected: int
) -> None:
    entity_id, first = _mixed_entity(scenarios)
    chosen = {} if decision is None else {"decision": decision}
    today = scenarios.count(served=True, current=True, entity_id=entity_id, **chosen)
    assert scenarios.count_current_scenarios(entity_id=entity_id, **chosen) == today == expected
    session = scenarios.count(served=True, current=True, session_id=first, **chosen)
    assert scenarios.count_current_scenarios(session_id=first, **chosen) == session


@pytest.mark.parametrize(
    ("where", "index"),
    [("entity", "entity_counts"), ("entity_accepted", "entity_counts"), ("session", "run_counts")],
)
def test_the_total_reads_one_index_only(scenarios: ThreatScenarioRepository, where: str, index: str) -> None:
    entity_id, first = _mixed_entity(scenarios)
    chosen = {
        "entity": {"entity_id": entity_id},
        "entity_accepted": {"entity_id": entity_id, "decision": Decision.ACCEPTED},
        "session": {"session_id": first},
    }[where]
    asked: list[list[dict[str, Any]]] = []
    spy = copy.copy(scenarios)  # the instance's named conditions, on a collection that records the pipeline
    spy._collection = SimpleNamespace(aggregate=lambda pipeline: asked.append(pipeline) or iter([]))
    spy.count_current_scenarios(**chosen)
    command = {"aggregate": Collection.SCENARIOS, "pipeline": asked[0], "cursor": {}}
    explained = get_mongodb().command("explain", command, verbosity="queryPlanner")
    planner = explained.get("queryPlanner") or explained["stages"][0]["$cursor"]["queryPlanner"]
    winning = json.dumps(planner["winningPlan"])
    assert index in winning and '"FETCH"' not in winning


def test_a_full_page_takes_its_total_from_the_covered_count(scenarios: ThreatScenarioRepository) -> None:
    entity_id, _ = _mixed_entity(scenarios)
    counted: list[dict[str, Any]] = []
    spy = copy.copy(scenarios)
    spy.count = lambda **where: counted.append(where) or 0  # type: ignore[method-assign]
    owner = SimpleNamespace(_scenarios=spy)
    records, total = ThreatScenarioService._scenario_page(owner, "-created_at", 0, 1, entity_id=entity_id)  # type: ignore[arg-type]
    assert (len(records), total, counted) == (1, 7, [])
