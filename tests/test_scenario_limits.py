"""The owner's two limits: TOTAL_SCENARIO_COUNT (0 = every valid path) and
MAX_SUPPORTING_SYSTEMS (0 = no upper limit)."""

import pytest
from pydantic import ValidationError

from app.core.config import get_settings
from app.core.constants import Generation, Limits, SessionMessage, UnselectedReason
from app.domain.scenario.plan import select_up_to_target
from app.models.scenario.views import StartRunRequest


def _paths(count: int) -> list[dict]:
    """`count` valid paths, deliberately out of rank order (the target must sort them)."""
    return [{"path_id": f"p{rank}", "rank": rank} for rank in reversed(range(1, count + 1))]


def _selected(paths: list[dict]) -> list[str]:
    return [path["path_id"] for path in paths if path["selected"]]


def test_both_limits_are_zero_or_a_positive_number() -> None:
    assert get_settings().total_scenario_count >= 0
    assert Generation.MAX_SUPPORTING_SYSTEMS >= 0


def test_target_zero_writes_every_valid_path() -> None:
    every_path = [f"p{rank}" for rank in range(1, 8)]
    assert _selected(select_up_to_target(_paths(7), max_scenarios=0)) == every_path


def test_a_positive_target_keeps_the_most_relevant_and_sets_the_rest_aside() -> None:
    planned = select_up_to_target(_paths(7), max_scenarios=3)
    assert _selected(planned) == ["p1", "p2", "p3"]
    set_aside = [path for path in planned if not path["selected"]]
    # kept in the plan, in rank order
    assert [path["path_id"] for path in set_aside] == ["p4", "p5", "p6", "p7"]
    assert {path["unselected_reason"] for path in set_aside} == {UnselectedReason.TARGET_REACHED}


def test_fewer_paths_than_the_target_are_all_written_and_none_invented() -> None:
    planned = select_up_to_target(_paths(4), max_scenarios=15)
    assert len(planned) == 4
    assert _selected(planned) == ["p1", "p2", "p3", "p4"]


def _start(system_ids: object) -> StartRunRequest:
    return StartRunRequest.model_validate({"asset_id": 103, "supporting_system_ids": system_ids})


def test_systems_limit_zero_accepts_any_number(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Generation, "MAX_SUPPORTING_SYSTEMS", 0)
    assert len(_start(list(range(1, 201))).supporting_system_ids) == 200


def test_a_positive_systems_limit_refuses_one_more(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Generation, "MAX_SUPPORTING_SYSTEMS", 2)
    assert _start([321, 322]).supporting_system_ids == [321, 322]
    with pytest.raises(ValidationError, match=SessionMessage.TOO_MANY_SYSTEMS.format(limit=2)):
        _start([321, 322, 323])


@pytest.mark.parametrize(
    ("system_ids", "message"),
    [([], SessionMessage.SYSTEMS_REQUIRED), ([321, 321], SessionMessage.SYSTEMS_REPEATED)],
)
def test_systems_must_be_sent_and_each_only_once(system_ids: list[int], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        _start(system_ids)


def test_a_single_system_id_is_accepted_as_a_list_of_one() -> None:
    assert _start(321).supporting_system_ids == [321]


@pytest.mark.parametrize(
    "body",
    [
        {"asset_id": Limits.MAX_SQL_INT + 1, "supporting_system_ids": [1]},
        {"asset_id": 1, "supporting_system_ids": [Limits.MAX_SQL_INT + 1]},
        {"asset_id": 1, "supporting_system_ids": [1], "sector_id": Limits.MAX_SQL_INT + 1},
    ],
)
def test_an_id_too_large_for_sql_server_is_refused_here(body: dict) -> None:
    """Before: 3,000,000,000 passed and failed inside the stored procedure as a 500 (bigint to int)."""
    with pytest.raises(ValidationError):
        StartRunRequest.model_validate(body)
