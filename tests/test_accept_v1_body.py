"""Accept also takes TSG v1's body (`mode` all / subset / none) and answers it as today's body; runs and
scenarios are written straight into the test MongoDB (tests/test_review's helpers)."""

import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app import container
from app.core.constants import (
    AuditAction,
    ConflictReason,
    Decision,
    ReviewMessage,
    Status,
    Step,
    TargetProblem,
)
from app.models.scenario.views import AcceptRequest
from tests.test_review import PUBLISHED, _audits, _decision, _post, _run, _scenario, service  # noqa: F401

IDS_ONLY_WITH_SUBSET = ReviewMessage.ONLY_WITH_SUBSET.format(field="scenario_ids")
REPLACE_ONLY_WITH_SUBSET = ReviewMessage.ONLY_WITH_SUBSET.format(field="replace_accepted")


@pytest.fixture(scope="module")
def api_key() -> str:
    _, key = container.get_admin_service().create_api_client(
        f"accept-v1-{uuid.uuid4().hex[:8]}", None, "test"
    )
    return key


@pytest.mark.usefixtures("service")
def test_mode_all_accepts_what_scenario_ids_all_accepts(client: TestClient, api_key: str) -> None:
    """`{"mode": "all"}` takes every acceptable scenario, skips what "all" skips, and gives the v2 answer."""
    record_id = _run()
    first, second = _scenario(record_id, "p1"), _scenario(record_id, "p2")
    rejected = _scenario(record_id, "p3", decision=Decision.REJECTED)
    newer = _scenario(record_id, "p4", version=2)
    _scenario(record_id, "p4", decision=Decision.ACCEPTED, superseded_by=newer)
    url = f"/v1/sessions/{record_id}/accept"
    answer = _post(client, api_key, url, {"mode": "all"})
    assert answer.status_code == 200, answer.text
    body = answer.json()
    assert sorted(body["accepted"]) == sorted([first, second]) and body["replaced"] == []
    assert body["skipped"] == [{"scenario_id": newer, "reason": TargetProblem.DUPLICATE_VERSION}]
    assert (_decision(first), _decision(second), _decision(rejected)) == (
        Decision.ACCEPTED,
        Decision.ACCEPTED,
        Decision.REJECTED,
    )
    assert _post(client, api_key, url, {"scenario_ids": "all"}).json() == body


@pytest.mark.usefixtures("service")
def test_mode_subset_accepts_the_ids_and_replace_accepted_moves_the_accepted_version(
    client: TestClient, api_key: str
) -> None:
    """`subset` accepts only the ids sent; with `replace_accepted: true` a newer version replaces the old."""
    record_id = _run()
    chosen, left = _scenario(record_id, "p1"), _scenario(record_id, "p2")
    url = f"/v1/sessions/{record_id}/accept"
    answer = _post(client, api_key, url, {"mode": "subset", "scenario_ids": [chosen]})
    assert (answer.status_code, answer.json()["accepted"]) == (200, [chosen]), answer.text
    assert (_decision(chosen), _decision(left)) == (Decision.ACCEPTED, Decision.PENDING)
    newer = _scenario(record_id, "p3", version=2)
    older = _scenario(record_id, "p3", decision=Decision.ACCEPTED, superseded_by=newer)
    refused = _post(client, api_key, url, {"mode": "subset", "scenario_ids": [newer]})
    assert (refused.status_code, refused.json()["reason"]) == (409, ConflictReason.DUPLICATE_VERSION)
    body = {"mode": "subset", "scenario_ids": [newer], "replace_accepted": True}
    replaced = _post(client, api_key, url, body).json()
    assert (replaced["accepted"], replaced["replaced"]) == ([newer], [older])
    assert (_decision(newer), _decision(older)) == (Decision.ACCEPTED, Decision.PENDING)


@pytest.mark.usefixtures("service")
def test_mode_none_decides_nothing_and_writes_nothing(client: TestClient, api_key: str) -> None:
    """`{"mode": "none"}`: 200 with four empty lists, every scenario pending, no audit, no live update; a run
    still generating is refused as for any accept."""
    record_id = _run()
    scenario_ids = [_scenario(record_id, "p1"), _scenario(record_id, "p2")]
    PUBLISHED.clear()
    answer = _post(client, api_key, f"/v1/sessions/{record_id}/accept", {"mode": "none"})
    assert (answer.status_code, answer.json()) == (
        200,
        {"accepted": [], "replaced": [], "skipped": [], "controls_pending": []},
    )
    assert [_decision(scenario_id) for scenario_id in scenario_ids] == [Decision.PENDING, Decision.PENDING]
    assert _audits(record_id, AuditAction.SCENARIOS_ACCEPTED) == [] and PUBLISHED == []
    busy = _post(
        client, api_key, f"/v1/sessions/{_run(Status.RUNNING, Step.SCENARIOS)}/accept", {"mode": "none"}
    )
    assert (busy.status_code, busy.json()["reason"]) == (409, ConflictReason.GENERATION_IN_PROGRESS)


@pytest.mark.usefixtures("service")
@pytest.mark.parametrize(
    ("body", "field", "message"),
    [
        ({"mode": "subset"}, "scenario_ids", ReviewMessage.SUBSET_NEEDS_IDS),
        ({"mode": "subset", "scenario_ids": "all"}, "scenario_ids", ReviewMessage.SUBSET_NEEDS_IDS),
        ({"mode": "all", "scenario_ids": ["s1"]}, "scenario_ids", IDS_ONLY_WITH_SUBSET),
        ({"mode": "none", "scenario_ids": "all"}, "scenario_ids", IDS_ONLY_WITH_SUBSET),
        ({"mode": "all", "replace_accepted": True}, "replace_accepted", REPLACE_ONLY_WITH_SUBSET),
        ({"mode": "none", "replace_accepted": True}, "replace_accepted", REPLACE_ONLY_WITH_SUBSET),
        ({"mode": "some", "scenario_ids": ["s1"]}, "mode", "Input should be 'all', 'subset' or 'none'"),
        ({"mode": None, "scenario_ids": ["s1"]}, "mode", ReviewMessage.MODE_VALUES),
        ({"replace_accepted": True}, "scenario_ids", "Field required"),
    ],
)
def test_a_body_breaking_a_mode_rule_is_refused_on_its_field(
    client: TestClient, api_key: str, body: dict[str, Any], field: str, message: str
) -> None:
    """v1's rules (ids and replace_accepted only with subset, subset needs a list) and the v2 body without
    `scenario_ids`: 422 naming the field, nothing decided."""
    record_id = _run()
    scenario_id = _scenario(record_id, "p1")
    answer = _post(client, api_key, f"/v1/sessions/{record_id}/accept", body)
    assert answer.status_code == 422, answer.text
    assert answer.json()["errors"] == [{"field": f"body.{field}", "message": message}]
    assert _decision(scenario_id) == Decision.PENDING


def test_swagger_says_when_mode_and_scenario_ids_are_sent() -> None:
    """The schema names the `mode` values and when `scenario_ids` is sent, as v1's Swagger did."""
    fields = AcceptRequest.model_json_schema()["properties"]
    assert all(f"{mode}: accept" in fields["mode"]["description"] for mode in ("all", "subset", "none"))
    assert "With mode subset: the ids to accept" in fields["scenario_ids"]["description"]
    assert "Without mode (the v2 body): required" in fields["scenario_ids"]["description"]


def test_swagger_offers_every_body_with_the_v1_format_first(client: TestClient) -> None:
    """Swagger's example list on accept starts with v1's bodies, then the v2 ones, and each one validates."""
    accept = client.get("/openapi.json").json()["paths"]["/v1/sessions/{session_id}/accept"]["post"]
    examples = list(accept["requestBody"]["content"]["application/json"]["examples"].values())
    assert examples[0]["value"] == {"mode": "subset", "scenario_ids": examples[0]["value"]["scenario_ids"]}
    assert [("mode" in example["value"]) for example in examples] == [True] * 4 + [False] * 2
    for example in examples:
        AcceptRequest.model_validate(example["value"])
