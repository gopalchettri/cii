"""The AI usage reports on the Swagger page (/docs), so a developer can use them from there alone (owner,
2026-10-30): each report says what it is for and explains every parameter; module, API call, part, task and
group are picked from lists; the module and API table is the catalogue's; every example answer is a report its
route really gives; and every error example is what the API really answers. Each test names the mutation it
catches."""

import json
import re
from typing import Any

import pytest
from fastapi.encoders import jsonable_encoder
from fastapi.testclient import TestClient
from pydantic import BaseModel
from pymongo.errors import ServerSelectionTimeoutError

from app.api.openapi_ai_usage import ERROR_EXAMPLES, EXAMPLE_ANSWERS, EXAMPLES, route_of
from app.api.routers import ai_usage as ai_usage_routes
from app.core.constants import API_INFO, AiApi, AiBucket, AiTask, AiUsageGroup, ApiTag, Module, Problem
from app.main import create_app
from app.models.ai_usage.usage_report import (
    RequestUsageDetail,
    RequestUsageList,
    UsageCallList,
    UsageTotals,
)
from app.services.ai_usage.ai_usage_service import AiUsageService
from tests.test_ai_usage_report import _NoPlace

#: Each report: its route, and the shape its example answers must have.
REPORTS: dict[str, tuple[str, type[BaseModel]]] = {
    "totals": ("/v1/ai-usage", UsageTotals),
    "requests": ("/v1/ai-usage/requests", RequestUsageList),
    "request": ("/v1/ai-usage/requests/{request_id}", RequestUsageDetail),
    "calls": ("/v1/ai-usage/calls", UsageCallList),
}


@pytest.fixture(scope="module")
def document() -> dict[str, Any]:
    return create_app().openapi()


def _operation(document: dict[str, Any], path: str) -> dict[str, Any]:
    return document["paths"][path]["get"]


def _problem_examples(operation: dict[str, Any], status: str) -> dict[str, Any]:
    named = operation["responses"][status]["content"][Problem.MEDIA_TYPE]["examples"]
    return {name: example["value"] for name, example in named.items()}


def _same_problem(answer: dict[str, Any], documented: dict[str, Any]) -> bool:
    """The same answer but for its request id (each call has its own)."""
    return {**answer, "request_id": None} == {**json.loads(json.dumps(documented)), "request_id": None}


def test_every_report_says_what_it_is_for_and_explains_every_parameter(document: dict) -> None:
    """Mutation: drop a route's description, or a parameter's."""
    for path, _shape in REPORTS.values():
        operation = _operation(document, path)
        assert operation["summary"] and "**Use it for**" in operation["description"], path
        unexplained = [p["name"] for p in operation["parameters"] if len(p.get("description", "")) < 20]
        assert unexplained == [], path


@pytest.mark.parametrize(
    ("path", "name", "values"),
    [
        ("/v1/ai-usage", "module", Module),
        ("/v1/ai-usage", "api", AiApi),
        ("/v1/ai-usage", "bucket", AiBucket),
        ("/v1/ai-usage", "task", AiTask),
        ("/v1/ai-usage", "group_by", AiUsageGroup),
        ("/v1/ai-usage/requests", "module", Module),
        ("/v1/ai-usage/requests", "api", AiApi),
    ],
)
def test_module_api_part_task_and_group_are_picked_from_lists(
    document: dict, path: str, name: str, values: type
) -> None:
    """Mutation: take one back as free text (a typo then gave an empty report, with no warning)."""
    parameter = next(p for p in _operation(document, path)["parameters"] if p["name"] == name)
    ref = re.search(r'"#/components/schemas/(\w+)"', json.dumps(parameter["schema"]))
    assert ref, f"{name} is free text"
    assert document["components"]["schemas"][ref.group(1)]["enum"] == [value.value for value in values]


def test_the_group_lists_each_module_with_its_api_calls_as_the_catalogue_does(document: dict) -> None:
    """Mutation: leave a row out of the module and API table."""
    group = next(tag["description"] for tag in document["tags"] if tag["name"] == ApiTag.AI_USAGE)
    assert re.findall(r"^\| `(\w+)` \| `(\w+)` \|", group, re.MULTILINE) == list(API_INFO)


def test_every_example_answer_is_a_report_its_route_gives(document: dict) -> None:
    """Mutation: rename, add or drop a field in an example answer, label it with a call to another report,
    or leave one off its route."""
    for report, (path, shape) in REPORTS.items():
        for name, example in EXAMPLES[report].items():
            answer = example["answer"]
            assert shape.model_validate(answer).model_dump(mode="json") == answer, (report, name)
            assert route_of(example["call"]) == path, (report, name)
        shown = _operation(document, path)["responses"]["200"]["content"]["application/json"]["examples"]
        # FastAPI leaves every null out of the OpenAPI document
        expected = jsonable_encoder(EXAMPLE_ANSWERS[report], exclude_none=True)
        assert {name: example["value"] for name, example in shown.items()} == expected


@pytest.mark.parametrize("name", sorted(ERROR_EXAMPLES))
def test_every_error_example_is_what_the_api_answers(client: TestClient, document: dict, name: str) -> None:
    """Mutations: change an error example's detail; let a module or API call not in the list through; allow
    `limit=0` on one route only."""
    _summary, call, documented = ERROR_EXAMPLES[name]
    response = client.get(call)
    assert response.headers["content-type"] == Problem.MEDIA_TYPE
    assert _same_problem(response.json(), documented), response.json()
    shown = _problem_examples(_operation(document, route_of(call)), str(response.status_code))
    assert shown[name] == json.loads(json.dumps(documented))


def test_every_report_shows_the_errors_this_api_sends_never_fastapis_shape(document: dict) -> None:
    """Mutation: drop a route's 422 examples (Swagger then shows FastAPI's HTTPValidationError, which this API
    never sends: every error is a problem body)."""
    for path, _shape in REPORTS.values():
        responses = _operation(document, path)["responses"]
        assert "422" in responses and "503" in responses, path
        for status, answer in responses.items():
            if status != "200":
                assert list(answer["content"]) == [Problem.MEDIA_TYPE], (path, status)


def test_every_try_it_call_works(client: TestClient, document: dict) -> None:
    """Mutations: a "Try it" call with a value outside its list (`group_by=models`), or a bad time zone; an id
    typed by hand that the example answers do not hold. Report 3's example request has no AI calls in the
    test database: it answers 404 there, 200 where it ran."""
    example_ids = set(re.findall(r"[0-9a-f]{32}", json.dumps(EXAMPLES)))
    for path, _shape in REPORTS.values():
        calls = re.findall(r"`GET (/v1/ai-usage[^`]*)`", _operation(document, path)["description"])
        assert calls, path
        for call in calls:
            assert route_of(call) == path, call
            assert set(re.findall(r"[0-9a-f]{32}", call)) <= example_ids, call
            status = client.get(call).status_code
            assert status == 200 or (status == 404 and path == REPORTS["request"][0]), (call, status)


def test_the_busy_example_is_what_a_busy_report_answers(
    client: TestClient, document: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Mutation: change the busy example's detail."""
    monkeypatch.setattr(ai_usage_routes, "_KEPT_REPORTS", _NoPlace())
    response = client.get("/v1/ai-usage")
    busy = _problem_examples(_operation(document, "/v1/ai-usage"), "503")["busy"]
    assert response.status_code == 503 and response.headers.get("Retry-After")
    assert _same_problem(response.json(), busy)


def test_the_database_example_is_what_a_report_answers_with_mongodb_down(
    client: TestClient, document: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Mutation: change the database example's detail."""

    def mongodb_down(*_args: Any) -> dict[str, Any]:
        raise ServerSelectionTimeoutError("no server")

    monkeypatch.setattr(AiUsageService, "list_ai_usage_calls", mongodb_down)
    response = client.get("/v1/ai-usage/calls", params={"request_id": "any"})
    database = _problem_examples(_operation(document, "/v1/ai-usage/calls"), "503")["database"]
    assert response.status_code == 503 and _same_problem(response.json(), database)
