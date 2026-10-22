"""Service Mapper's catalog, reconciliation, scoped lifecycle and review contract."""

import json
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import numpy as np
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app import container
from app.ai.chat import TruncatedAiAnswer
from app.core.constants import (
    AiOutage,
    AuditAction,
    Collection,
    MapperDecisionFailure,
    MapperMessage,
    MappingOverall,
    Status,
    TaskName,
)
from app.core.database import get_mongodb
from app.core.exceptions import JobFailed
from app.data_access.admin.audit_repository import AuditRepository
from app.data_access.service_mapper.mapping_repository import MappingHistoryRepository, MappingRepository
from app.domain.service_mapper import generate
from app.domain.service_mapper.answer_checks import answer_problems
from app.domain.service_mapper.catalog import build_catalog
from app.domain.service_mapper.generate import generate_result
from app.domain.service_mapper.reconcile import reconcile
from app.domain.service_mapper.views import approved_relationships, pending_relationships
from app.models.admin.api_clients import Principal
from app.models.service_mapper.catalog import CatalogRows, CatalogService, CatalogSnapshot, SectorAssociation
from app.models.service_mapper.contract import CreateMappingRequest, DependencyDecisionRequest
from app.models.service_mapper.generation import GeneratedAnswer, ProposedDependency
from app.search.service_mapper import ServiceCandidateSearch
from app.services.service_mapper.service_mapper_service import ServiceMapperService
from app.worker.service_mapper.job import ServiceMapperJob
from tests.conftest import ADMIN


def _request() -> CreateMappingRequest:
    return CreateMappingRequest(
        service_name="Power Generation System",
        service_description="Generates and dispatches electricity to the transmission grid.",
        sector="Energy",
        subsector="Power",
        entity_names=["Example Utility"],
    )


def _catalog():
    return build_catalog(
        CatalogRows(
            sector_summary=[{"SectorName": "Energy"}, {"SectorName": "Water"}],
            service_mappings=[
                {
                    "service_id": 1,
                    "service_name": "Power Generation System",
                    "sector_id": 10,
                    "sector_name": "Energy",
                },
                {
                    "service_id": 2,
                    "service_name": "Water Treatment Service",
                    "sector_id": 20,
                    "sector_name": "Water",
                },
            ],
            services=[
                {
                    "service_id": 1,
                    "service_name": "Power Generation System",
                    "service_description": "Generates electricity.",
                },
                {
                    "service_id": 2,
                    "service_name": "Water Treatment Service",
                    "service_description": "Supplies treated cooling water.",
                },
            ],
            sectors=[
                {"sector_id": 10, "sector_name": "Energy", "parent_sector_id": None},
                {"sector_id": 11, "sector_name": "Power", "parent_sector_id": 10},
                {"sector_id": 20, "sector_name": "Water", "parent_sector_id": None},
            ],
            sector_links=[
                {"service_id": 1, "sector_id": 11},
                {"service_id": 2, "sector_id": 20},
            ],
            entity_links=[
                {"service_id": 2, "sector_id": 20, "entity_id": 86, "entity_name": "Example Utility"},
            ],
        )
    )


def _item(name: str, reason: str, sector: str | None = None, subsector: str | None = None) -> dict[str, Any]:
    return {"service_name": name, "sector": sector, "subsector": subsector, "dependency_reason": reason}


def _answer() -> GeneratedAnswer:
    reason = "It directly supplies treated cooling water needed by the generation process."
    return GeneratedAnswer.model_validate(
        {
            "operational_context": "The plant converts primary energy into electricity for grid delivery.",
            "upstream_services": [
                _item("Water Treatment Service", reason),
                _item("Water Treatment Service", reason),
                _item(
                    "Fuel Logistics Service",
                    "It delivers fuel directly to the plant for generation.",
                    "Energy",
                ),
                _item("Electricity", "A one-word resource is too vague to present as a service."),
                _item("Power Generation System", "The selected service cannot depend directly on itself."),
            ],
            "downstream_services": [
                _item(
                    "Water Treatment Service", "It directly consumes plant electricity to run water pumps."
                ),
                _item(
                    "Grid Balancing Service", "It directly takes the plant's generation output for balancing."
                ),
            ],
        }
    )


def test_reconciliation_deduplicates_and_drops_the_selected_service_and_vague_names() -> None:
    result = reconcile("mapping", 1, _request(), _answer(), _catalog(), 2, 2)
    assert result["selected_service"]["service_id"] == 1
    assert result["summary"]["upstream_count"] == 2
    assert result["summary"]["downstream_count"] == 1
    assert result["summary"]["unique_services"] == 3
    water = next(item for item in result["dependencies"] if item["service_id"] == 2)
    assert water["sector"] == "Water" and water["ai_suggested"] is False
    assert set(water["relations"]) == {"upstream"}  # in both lists at the same rank: upstream wins the tie
    assert all(item["service_name"] != "Electricity" for item in result["dependencies"])
    assert len({item["dependency_id"] for item in result["dependencies"]}) == 3


def test_every_dropped_item_is_named_with_why_for_the_re_ask() -> None:
    problems = answer_problems(_request(), _answer(), _catalog())
    assert problems == [
        'upstream_services: "Water Treatment Service" is listed twice',
        'upstream_services: "Electricity" is too vague: name the specific service in at least two words '
        "(a new name is fine when no catalog service provides it)",
        'upstream_services: "Power Generation System" is the selected service itself',
        '"Water Treatment Service" is in both lists: keep it only in its strongest direction',
        '"Grid Balancing Service" needs a sector from catalog',
    ]


def test_a_sector_name_is_not_taken_as_a_service() -> None:
    answer = GeneratedAnswer.model_validate(
        {
            "operational_context": "The plant generates electricity for delivery to the grid.",
            "upstream_services": [_item("Water", "A sector name is not the name of a service.")],
            "downstream_services": [],
        }
    )
    assert answer_problems(_request(), answer, _catalog()) == [
        'upstream_services: "Water" is a sector or subsector name, not a service: name the service'
    ]


def test_a_new_service_like_a_catalog_one_is_asked_to_use_it_and_a_merely_related_one_is_not() -> None:
    """Owner 2026-10-22: a service already in the database is never identified anew by the AI."""
    water = SectorAssociation(10, "Energy", 12, "Water")
    media = SectorAssociation(30, "ICT", 31, "Media")
    catalog = CatalogSnapshot(
        "duplicates",
        ("Energy", "ICT"),
        (water, media),
        (
            CatalogService(3, "Water Production & Transmission", "", (water,), (), "", ""),
            CatalogService(5, "Broadcasting and Public Media Operations", "", (media,), (), "", ""),
        ),
    )
    reason = "It supplies the cooling water the plant cannot run without."
    answer = GeneratedAnswer.model_validate(
        {
            "operational_context": "The plant generates electricity for delivery to the grid.",
            "upstream_services": [
                _item("Water Supply and Distribution", reason, "Energy", "Water"),
                _item("Telecommunications Network Services", reason, "ICT", "Media"),
            ],
            "downstream_services": [],
        }
    )
    assert answer_problems(_request(), answer, catalog) == [
        '"Water Supply and Distribution" is new, but catalog Energy / Water already has '
        '"Water Production & Transmission": use the one that provides it, '
        'or keep "Water Supply and Distribution" only if none does'
    ]


def test_two_catalog_services_with_one_name_are_told_apart_by_sector() -> None:
    def grid(service_id: int, sector: str) -> CatalogService:
        return CatalogService(
            service_id,
            "Grid Control Service",
            "",
            (SectorAssociation(service_id, sector, None, None),),
            (),
            "",
            "",
        )

    catalog = CatalogSnapshot("same-name", ("Energy", "Water"), (), (grid(5, "Energy"), grid(6, "Water")))
    reason = "It dispatches the plant's output to the grid directly."

    def kept(sector: str | None) -> list[int | None]:
        answer = GeneratedAnswer.model_validate(
            {
                "operational_context": "The plant generates electricity for delivery to the grid.",
                "upstream_services": [],
                "downstream_services": [_item("Grid Control Service", reason, sector)],
            }
        )
        return [
            item["service_id"]
            for item in reconcile("m", 1, _request(), answer, catalog, 5, 5)["dependencies"]
        ]

    assert kept("Water") == [6]
    assert kept(None) == []  # a shared name without its sector is never guessed


def test_a_service_in_both_lists_is_kept_only_where_the_ai_ranked_it_higher() -> None:
    answer = _answer().model_dump()
    answer["upstream_services"] = answer["upstream_services"][2:3] + answer["upstream_services"][:1]
    result = reconcile("mapping", 1, _request(), GeneratedAnswer.model_validate(answer), _catalog(), 5, 5)
    water = next(item for item in result["dependencies"] if item["service_id"] == 2)
    assert set(water["relations"]) == {"downstream"}  # first downstream, second upstream
    assert (result["summary"]["upstream_count"], result["summary"]["downstream_count"]) == (1, 2)


class _Chat:
    """The AI gateway's re-ask: a first answer the checks fault is asked again once with its problems."""

    max_prompt_chars = 200_000

    def __init__(self, *answers: dict[str, Any]) -> None:
        self.answers = list(answers)
        self.prompts: list[dict[str, Any]] = []
        self.problems: list[str] = []

    def ask_for_checked_json(self, _task, _system, prompt, check, first_answer_check):
        self.prompts.append(json.loads(prompt))
        first = self.answers.pop(0)
        assert check(first) == []
        self.problems = first_answer_check(first)
        return self.answers.pop(0) if self.problems else first


class _Search:
    def candidates(self, catalog, _queries):
        return list(catalog.services)


def test_a_short_answer_with_nothing_dropped_makes_one_ai_call() -> None:
    reason = "It directly supplies treated cooling water needed by the generation process."
    short = {
        "operational_context": "The plant converts primary energy into electricity for grid delivery.",
        "upstream_services": [_item("Water Treatment Service", reason)],
        "downstream_services": [],
    }
    chat = _Chat(short)
    result = generate_result(chat, _Search(), _request(), _catalog(), ("mapping", 1), (5, 5))  # type: ignore[arg-type]
    assert len(chat.prompts) == 1 and chat.problems == []
    assert (result["summary"]["upstream_count"], result["summary"]["downstream_count"]) == (1, 0)


def test_a_first_answer_with_dropped_items_is_asked_again_with_why() -> None:
    fixed = _answer().model_dump()
    fixed["upstream_services"] = fixed["upstream_services"][:1] + fixed["upstream_services"][2:3]
    fixed["downstream_services"] = fixed["downstream_services"][1:]
    fixed["downstream_services"][0]["sector"] = "Energy"
    chat = _Chat(_answer().model_dump(), fixed)
    result = generate_result(chat, _Search(), _request(), _catalog(), ("mapping", 1), (5, 5))  # type: ignore[arg-type]
    assert len(chat.problems) == 5
    assert answer_problems(_request(), GeneratedAnswer.model_validate(fixed), _catalog()) == []
    assert (result["summary"]["upstream_count"], result["summary"]["downstream_count"]) == (2, 1)


def test_the_prompt_sends_names_never_a_catalog_id_and_not_the_selected_service() -> None:
    chat = _Chat(_answer().model_dump(), _answer().model_dump())
    generate_result(chat, _Search(), _request(), _catalog(), ("mapping", 1), (2, 1))  # type: ignore[arg-type]
    sent = chat.prompts[0]
    assert "catalog_service_id" not in json.dumps(sent)
    assert sent["catalog"] == [  # every sector and subsector with its services, the selected one left out
        {
            "sector": "Water",
            "subsector": None,
            "services": [
                {"service_name": "Water Treatment Service", "description": "Supplies treated cooling water."}
            ],
        },
        {"sector": "Energy", "subsector": "Power", "services": []},  # empty groups last
    ]


def test_a_catalog_too_large_for_the_prompt_keeps_the_most_similar_services() -> None:
    water = SectorAssociation(20, "Water", None, None)
    services = tuple(
        CatalogService(
            number, f"Water Service {number}", "Treats and supplies water. " * 9, (water,), (), "", ""
        )
        for number in range(1, 41)
    )
    catalog = CatalogSnapshot("large", ("Water",), (water,), services)
    ranked = list(reversed(services))

    class Search:
        def candidates(self, _catalog, _queries):
            return ranked

    chat = _Chat(_answer().model_dump(), _answer().model_dump())
    chat.max_prompt_chars = 20_000
    generate_result(chat, Search(), _request(), catalog, ("mapping", 1), (2, 1))  # type: ignore[arg-type]
    sent = [service["service_name"] for service in chat.prompts[0]["catalog"][0]["services"]]
    assert 0 < len(sent) < len(services)
    assert sent == [service.service_name for service in ranked[: len(sent)]]


def test_the_prompt_names_every_input_key_and_answer_field_and_writes_no_number() -> None:
    """The system prompt and the code cannot drift apart: each key it is sent or answers is named in it."""
    chat = _Chat(_answer().model_dump(), _answer().model_dump())
    generate_result(chat, _Search(), _request(), _catalog(), ("mapping", 1), (2, 1))  # type: ignore[arg-type]
    keys = {
        *chat.prompts[0],
        *chat.prompts[0]["catalog"][0],
        "known_upstream",
        "known_downstream",
        "entity_names",
        *GeneratedAnswer.model_fields,
        *ProposedDependency.model_fields,
    }
    assert [key for key in sorted(keys) if key not in generate._SYSTEM] == []
    assert not re.search(r"\d", generate._SYSTEM)
    assert len(generate._SYSTEM) < 3_800


def test_a_truncated_ai_answer_fails_the_job_with_a_clear_message() -> None:
    class Chat:
        max_prompt_chars = 200_000

        def ask_for_checked_json(self, *_args):
            raise TruncatedAiAnswer("cut off at the length limit")

    class Catalog:
        def snapshot(self) -> CatalogSnapshot:
            return _catalog()

    job = ServiceMapperJob(None, None, Catalog(), _Search(), Chat())  # type: ignore[arg-type]
    record = {"request": _request().model_dump(), "limits": {"max_upstream": 2, "max_downstream": 2}}
    with pytest.raises(JobFailed) as failed:
        job.generate(SimpleNamespace(record=record, record_id="mapping", epoch=1))  # type: ignore[arg-type]
    assert failed.value.message == MapperMessage.AI_ANSWER_TOO_LONG


def test_empty_catalog_still_keeps_defensible_ai_services() -> None:
    empty = build_catalog(CatalogRows([], [], [], [], [], []))
    answer = _answer().model_dump()
    result = reconcile("mapping", 1, _request(), GeneratedAnswer.model_validate(answer), empty, 2, 2)
    assert {item["service_name"] for item in result["dependencies"]} == {
        "Water Treatment Service",
        "Fuel Logistics Service",
        "Grid Balancing Service",
    }
    assert all(item["ai_suggested"] and item["service_id"] is None for item in result["dependencies"])


def test_semantic_retrieval_can_find_a_cross_sector_service_without_matching_words() -> None:
    class Embeddings:
        def embed_library_texts(self, _corpus, _texts, _sources):
            return np.array([[1.0, 0.0], [0.0, 1.0]], dtype=np.float32)

        def embed_search_queries(self, _queries):
            return np.array([[0.0, 1.0]], dtype=np.float32)

    found = ServiceCandidateSearch(Embeddings()).candidates(_catalog(), ["unrelated vocabulary"])
    assert found[0].service_name == "Water Treatment Service"
    assert found[0].primary_sector.sector_name == "Water"


def test_shared_catalog_alias_is_not_misreported_as_an_out_of_catalog_service() -> None:
    catalog = CatalogSnapshot(
        "alias-test",
        (),
        (),
        (
            CatalogService(7, "Power Management Service (PMS)", "", (), (), "", ""),
            CatalogService(8, "Plant Monitoring Service (PMS)", "", (), (), "", ""),
        ),
    )
    answer = GeneratedAnswer.model_validate(
        {
            "operational_context": "The selected service generates electricity for grid delivery.",
            "upstream_services": [_item("PMS", "It provides monitoring directly to the generation process.")],
            "downstream_services": [],
        }
    )
    result = reconcile("mapping", 1, _request(), answer, catalog, 20, 20)
    assert result["dependencies"] == []


def test_parallel_idempotent_starts_create_and_send_only_one_job(empty_test_database: None) -> None:
    sent: list[tuple[TaskName, str, int]] = []
    mapper = ServiceMapperService(
        MappingRepository(),
        MappingHistoryRepository(),
        container.get_settings(),
        lambda *args: sent.append(args),
        None,
        AuditRepository(),
        lambda _mapping_id: None,
    )
    principal = Principal("client", "reviewer", 86, "tenant-a")
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(lambda _: mapper.create_service_mapping(principal, _request(), "one-key"), range(2))
        )
    assert results[0][0].mapping_id == results[1][0].mapping_id
    assert sorted(created for _, created in results) == [False, True]
    assert len(sent) == 1


def test_mapper_api_scopes_records_and_stamps_each_direction(client: TestClient) -> None:
    sent: list[tuple[TaskName, str, int]] = []
    published: list[str] = []

    class Catalog:
        def load(self) -> CatalogRows:
            snapshot = _catalog()
            assert snapshot.services
            return CatalogRows(
                [{"SectorName": "Energy"}, {"SectorName": "Water"}],
                [],
                [{"service_id": 2, "service_name": "Water Treatment Service"}],
                [
                    {"sector_id": 10, "sector_name": "Energy", "parent_sector_id": None},
                    {"sector_id": 20, "sector_name": "Water", "parent_sector_id": None},
                ],
                [{"service_id": 2, "sector_id": 20}],
                [{"service_id": 2, "sector_id": 20, "entity_id": 86, "entity_name": "Example Utility"}],
            )

    mapper = ServiceMapperService(
        MappingRepository(),
        MappingHistoryRepository(),
        container.get_settings(),
        lambda task, mapping_id, generation: sent.append((task, mapping_id, generation)),
        Catalog(),
        AuditRepository(),
        published.append,
    )
    client.app.dependency_overrides[container.get_service_mapper_service] = lambda: mapper
    try:
        minted = client.post(
            "/v1/tsg/api-clients",
            json={"name": "service-mapper-test"},
            headers=ADMIN | {"X-User-Id": "admin"},
        ).json()
        headers = {
            "X-API-Key": minted["api_key"],
            "X-User-Id": "reviewer-1",
            "X-Entity-Id": "86",
            "X-Tenant-Id": "tenant-a",
            "Idempotency-Key": "create-a",
        }
        created = client.post("/v1/service-mapper", json=_request().model_dump(), headers=headers)
        assert created.status_code == 202, created.text
        mapping_id = created.json()["mapping_id"]
        assert sent == [(TaskName.MAP_SERVICES, mapping_id, 1)]
        replayed = client.post("/v1/service-mapper", json=_request().model_dump(), headers=headers)
        assert replayed.status_code == 200
        assert replayed.json() == created.json()
        assert len(sent) == 1
        assert client.get(f"/v1/service-mapper/{mapping_id}", headers=headers).json()["status"] == "queued"
        status_path = f"/v1/service-mapper/{mapping_id}/status"
        status = client.get(status_path, headers=headers)
        assert status.status_code == 200 and status.json()["progress"]["overall"] == "generating"
        assert client.get(status_path, headers=headers | {"X-Entity-Id": "87"}).status_code == 403
        assert client.get(f"/v1/service-mapper/{uuid4().hex}/status", headers=headers).status_code == 404
        listed = client.get("/v1/entities/86/services", headers=headers)
        assert listed.status_code == 200 and listed.json()["services"][0]["service_id"] == 2
        assert client.get("/v1/entities/87/services", headers=headers).status_code == 403
        assert (
            client.get(
                f"/v1/service-mapper/{mapping_id}", headers=headers | {"X-Entity-Id": "87"}
            ).status_code
            == 403
        )

        result = reconcile(mapping_id, 1, _request(), _answer(), _catalog(), 2, 2)
        get_mongodb()[Collection.SERVICE_MAPPINGS].update_one(
            {"_id": mapping_id},
            {"$set": {"status": Status.DONE, "result": result, "updated_at": datetime.now(UTC)}},
        )
        water = next(item for item in result["dependencies"] if item["service_id"] == 2)
        path, water_id = f"/v1/service-mapper/{mapping_id}/dependencies/decision", water["dependency_id"]
        decided = client.post(path, json={"accept": [water_id], "reject": [""]}, headers=headers)
        assert decided.status_code == 200, decided.text
        relation = decided.json()["upstream_services"][0]
        assert relation["isAccepted"] is True
        assert relation["accepted_by"] == "reviewer-1" and relation["accepted_datetime"]
        assert decided.json()["downstream_services"][0]["isAccepted"] is None
        assert decided.json()["failed"] == []
        assert "bidirectional_services" not in decided.json()  # one direction per service
        reversal = client.post(path, json={"accept": None, "reject": [water_id]}, headers=headers)
        assert reversal.status_code == 200, reversal.text
        assert [failure["reason"] for failure in reversal.json()["failed"]] == ["decision_final"]
        assert reversal.json()["upstream_services"][0]["isAccepted"] is True  # unchanged
        assert client.post(path, json={"accept": [""], "reject": [""]}, headers=headers).status_code == 422
        whole_path = f"/v1/service-mapper/{mapping_id}/decision"  # no review of the whole mapping any more
        whole = client.post(whole_path, json={"action": "accept"}, headers=headers)
        assert whole.status_code in (404, 405)
        regenerated = client.post(
            f"/v1/service-mapper/{mapping_id}/regenerate",
            headers=headers | {"Idempotency-Key": "regen-a"},
        )
        assert regenerated.status_code == 202, regenerated.text
        assert regenerated.json()["generation"] == 2
        regen_replay = client.post(
            f"/v1/service-mapper/{mapping_id}/regenerate",
            headers=headers | {"Idempotency-Key": "regen-a"},
        )
        assert regen_replay.status_code == 200 and regen_replay.json() == regenerated.json()
        archived = get_mongodb()[Collection.SERVICE_MAPPING_HISTORY].find_one({"mapping_id": mapping_id})
        assert archived["generation"] == 1 and archived["result"] is not None
        assert published == [mapping_id] * 3
        assert get_mongodb()[Collection.AUDIT].count_documents({"target.id": mapping_id}) == 3
    finally:
        client.app.dependency_overrides.clear()


PRINCIPAL = Principal("client", "reviewer", 86, "tenant-a")


def _finished_mapping() -> tuple[ServiceMapperService, str, list[dict[str, str]]]:
    """A mapping whose first generation finished, and its relationships (all still undecided)."""
    mapper = ServiceMapperService(
        MappingRepository(),
        MappingHistoryRepository(),
        container.get_settings(),
        lambda *args: None,
        None,
        AuditRepository(),
        lambda _mapping_id: None,
    )
    started, _ = mapper.create_service_mapping(PRINCIPAL, _request(), uuid4().hex)
    result = reconcile(started.mapping_id, 1, _request(), _answer(), _catalog(), 20, 20)
    get_mongodb()[Collection.SERVICE_MAPPINGS].update_one(
        {"_id": started.mapping_id}, {"$set": {"status": Status.DONE, "result": result}}
    )
    return mapper, started.mapping_id, pending_relationships(result)


def _decide(mapper: ServiceMapperService, mapping_id: str, relation: dict[str, str], accept: bool = True):
    ids = [relation["dependency_id"]]
    body = DependencyDecisionRequest(accept=ids) if accept else DependencyDecisionRequest(reject=ids)
    return mapper.decide_dependencies(PRINCIPAL, mapping_id, body)


def _record(mapping_id: str) -> dict:
    return get_mongodb()[Collection.SERVICE_MAPPINGS].find_one({"_id": mapping_id})


def test_a_mapping_waiting_out_an_ai_outage_says_so_and_a_failed_one_names_the_outage(
    empty_test_database: None,
) -> None:
    """Owner 2026-10-20: the status and the mapping show the retry notice while the job waits, and once it
    failed, which AI outage it was."""
    mapper, mapping_id, _ = _finished_mapping()
    mappings = get_mongodb()[Collection.SERVICE_MAPPINGS]
    notice = {
        "reason": AiOutage.BUSY,
        "message": "The AI service is busy: overloaded or too many requests right now.",
        "attempt": 2,
        "max_attempts": 5,
        "retry_at": datetime.now(UTC),
    }
    mappings.update_one({"_id": mapping_id}, {"$set": {"status": Status.QUEUED, "job.retry": notice}})
    for shown in (
        mapper.get_service_mapping_status(PRINCIPAL, mapping_id),
        mapper.get_service_mapping(PRINCIPAL, mapping_id),
    ):
        assert shown.retrying is not None and (shown.retrying.reason, shown.retrying.attempt) == (
            AiOutage.BUSY,
            2,
        )
    error = {"code": "unavailable", "message": "The AI service is down.", "reason": AiOutage.DOWN}
    mappings.update_one(
        {"_id": mapping_id}, {"$set": {"status": Status.FAILED, "job.error": error, "job.retry": None}}
    )
    status = mapper.get_service_mapping_status(PRINCIPAL, mapping_id)
    view = mapper.get_service_mapping(PRINCIPAL, mapping_id)
    assert status.retrying is None and view.retrying is None
    assert status.error is not None and view.error is not None
    assert status.error.reason == view.error.reason == AiOutage.DOWN


def test_the_status_says_where_the_generation_is_and_counts_the_decisions(empty_test_database: None) -> None:
    mapper, mapping_id, relations = _finished_mapping()

    def shown() -> tuple[MappingOverall, tuple[int, int, int, int]]:
        status = mapper.get_service_mapping_status(PRINCIPAL, mapping_id)
        counts = status.progress.relationships
        return status.progress.overall, (counts.total, counts.accepted, counts.rejected, counts.pending)

    assert shown() == (MappingOverall.DONE, (3, 0, 0, 3))
    _decide(mapper, mapping_id, relations[0])
    _decide(mapper, mapping_id, relations[1], accept=False)
    assert shown() == (MappingOverall.DONE, (3, 1, 1, 1))
    status = mapper.get_service_mapping_status(PRINCIPAL, mapping_id)
    assert (status.entity_id, status.user_id) == (86, "reviewer")
    mappings = get_mongodb()[Collection.SERVICE_MAPPINGS]
    mappings.update_one({"_id": mapping_id}, {"$set": {"status": Status.QUEUED, "result": None}})
    assert shown() == (MappingOverall.GENERATING, (0, 0, 0, 0))
    mappings.update_one({"_id": mapping_id}, {"$set": {"status": Status.FAILED}})
    assert shown()[0] == MappingOverall.FAILED


def test_an_accepted_relationship_is_approved_at_once_and_its_decision_is_final(
    empty_test_database: None,
) -> None:
    mapper, mapping_id, relations = _finished_mapping()
    assert len(relations) == 3  # water and fuel upstream, grid balancing downstream
    assert approved_relationships(_record(mapping_id)) == []  # nothing decided yet
    _decide(mapper, mapping_id, relations[0])
    _decide(mapper, mapping_id, relations[1], accept=False)
    approved = approved_relationships(_record(mapping_id))
    assert [(dependency["dependency_id"], direction) for dependency, direction in approved] == [
        (relations[0]["dependency_id"], relations[0]["direction"])
    ]  # the rejected one never counts, the pending one not yet
    assert pending_relationships(_record(mapping_id)["result"]) == relations[2:]
    assert _decide(mapper, mapping_id, relations[2]).failed == []  # still decidable: nothing freezes them
    assert len(approved_relationships(_record(mapping_id))) == 2
    assert _decide(mapper, mapping_id, relations[0]).failed == []  # the same decision: no change
    reversal = _decide(mapper, mapping_id, relations[0], accept=False)
    assert [failure.reason for failure in reversal.failed] == [MapperDecisionFailure.DECISION_FINAL]


@pytest.mark.parametrize(
    ("body", "accept", "reject"),
    [
        ({"accept": ["a", "b"], "reject": [""]}, ["a", "b"], []),
        ({"accept": [""], "reject": ["c"]}, [], ["c"]),
        ({"accept": None, "reject": [" c ", "c"]}, [], ["c"]),
        ({"reject": ["c"]}, [], ["c"]),
    ],
)
def test_a_decision_request_drops_nulls_blanks_and_repeats(
    body: dict[str, Any], accept: list[str], reject: list[str]
) -> None:
    request = DependencyDecisionRequest.model_validate(body)
    assert (request.accept, request.reject) == (accept, reject)


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"accept": None, "reject": None},
        {"accept": [""], "reject": ["  "]},
        {"accept": ["a"], "reject": ["a"]},  # both accepted and rejected
        {"accept": ["a"], "colour": "blue"},
        {"accept": [f"id-{n}" for n in range(201)]},
        {"accept": ["x" * 65]},
    ],
)
def test_a_decision_request_with_nothing_to_decide_or_a_contradiction_is_refused(
    body: dict[str, Any],
) -> None:
    with pytest.raises(ValidationError):
        DependencyDecisionRequest.model_validate(body)


def test_one_call_saves_every_valid_decision_together_and_names_the_rest(empty_test_database: None) -> None:
    mapper, mapping_id, relations = _finished_mapping()
    water, fuel, grid = (relation["dependency_id"] for relation in relations)
    _decide(mapper, mapping_id, relations[2])  # grid balancing accepted earlier: rejecting it now is refused
    seq = _record(mapping_id)["decision_seq"]
    body = DependencyDecisionRequest(accept=[water, "missing"], reject=[fuel, grid])
    result = mapper.decide_dependencies(PRINCIPAL, mapping_id, body)
    assert [(failure.dependency_id, failure.reason) for failure in result.failed] == [
        ("missing", MapperDecisionFailure.DEPENDENCY_NOT_FOUND),
        (grid, MapperDecisionFailure.DECISION_FINAL),
    ]
    record = _record(mapping_id)
    assert record["decision_seq"] == seq + 1  # water and fuel saved in one update
    decided = {
        item["dependency_id"]: [relation["isAccepted"] for relation in item["relations"].values()]
        for item in record["result"]["dependencies"]
    }
    assert decided == {water: [True], fuel: [False], grid: [True]}
    reviewed = {"target.id": mapping_id, "action": AuditAction.DEPENDENCY_REVIEWED}
    audits = list(get_mongodb()[Collection.AUDIT].find(reviewed).sort("at", 1))
    assert len(audits) == 2  # one per call: the earlier grid decision, then this one
    assert (audits[-1]["details"]["accepted"], audits[-1]["details"]["rejected"]) == ([water], [fuel])


def test_two_reviewers_deciding_different_relationships_at_once_both_land(empty_test_database: None) -> None:
    mapper, mapping_id, relations = _finished_mapping()
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda relation: _decide(mapper, mapping_id, relation), relations[:2]))
    assert len(pending_relationships(_record(mapping_id)["result"])) == len(relations) - 2


def test_regeneration_archives_the_decisions_and_starts_every_relationship_pending(
    empty_test_database: None,
) -> None:
    mapper, mapping_id, relations = _finished_mapping()
    for relation in relations:
        _decide(mapper, mapping_id, relation)
    started, _ = mapper.regenerate_service_mapping(PRINCIPAL, mapping_id, uuid4().hex)
    assert started.generation == 2
    archived = get_mongodb()[Collection.SERVICE_MAPPING_HISTORY].find_one({"_id": f"{mapping_id}:1"})
    assert pending_relationships(archived["result"]) == [] and "review" not in archived
    result = reconcile(mapping_id, 2, _request(), _answer(), _catalog(), 20, 20)  # what the worker saves
    get_mongodb()[Collection.SERVICE_MAPPINGS].update_one(
        {"_id": mapping_id}, {"$set": {"status": Status.DONE, "result": result}}
    )
    fresh = _record(mapping_id)
    assert len(pending_relationships(fresh["result"])) == len(relations)
    assert not {r["dependency_id"] for r in relations} & {d["dependency_id"] for d in result["dependencies"]}
    assert approved_relationships(fresh) == []
