"""Service Mapper's catalog, reconciliation, scoped lifecycle and review contract."""

import json
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import numpy as np
import pytest
from fastapi.testclient import TestClient

from app import container
from app.core.constants import (
    AiOutage,
    AuditAction,
    Collection,
    MapperAction,
    MapperConflict,
    MapperDirection,
    Status,
    TaskName,
)
from app.core.database import get_mongodb
from app.core.exceptions import Conflict
from app.data_access.admin.audit_repository import AuditRepository
from app.data_access.service_mapper.mapping_repository import MappingHistoryRepository, MappingRepository
from app.domain.service_mapper import generate
from app.domain.service_mapper.catalog import build_catalog
from app.domain.service_mapper.generate import generate_result
from app.domain.service_mapper.reconcile import reconcile
from app.domain.service_mapper.views import approved_relationships, pending_relationships
from app.models.admin.api_clients import Principal
from app.models.service_mapper.catalog import CatalogRows, CatalogService, CatalogSnapshot
from app.models.service_mapper.contract import (
    CreateMappingRequest,
    DependencyDecisionRequest,
    MappingDecisionRequest,
)
from app.models.service_mapper.generation import GeneratedAnswer
from app.search.service_mapper import ServiceCandidateSearch
from app.services.service_mapper.service_mapper_service import ServiceMapperService
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


def _answer() -> GeneratedAnswer:
    reason = "It directly supplies treated cooling water needed by the generation process."
    return GeneratedAnswer.model_validate(
        {
            "operational_context": "The plant converts primary energy into electricity for grid delivery.",
            "upstream_services": [
                {
                    "service_name": "Water Treatment Service",
                    "catalog_service_id": 2,
                    "dependency_reason": reason,
                },
                {
                    "service_name": "Water Treatment Service",
                    "catalog_service_id": 2,
                    "dependency_reason": reason,
                },
                {
                    "service_name": "Fuel Logistics Service",
                    "catalog_service_id": None,
                    "dependency_reason": "It delivers fuel directly to the plant for generation.",
                },
                {
                    "service_name": "Invented Master",
                    "catalog_service_id": 999,
                    "dependency_reason": "This fabricated catalog identifier must be rejected.",
                },
                {
                    "service_name": "Power Generation System",
                    "catalog_service_id": 1,
                    "dependency_reason": "The selected service cannot depend directly on itself.",
                },
            ],
            "downstream_services": [
                {
                    "service_name": "Water Treatment Service",
                    "catalog_service_id": 2,
                    "dependency_reason": "It directly consumes plant electricity to run water pumps.",
                },
                {
                    "service_name": "Grid Balancing Service",
                    "catalog_service_id": None,
                    "dependency_reason": "It directly takes the plant's generation output for balancing.",
                },
            ],
        }
    )


def test_reconciliation_deduplicates_cross_sector_links_and_rejects_fabricated_ids() -> None:
    result = reconcile("mapping", 1, _request(), _answer(), _catalog(), 2, 2)
    assert result["selected_service"]["service_id"] == 1
    assert result["summary"]["upstream_count"] == 2
    assert result["summary"]["downstream_count"] == 1
    assert result["summary"]["unique_services"] == 3
    water = next(item for item in result["dependencies"] if item["service_id"] == 2)
    assert water["sector"] == "Water" and water["ai_suggested"] is False
    assert set(water["relations"]) == {"upstream"}  # in both lists at the same rank: upstream wins the tie
    assert all(item["service_id"] != 999 for item in result["dependencies"])
    assert len({item["dependency_id"] for item in result["dependencies"]}) == 3


def test_a_service_in_both_lists_is_kept_only_where_the_ai_ranked_it_higher() -> None:
    answer = _answer().model_dump()
    answer["upstream_services"] = answer["upstream_services"][2:3] + answer["upstream_services"][:1]
    result = reconcile("mapping", 1, _request(), GeneratedAnswer.model_validate(answer), _catalog(), 5, 5)
    water = next(item for item in result["dependencies"] if item["service_id"] == 2)
    assert set(water["relations"]) == {"downstream"}  # first downstream, second upstream
    assert (result["summary"]["upstream_count"], result["summary"]["downstream_count"]) == (1, 2)


def test_a_short_direction_gets_one_more_ai_call_that_adds_no_duplicates() -> None:
    def item(name: str) -> dict[str, Any]:
        return {"service_name": name, "dependency_reason": f"{name} is a direct operational dependency here."}

    context = "The plant converts primary energy into electricity for grid delivery."
    answers = [
        {
            "operational_context": context,
            "upstream_services": [item("Water Treatment Service")],
            "downstream_services": [item("Grid Balancing Service")],
        },
        {
            "operational_context": context,
            "upstream_services": [item("Water Treatment Service"), item("Fuel Logistics Service")],
            "downstream_services": [item("Grid Balancing Service")],
        },
    ]
    prompts: list[dict[str, Any]] = []
    sent: list[tuple[str, str]] = []

    class Chat:
        max_prompt_chars = 200_000

        def ask_for_checked_json(self, _task, system, prompt, check):
            sent.append((system, prompt))
            prompts.append(json.loads(prompt))
            answer = answers.pop(0)
            assert check(answer) == []
            return answer

    class Search:
        def candidates(self, _catalog, _queries):
            return []

    result = generate_result(Chat(), Search(), _request(), _catalog(), ("mapping", 1), (2, 1))  # type: ignore[arg-type]
    assert [(p["upstream_count"], p["downstream_count"]) for p in prompts] == [(2, 1), (1, 0)]
    assert "already_selected" not in prompts[0]
    assert sorted(prompts[1]["already_selected"]) == ["Grid Balancing Service", "Water Treatment Service"]
    assert (result["summary"]["upstream_count"], result["summary"]["downstream_count"]) == (2, 1)
    assert sorted(item["service_name"] for item in result["dependencies"]) == [
        "Fuel Logistics Service",
        "Grid Balancing Service",
        "Water Treatment Service",
    ]
    system = (Path(generate.__file__).parent / "prompts" / "generate.txt").read_text(encoding="utf-8")
    assert result["prompts"] == {"system_prompt": system, "user_prompts": [prompt for _, prompt in sent]}
    assert all(sent_system == system for sent_system, _ in sent)


def test_the_prompt_reads_the_counts_and_writes_none_itself() -> None:
    prompt = (Path(generate.__file__).parent / "prompts" / "generate.txt").read_text(encoding="utf-8")
    assert "upstream_count" in prompt and "downstream_count" in prompt and "already_selected" in prompt
    assert not re.search(r"\d", prompt)


def test_empty_catalog_still_keeps_defensible_ai_services() -> None:
    empty = build_catalog(CatalogRows([], [], [], [], [], []))
    answer = _answer().model_dump()
    answer["upstream_services"] = [
        item for item in answer["upstream_services"] if item["service_name"] != "Invented Master"
    ]
    for item in (*answer["upstream_services"], *answer["downstream_services"]):
        item["catalog_service_id"] = None
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
            "upstream_services": [
                {
                    "service_name": "PMS",
                    "catalog_service_id": None,
                    "dependency_reason": "It provides monitoring directly to the generation process.",
                }
            ],
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
        path = f"/v1/service-mapper/{mapping_id}/dependencies/{water['dependency_id']}/decision"
        decided = client.post(path, json={"direction": "upstream", "action": "accept"}, headers=headers)
        assert decided.status_code == 200, decided.text
        relation = decided.json()["upstream_services"][0]
        assert relation["isAccepted"] is True
        assert relation["accepted_by"] == "reviewer-1" and relation["accepted_datetime"]
        assert decided.json()["downstream_services"][0]["isAccepted"] is None
        reversal = client.post(path, json={"direction": "upstream", "action": "reject"}, headers=headers)
        assert reversal.status_code == 409
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
    body = DependencyDecisionRequest(
        direction=MapperDirection(relation["direction"]),
        action=MapperAction.ACCEPT if accept else MapperAction.REJECT,
    )
    return mapper.decide_dependency(PRINCIPAL, mapping_id, relation["dependency_id"], body)


def _decide_mapping(mapper: ServiceMapperService, mapping_id: str, accept: bool = True):
    action = MapperAction.ACCEPT if accept else MapperAction.REJECT
    return mapper.decide_mapping(PRINCIPAL, mapping_id, MappingDecisionRequest(action=action))


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


def test_a_mapping_is_accepted_only_once_every_relationship_has_its_own_decision(
    empty_test_database: None,
) -> None:
    mapper, mapping_id, relations = _finished_mapping()
    assert len(relations) == 3  # water and fuel upstream, grid balancing downstream
    with pytest.raises(Conflict) as refused:
        _decide_mapping(mapper, mapping_id)
    assert refused.value.reason == MapperConflict.RELATIONSHIPS_PENDING
    assert refused.value.details == {"pending": relations}
    for relation in relations[:-1]:
        _decide(mapper, mapping_id, relation)
    with pytest.raises(Conflict) as still:
        _decide_mapping(mapper, mapping_id)
    assert still.value.details == {"pending": relations[-1:]}
    _decide(mapper, mapping_id, relations[-1], accept=False)
    assert _decide_mapping(mapper, mapping_id).review == "accepted"
    audit = get_mongodb()[Collection.AUDIT].find_one(
        {"target.id": mapping_id, "action": AuditAction.MAPPING_REVIEWED}
    )
    assert audit["details"]["relationships_accepted"] == len(relations) - 1
    assert audit["details"]["relationships_rejected"] == 1
    record = _record(mapping_id)
    assert len(approved_relationships(record)) == len(relations) - 1  # the rejected one never counts
    assert _decide(mapper, mapping_id, relations[0]).review == "accepted"  # the same decision: no change
    with pytest.raises(Conflict) as frozen:
        _decide(mapper, mapping_id, relations[0], accept=False)
    assert frozen.value.reason == MapperConflict.DECISION_FINAL


def test_a_rejected_mapping_approves_no_relationship_and_freezes_the_rest(empty_test_database: None) -> None:
    mapper, mapping_id, relations = _finished_mapping()
    _decide(mapper, mapping_id, relations[0])
    assert _decide_mapping(mapper, mapping_id, accept=False).review == "rejected"  # pending ones may stay
    with pytest.raises(Conflict) as frozen:
        _decide(mapper, mapping_id, relations[1])
    assert frozen.value.reason == MapperConflict.DECISION_FINAL
    assert approved_relationships(_record(mapping_id)) == []  # even the relationship accepted earlier


def test_the_accept_update_itself_refuses_a_pending_relationship(empty_test_database: None) -> None:
    mapper, mapping_id, relations = _finished_mapping()
    for relation in relations:
        _decide(mapper, mapping_id, relation)
    record = _record(mapping_id)
    path = f"result.dependencies.$[d].relations.{relations[0]['direction']}.isAccepted"
    get_mongodb()[Collection.SERVICE_MAPPINGS].update_one(  # undone behind the counter's back
        {"_id": mapping_id},
        {"$set": {path: None}},
        array_filters=[{"d.dependency_id": relations[0]["dependency_id"]}],
    )
    accepted = MappingRepository().decide_mapping(
        mapping_id, record["generation"], record["decision_seq"], True, "reviewer", datetime.now(UTC)
    )
    assert accepted is False and _record(mapping_id)["review"] == "pending"


def test_accepting_while_the_last_relationship_is_decided_never_accepts_a_pending_one(
    empty_test_database: None,
) -> None:
    for _round in range(5):
        mapper, mapping_id, relations = _finished_mapping()
        for relation in relations[:-1]:
            _decide(mapper, mapping_id, relation)

        def accept_mapping(mapper: ServiceMapperService = mapper, mapping_id: str = mapping_id) -> str:
            try:
                return _decide_mapping(mapper, mapping_id).review
            except Conflict as refused:
                return str(refused.reason)

        with ThreadPoolExecutor(max_workers=2) as pool:
            last = pool.submit(_decide, mapper, mapping_id, relations[-1])
            outcome = pool.submit(accept_mapping).result()
            last.result()
        record = _record(mapping_id)
        assert pending_relationships(record["result"]) == []
        assert outcome in {"accepted", MapperConflict.RELATIONSHIPS_PENDING}
        assert record["review"] == ("accepted" if outcome == "accepted" else "pending")


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
    _decide_mapping(mapper, mapping_id)
    started, _ = mapper.regenerate_service_mapping(PRINCIPAL, mapping_id, uuid4().hex)
    assert started.generation == 2
    archived = get_mongodb()[Collection.SERVICE_MAPPING_HISTORY].find_one({"_id": f"{mapping_id}:1"})
    assert archived["review"] == "accepted" and pending_relationships(archived["result"]) == []
    result = reconcile(mapping_id, 2, _request(), _answer(), _catalog(), 20, 20)  # what the worker saves
    get_mongodb()[Collection.SERVICE_MAPPINGS].update_one(
        {"_id": mapping_id}, {"$set": {"status": Status.DONE, "result": result}}
    )
    fresh = _record(mapping_id)
    assert fresh["review"] == "pending" and len(pending_relationships(fresh["result"])) == len(relations)
    assert not {r["dependency_id"] for r in relations} & {d["dependency_id"] for d in result["dependencies"]}
    assert approved_relationships(fresh) == []
