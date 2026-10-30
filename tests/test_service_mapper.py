"""Service Mapper's catalog, reconciliation, scoped lifecycle and review contract."""

import contextlib
import json
import re
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
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
from app.core.config import Settings
from app.core.constants import (
    AI_OUTAGE_MESSAGES,
    AiOutage,
    AuditAction,
    Collection,
    ConflictReason,
    Lease,
    MapperConflict,
    MapperDecisionFailure,
    MapperMessage,
    MappingOverall,
    Status,
    TaskName,
)
from app.core.database import get_mongodb
from app.core.exceptions import Conflict, JobFailed, Unavailable
from app.data_access.admin.audit_repository import AuditRepository
from app.data_access.jobs.job_repository import JobLease
from app.data_access.service_mapper.mapping_repository import MappingRepository
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
from app.worker import jobs
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


def _catalog_rows() -> CatalogRows:
    return CatalogRows(
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


def _catalog():
    return build_catalog(_catalog_rows())


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


def _counts(result: dict[str, Any]) -> tuple[int, int]:
    """(upstream, downstream) relationships of a run's reconciled result."""
    directions = [direction for item in result["dependencies"] for direction in item["relations"]]
    return directions.count("upstream"), directions.count("downstream")


def test_reconciliation_deduplicates_and_drops_the_selected_service_and_vague_names() -> None:
    result = reconcile("mapping", 1, _request(), _answer(), _catalog(), 2, 2)
    assert result["selected_service"]["service_id"] == 1
    assert _counts(result) == (2, 1)
    assert len(result["dependencies"]) == 3
    water = next(item for item in result["dependencies"] if item["service_id"] == 2)
    assert water["sector"] == "Water" and water["ai_suggested"] is False
    assert set(water["relations"]) == {"upstream"}  # in both lists at the same rank: upstream wins the tie
    assert all(item["service_name"] != "Electricity" for item in result["dependencies"])
    assert len({item["dependency_id"] for item in result["dependencies"]}) == 3


def test_only_items_reconcile_cannot_settle_are_named_with_why_for_the_re_ask() -> None:
    """A repeat, the selected service and a service in both lists reconcile settles without the AI."""
    problems = answer_problems(_request(), _answer(), _catalog())
    assert problems == [
        'upstream_services: "Electricity" is too vague: name the specific service in at least two words '
        "(a new name is fine when no catalog service provides it)",
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
    assert _counts(result) == (1, 2)


class _Chat:
    """The AI gateway's re-ask: a first answer the checks fault is asked again once with its problems."""

    max_prompt_chars = 200_000

    def __init__(self, *answers: dict[str, Any]) -> None:
        self.answers = list(answers)
        self.prompts: list[dict[str, Any]] = []
        self.problems: list[str] = []
        self.reuse_earlier_answer = False

    def ask_for_checked_json(
        self, _task, _system, prompt, check, first_answer_check, reuse_earlier_answer=False
    ):
        self.prompts.append(json.loads(prompt))
        self.reuse_earlier_answer = reuse_earlier_answer
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
    assert _counts(result) == (1, 0)


def test_a_retry_of_the_same_generation_reuses_its_earlier_ai_answer() -> None:
    """The job's epoch is the generation: a delivery retried after an outage takes the answer it already got,
    so a busy gateway is not asked again; a regenerate is the next epoch and asks afresh."""
    chat = _Chat(_answer().model_dump(), _answer().model_dump())
    generate_result(chat, _Search(), _request(), _catalog(), ("mapping", 1), (5, 5))  # type: ignore[arg-type]
    assert chat.reuse_earlier_answer is True


def test_a_first_answer_with_dropped_items_is_asked_again_with_why() -> None:
    fixed = _answer().model_dump()
    fixed["upstream_services"] = fixed["upstream_services"][:1] + fixed["upstream_services"][2:3]
    fixed["downstream_services"] = fixed["downstream_services"][1:]
    fixed["downstream_services"][0]["sector"] = "Energy"
    chat = _Chat(_answer().model_dump(), fixed)
    result = generate_result(chat, _Search(), _request(), _catalog(), ("mapping", 1), (5, 5))  # type: ignore[arg-type]
    assert len(chat.problems) == 2
    assert answer_problems(_request(), GeneratedAnswer.model_validate(fixed), _catalog()) == []
    assert _counts(result) == (2, 1)


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


def test_the_selected_services_recorded_dependencies_lead_and_a_shared_service_is_described_once() -> None:
    """No fixed checklist (owner 2026-10-23): what the AI decides first is the selected service's own recorded
    upstream/downstream from the database; a service in two groups is sent with its details once."""
    power = SectorAssociation(10, "Energy", 11, "Power")
    water, grid = SectorAssociation(20, "Water", None, None), SectorAssociation(10, "Energy", 12, "Grid")
    selected = CatalogService(1, "Power Generation System", "", (power,), (), "Fuel supply", "Grid operator")
    shared = CatalogService(
        2, "Water Treatment Service", "Supplies treated water.", (water, grid), (), "", ""
    )
    catalog = CatalogSnapshot("v", ("Energy", "Water"), (power, water, grid), (selected, shared))
    chat = _Chat(_answer().model_dump(), _answer().model_dump())
    generate_result(chat, _Search(), _request(), catalog, ("mapping", 1), (2, 1))  # type: ignore[arg-type]
    sent = chat.prompts[0]
    assert "upstream_checks" not in sent
    assert (sent["selected_service"]["known_upstream"], sent["selected_service"]["known_downstream"]) == (
        "Fuel supply",
        "Grid operator",
    )
    entries = [entry for group in sent["catalog"] for entry in group["services"]]
    assert entries == [
        {"service_name": "Water Treatment Service", "description": "Supplies treated water."},
        {"service_name": "Water Treatment Service"},
    ]
    new_service = CreateMappingRequest(**(_request().model_dump() | {"service_name": "Hydrogen Storage"}))
    chat = _Chat(_answer().model_dump(), _answer().model_dump())
    generate_result(chat, _Search(), new_service, catalog, ("mapping", 2), (2, 1))  # type: ignore[arg-type]
    assert "known_upstream" not in chat.prompts[0]["selected_service"]  # not in the catalog: none recorded


def test_a_new_service_named_in_two_forms_is_kept_once_in_a_list_and_across_lists() -> None:
    reason = "It settles every top-up; without it no fare is collected."
    answer = GeneratedAnswer.model_validate(
        {
            "operational_context": "The plant converts primary energy into electricity for grid delivery.",
            "upstream_services": [
                _item("Payment Settlement Service (PSS)", reason, "Energy"),
                _item("Payment Settlement Service", reason, "Energy"),
            ],
            "downstream_services": [_item("Payment Settlement Service", reason, "Energy")],
        }
    )
    result = reconcile("mapping", 1, _request(), answer, _catalog(), 5, 5)
    assert [item["service_name"] for item in result["dependencies"]] == ["Payment Settlement Service (PSS)"]
    assert set(result["dependencies"][0]["relations"]) == {"upstream"}  # the tie goes upstream
    assert answer_problems(_request(), answer, _catalog()) == []  # reconcile settles it: no re-ask


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
        "already_mapped",  # a later run's (owner 2026-10-28)
        "entity_names",
        *GeneratedAnswer.model_fields,
        *ProposedDependency.model_fields,
    }
    assert [key for key in sorted(keys) if key not in generate._SYSTEM] == []
    assert not re.search(r"\d", generate._SYSTEM)
    assert len(generate._SYSTEM) < 4_500  # 4,400 before already_mapped's one line


def test_the_prompt_keeps_the_owners_evidence_and_weak_link_rules() -> None:
    """Owner 2026-10-23: each reason says Recorded or Inferred, a recorded dependency's direction is the
    carrying service's, uncertainty goes in operational_context, and weak links fail the test."""
    rules = (
        '"Recorded: "',
        '"Inferred: "',
        "their direction from the service that carries them",
        "any material uncertainty or inference",
        "mere interaction, optional support",
        "conditions the input does not support",
        "(zero means [])",
        "Empty lists are valid.",
        "classified at sector level, not unknown",
    )
    assert [rule for rule in rules if rule not in generate._SYSTEM] == []


def test_the_prompt_says_a_weaker_service_is_not_a_failed_one() -> None:
    """Live 2026-10-23: 1 reason in 9 said only that a service would "degrade", be delayed or be at risk. With
    these rules that halved on the DESC register, the dev catalog and the register with its records."""
    rules = (
        "Delay, extra cost, lower quality or risk is not failure.",
        "without it, <selected service> cannot ...",
        "without it,\n  <service> cannot ...",
    )
    assert [rule for rule in rules if rule not in generate._SYSTEM] == []


def test_a_truncated_ai_answer_fails_the_job_with_a_clear_message() -> None:
    class Chat:
        max_prompt_chars = 200_000

        def ask_for_checked_json(self, *_args, **_options):
            raise TruncatedAiAnswer("cut off at the length limit")

    class Catalog:
        def snapshot(self) -> CatalogSnapshot:
            return _catalog()

    job = ServiceMapperJob(None, Catalog(), _Search(), Chat())  # type: ignore[arg-type]
    record = {"request": _request().model_dump(), "limits": {"max_upstream": 2, "max_downstream": 2}}
    with pytest.raises(JobFailed) as failed:
        job.generate(SimpleNamespace(record=record, record_id="mapping", epoch=1))  # type: ignore[arg-type]
    assert failed.value.message == MapperMessage.AI_ANSWER_TOO_LONG


def _over_the_limits() -> dict[str, Any]:
    """Three defensible services each way: more than limits of two upstream and one downstream."""
    reason = "It directly supplies an input the generation process cannot run without."
    upstream = ("Fuel Logistics Service", "Gas Pipeline Operations", "Telecommunications Network Service")
    downstream = ("Grid Balancing Service", "Metro Rail Operations", "Hospital Emergency Care")
    return {
        "operational_context": "The plant converts primary energy into electricity for grid delivery.",
        "upstream_services": [_item(name, reason) for name in upstream],
        "downstream_services": [_item(name, reason) for name in downstream],
    }


def test_each_list_keeps_only_its_limit_strongest_first() -> None:
    answer = GeneratedAnswer.model_validate(_over_the_limits())
    result = reconcile("mapping", 1, _request(), answer, _catalog(), 2, 1)
    names = {
        direction: [item["service_name"] for item in result["dependencies"] if direction in item["relations"]]
        for direction in ("upstream", "downstream")
    }
    assert names == {
        "upstream": ["Fuel Logistics Service", "Gas Pipeline Operations"],
        "downstream": ["Grid Balancing Service"],
    }
    assert _counts(result) == (2, 1)


def test_a_recorded_reason_needs_a_record_of_the_link_in_the_input() -> None:
    """Live 2026-10-23: with no known_upstream/known_downstream anywhere, the AI still began 5 of 175 reasons
    "Recorded: ". Without a record of the link in that direction the reason says "Inferred: "."""
    recorded = "Recorded: the plant cannot generate without what this service provides."
    answer = GeneratedAnswer.model_validate(
        {
            "operational_context": "The plant converts primary energy into electricity for grid delivery.",
            "upstream_services": [
                _item("Water Treatment Service", recorded),
                _item("Fuel Logistics Service", recorded, "Energy"),
            ],
            "downstream_services": [_item("Grid Balancing Service", recorded, "Energy")],
        }
    )

    def labels(service_id: int, **record: str) -> dict[str, str]:
        catalog = _catalog()
        services = tuple(replace(s, **record) if s.service_id == service_id else s for s in catalog.services)
        result = reconcile("mapping", 1, _request(), answer, replace(catalog, services=services), 5, 5)
        return {
            item["service_name"]: relation["dependency_reason"].split(":")[0]
            for item in result["dependencies"]
            for relation in item["relations"].values()
        }

    nothing = {"Water Treatment Service": "Inferred", "Fuel Logistics Service": "Inferred"}
    assert labels(1) == nothing | {"Grid Balancing Service": "Inferred"}
    assert labels(2, downstream_context="Power plants take its cooling water.") == nothing | {
        "Water Treatment Service": "Recorded",  # the other service records the selected one downstream of it
        "Grid Balancing Service": "Inferred",
    }
    assert labels(1, upstream_context="Cooling water and fuel.") == {  # the selected one's upstream record
        "Water Treatment Service": "Recorded",
        "Fuel Logistics Service": "Recorded",
        "Grid Balancing Service": "Inferred",
    }
    assert labels(1, downstream_context="The grid.")["Grid Balancing Service"] == "Recorded"


def test_a_new_service_named_with_the_recorded_text_is_asked_again() -> None:
    """Live 2026-10-23 (DESC register): given its recorded upstream, the AI named "services" such as
    "Technology, hosting and cybersecurity providers", the record's headings. Each is asked again; a real name
    never is."""
    record = (
        "1. Emergency communications and telecom services - radio links. 2. Technology, hosting providers."
    )
    catalog = _catalog()
    services = tuple(
        replace(s, upstream_context=record) if s.service_id == 1 else s for s in catalog.services
    )
    reason = "Inferred: the plant cannot be dispatched without what this service provides."
    answer = GeneratedAnswer.model_validate(
        {
            "operational_context": "The plant converts primary energy into electricity for grid delivery.",
            "upstream_services": [
                _item("Emergency Communications and Telecom Services", reason, "Energy"),
                _item("Telecommunications Network Service", reason, "Energy"),
                _item("Technology, Hosting Providers", reason, "Energy"),
            ],
            "downstream_services": [],
        }
    )
    copied = [
        p for p in answer_problems(_request(), answer, replace(catalog, services=services)) if "copies" in p
    ]
    assert copied == [
        f'"{name}" copies the recorded text, not a service: name the specific service that provides it'
        for name in ("Emergency Communications and Telecom Services", "Technology, Hosting Providers")
    ]
    assert [
        p for p in answer_problems(_request(), answer, catalog) if "copies" in p
    ] == []  # nothing recorded


def test_the_job_sends_the_mappings_limits_to_the_ai_and_keeps_to_them() -> None:
    """The limits saved with the mapping (SERVICE_MAPPER_*_TOTAL_COUNT) reach the AI and cap the result."""

    class Catalog:
        def snapshot(self) -> CatalogSnapshot:
            return _catalog()

    class Mappings:
        def finish_generation(self, _lease, result, timings) -> None:
            self.result, self.timings = result, timings

    chat, mappings = _Chat(_over_the_limits(), _over_the_limits()), Mappings()
    record = {"request": _request().model_dump(), "limits": {"max_upstream": 2, "max_downstream": 1}}
    job = ServiceMapperJob(mappings, Catalog(), _Search(), chat)  # type: ignore[arg-type]
    job.generate(SimpleNamespace(record=record, record_id="mapping", epoch=1))  # type: ignore[arg-type]
    assert (chat.prompts[0]["upstream_count"], chat.prompts[0]["downstream_count"]) == (2, 1)
    assert _counts(mappings.result) == (2, 1)
    assert set(mappings.timings) == {"catalog_s", "services_s"}  # the run's two activities, timed


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

        def embed_search_queries(self, _queries, corpus):
            searched.append(corpus)
            return np.array([[0.0, 1.0]], dtype=np.float32)

    searched: list[str] = []
    found = ServiceCandidateSearch(Embeddings()).candidates(_catalog(), ["unrelated vocabulary"])
    assert searched == ["service"]
    assert found[0].service_name == "Water Treatment Service"
    assert found[0].primary_sector.sector_name == "Water"


def test_the_candidate_search_fuses_every_question_and_breaks_a_tie_by_service_id() -> None:
    """Each question's ranking adds 1 / (RRF_K + rank) (fuse_by_rank); a tie goes to the lower service id."""

    class Embeddings:
        def embed_search_queries(self, queries, _corpus):
            return np.zeros((len(queries), 2), dtype=np.float32)

    class Index:
        rankings = {"first": [2, 0], "second": [0, 2, 1]}  # positions, best first

        def search(self, query, _vector, _top_k):
            return [SimpleNamespace(position=position) for position in self.rankings[query]]

    services = tuple(
        CatalogService(service_id, f"Service {service_id}", "", (), (), "", "") for service_id in (1, 2, 3)
    )
    search = ServiceCandidateSearch(Embeddings())  # type: ignore[arg-type]
    search._for_catalog = lambda _catalog: Index()  # type: ignore[method-assign,assignment,return-value]
    found = search.candidates(CatalogSnapshot("fusion", (), (), services), ["first", "second"])
    assert [service.service_id for service in found] == [1, 3, 2]  # 1 and 3 tie at 1/61 + 1/62


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
    mapper, sent = _mapper()
    principal = Principal("client", "reviewer", 86, "tenant-a")
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(lambda _: mapper.create_service_mapping(principal, _request(), "one-key"), range(2))
        )
    assert results[0][0].mapping_id == results[1][0].mapping_id
    assert sorted(created for _, created in results) == [False, True]
    assert len(sent) == 1


def test_mapper_api_scopes_records_and_stamps_each_direction(client: TestClient) -> None:
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

    mapper, sent = _mapper(catalog=Catalog(), published=published)
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
        assert reversal.json()["failed"] == []  # a decision can be changed
        assert reversal.json()["upstream_services"][0]["isAccepted"] is False
        assert reversal.json()["upstream_services"][0]["accepted_by"] is None
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
        kept = client.get(f"/v1/service-mapper/{mapping_id}", headers=headers).json()  # nothing wiped
        assert kept["upstream_services"][0]["dependency_id"] == water_id
        assert kept["upstream_services"][0]["isAccepted"] is False
        assert published == [mapping_id] * 4  # started, decided, decision changed, regenerated
        assert get_mongodb()[Collection.AUDIT].count_documents({"target.id": mapping_id}) == 4
    finally:
        client.app.dependency_overrides.clear()


PRINCIPAL = Principal("client", "reviewer", 86, "tenant-a")


def _mapper(
    settings: Settings | None = None, catalog: Any = None, published: list[str] | None = None
) -> tuple[ServiceMapperService, list[tuple[Any, ...]]]:
    """The mapper service, and every job it sends. A service has one mapping, and the test database is
    emptied once per run: the mappings an earlier test made are removed first."""
    get_mongodb()[Collection.SERVICE_MAPPINGS].delete_many({})
    sent: list[tuple[Any, ...]] = []
    mapper = ServiceMapperService(
        MappingRepository(),
        settings or container.get_settings(),
        lambda *job: sent.append(job),
        catalog,
        AuditRepository(),
        published.append if published is not None else lambda _mapping_id: None,
    )
    return mapper, sent


def _finished_mapping() -> tuple[ServiceMapperService, str, list[dict[str, str]]]:
    """A mapping whose first run finished, and its relationships (all still undecided)."""
    mapper, _ = _mapper()
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


def test_a_mapping_and_its_next_run_pass_the_rule_uat_stored_on_20_oct(empty_test_database: None) -> None:
    """UAT 29 Oct: every POST /v1/service-mapper answered 500. The 20 Oct rule still requires generation
    and UAT's database user may not change a rule (collMod), so each new record and each run started
    again carries generation, the latest run."""
    MappingRepository().create_indexes()
    required = ["_id", "tenant_id", "entity_id", "status", "generation", "job"]
    rule = {"$jsonSchema": {"bsonType": "object", "required": required}}
    get_mongodb().command("collMod", Collection.SERVICE_MAPPINGS, validator=rule, validationLevel="moderate")
    mapper, mapping_id, _ = _finished_mapping()  # refused (WriteError 121) without generation
    assert _record(mapping_id)["generation"] == 1
    mapper.regenerate_service_mapping(PRINCIPAL, mapping_id, uuid4().hex)
    assert _record(mapping_id)["generation"] == _record(mapping_id)["job"]["epoch"] == 2


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


def test_an_accepted_relationship_is_approved_at_once_and_its_decision_can_be_changed(
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
    assert _decide(mapper, mapping_id, relations[0], accept=False).failed == []  # changed: rejected now
    approved = approved_relationships(_record(mapping_id))
    assert [dependency["dependency_id"] for dependency, _ in approved] == [relations[2]["dependency_id"]]


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
    _decide(mapper, mapping_id, relations[2])  # grid balancing accepted earlier: rejecting it now changes it
    body = DependencyDecisionRequest(accept=[water, "missing"], reject=[fuel, grid])
    result = mapper.decide_dependencies(PRINCIPAL, mapping_id, body)
    assert [(failure.dependency_id, failure.reason) for failure in result.failed] == [
        ("missing", MapperDecisionFailure.DEPENDENCY_NOT_FOUND)
    ]
    record = _record(mapping_id)
    decided = {
        item["dependency_id"]: [relation["isAccepted"] for relation in item["relations"].values()]
        for item in record["result"]["dependencies"]
    }
    assert decided == {water: [True], fuel: [False], grid: [False]}
    reviewed = {"target.id": mapping_id, "action": AuditAction.DEPENDENCY_REVIEWED}
    audits = list(get_mongodb()[Collection.AUDIT].find(reviewed).sort("at", 1))
    assert len(audits) == 2  # one per call: the earlier grid decision, then this one
    assert (audits[-1]["details"]["accepted"], audits[-1]["details"]["rejected"]) == ([water], [fuel, grid])


def test_two_reviewers_deciding_different_relationships_at_once_both_land(empty_test_database: None) -> None:
    mapper, mapping_id, relations = _finished_mapping()
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda relation: _decide(mapper, mapping_id, relation), relations[:2]))
    assert len(pending_relationships(_record(mapping_id)["result"])) == len(relations) - 2


# --- one mapping per service; a later run (Generate again, Regenerate) only adds services (owner 2026-10-28)


class _Snapshot:
    def snapshot(self) -> CatalogSnapshot:
        return _catalog()


def _task() -> Any:
    return SimpleNamespace(name=TaskName.MAP_SERVICES, request=SimpleNamespace(id=uuid4().hex), retry=None)


def _run(mapping_id: str, answer: dict[str, Any], during: Callable[[], object] = lambda: None) -> _Chat:
    """The mapping's queued run, done by the worker's own job under a real lease, the AI answering `answer`
    (again on a re-ask); `during` runs after the claim, before the run saves what it found."""
    chat = _Chat(answer, answer)
    job = ServiceMapperJob(MappingRepository(), _Snapshot(), _Search(), chat)  # type: ignore[arg-type]

    def work(lease: JobLease) -> None:
        during()
        job.generate(lease)

    run = _record(mapping_id)["job"]["epoch"]
    jobs.run_leased_job(
        _task(), Collection.SERVICE_MAPPINGS, mapping_id, run, work, ("request", "limits", "result")
    )
    assert _record(mapping_id)["status"] == Status.DONE
    return chat


def _fail_run(mapping_id: str) -> None:
    """The mapping's queued run fails for good on an AI outage, as the worker settles it."""
    records = get_mongodb()[Collection.SERVICE_MAPPINGS]
    records.update_one({"_id": mapping_id}, {"$set": {"job.attempts": Lease.MAX_ATTEMPTS - 1}})
    busy = Unavailable(AI_OUTAGE_MESSAGES[AiOutage.BUSY], reason=AiOutage.BUSY)

    def work(_lease: JobLease) -> None:
        raise busy

    run = _record(mapping_id)["job"]["epoch"]
    with contextlib.suppress(Unavailable):  # run_leased_job re-raises what it settled
        jobs.run_leased_job(_task(), Collection.SERVICE_MAPPINGS, mapping_id, run, work)
    assert _record(mapping_id)["status"] == Status.FAILED


def _second_answer() -> dict[str, Any]:
    """A later run's AI answer: three services the mapping holds (one as it was, one in the other direction,
    one under another form of its name) and one new."""
    reason = "It directly supplies an input the generation process cannot run without."
    return {
        "operational_context": "The plant converts primary energy into electricity for grid delivery.",
        "upstream_services": [
            _item("Water Treatment Service", reason),
            _item("Grid Balancing Service", reason),
            _item("Telecom Network Service", "The plant's control systems stop without it.", "Energy"),
        ],
        "downstream_services": [_item("Fuel Logistics Service (FLS)", reason, "Energy")],
    }


def _decide_ids(mapper: ServiceMapperService, mapping_id: str, **ids: list[str]) -> None:
    assert mapper.decide_dependencies(PRINCIPAL, mapping_id, DependencyDecisionRequest(**ids)).failed == []


def _ids_by_name(mapping_id: str) -> dict[str, str]:
    return {
        item["service_name"]: item["dependency_id"] for item in _record(mapping_id)["result"]["dependencies"]
    }


def _map(mapping_id: str, run: int) -> tuple[TaskName, str, int]:
    return TaskName.MAP_SERVICES, mapping_id, run


def test_generate_again_and_regenerate_add_only_new_services_and_keep_every_decision(
    empty_test_database: None,
) -> None:
    mapper, sent = _mapper()
    first, created = mapper.create_service_mapping(PRINCIPAL, _request(), uuid4().hex)
    mapping_id = first.mapping_id
    assert (first.generation, created) == (1, True)
    first_asked = _run(mapping_id, _answer().model_dump()).prompts[0]
    assert "Water Treatment Service" in json.dumps(first_asked["catalog"])
    run_1 = _ids_by_name(mapping_id)
    water, grid = run_1["Water Treatment Service"], run_1["Grid Balancing Service"]
    _decide_ids(mapper, mapping_id, accept=[water], reject=[grid])

    edited = _request().model_copy(update={"service_description": "Generates electricity for the grid."})
    again, created = mapper.create_service_mapping(PRINCIPAL, edited, uuid4().hex)  # the same service
    assert (again.mapping_id, again.generation, created) == (mapping_id, 2, True)
    asked = _run(mapping_id, _second_answer()).prompts[0]
    assert asked["selected_service"]["service_description"] == edited.service_description
    assert asked["already_mapped"] == {
        "upstream": ["Water Treatment Service", "Fuel Logistics Service"],
        "downstream": ["Grid Balancing Service"],
    }
    assert "_id" not in json.dumps(asked["already_mapped"])  # names only
    assert "Water Treatment Service" not in json.dumps(asked["catalog"])  # held: not offered again

    view = mapper.get_service_mapping(PRINCIPAL, mapping_id)
    shown = {
        item.service_name: (item.dependency_id, item.isAccepted, item.generation)
        for item in view.upstream_services + view.downstream_services
    }
    telecom = shown.pop("Telecom Network Service")
    assert shown == {
        "Water Treatment Service": (water, True, 1),
        "Grid Balancing Service": (grid, False, 1),
        "Fuel Logistics Service": (run_1["Fuel Logistics Service"], None, 1),
    }  # run 1's services, ids and decisions unchanged; none of its services added twice
    assert telecom[1:] == (None, 2)
    assert (view.generation, view.generations_done, view.summary.unique_services) == (2, 2, 4)

    third, created = mapper.regenerate_service_mapping(PRINCIPAL, mapping_id, uuid4().hex)
    assert (third.mapping_id, third.generation, created) == (mapping_id, 3, True)
    assert _run(mapping_id, _second_answer()).prompts[0]["selected_service"]["service_description"] == (
        edited.service_description
    )  # Regenerate runs on the details the mapping holds
    assert len(_record(mapping_id)["result"]["dependencies"]) == 4  # nothing new found: nothing added
    assert sent == [_map(mapping_id, 1), _map(mapping_id, 2), _map(mapping_id, 3)]


def test_a_running_mapping_starts_no_second_run(empty_test_database: None) -> None:
    mapper, sent = _mapper()
    mapping_id = mapper.create_service_mapping(PRINCIPAL, _request(), uuid4().hex)[0].mapping_id
    same, created = mapper.create_service_mapping(PRINCIPAL, _request(), uuid4().hex)  # a second click
    assert (same.mapping_id, same.generation, created) == (mapping_id, 1, False)
    edited = _request().model_copy(update={"service_description": "Generates electricity for the grid."})
    for refused in (
        lambda: mapper.create_service_mapping(PRINCIPAL, edited, uuid4().hex),
        lambda: mapper.regenerate_service_mapping(PRINCIPAL, mapping_id, uuid4().hex),
    ):
        with pytest.raises(Conflict) as running:
            refused()
        assert running.value.reason == MapperConflict.GENERATION_IN_PROGRESS
        assert running.value.details is not None and running.value.details["mapping_id"] == mapping_id
    assert sent == [_map(mapping_id, 1)]


def _both_read_first(monkeypatch: pytest.MonkeyPatch, method: str) -> None:
    """MappingRepository's `method` waits until two calls at once both reach it, so each has read the mapping
    before either writes: the race two clicks at once make, every time."""
    both = threading.Barrier(2)
    real = getattr(MappingRepository, method)

    def after_both(self: MappingRepository, *args: Any) -> Any:
        both.wait(timeout=10)
        return real(self, *args)

    monkeypatch.setattr(MappingRepository, method, after_both)


def test_two_clicks_at_once_make_one_mapping_and_one_run(
    empty_test_database: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    mapper, sent = _mapper()
    _both_read_first(monkeypatch, "create")  # both found no mapping for the service
    _both_read_first(monkeypatch, "start_next_run")  # both found it done
    with ThreadPoolExecutor(max_workers=2) as pool:
        made = list(
            pool.map(lambda _: mapper.create_service_mapping(PRINCIPAL, _request(), uuid4().hex), range(2))
        )
    assert len({accepted.mapping_id for accepted, _ in made}) == 1
    assert sorted(created for _, created in made) == [False, True]
    mapping_id = made[0][0].mapping_id
    _run(mapping_id, _answer().model_dump())

    def regenerate(_: int) -> str:
        try:
            return str(mapper.regenerate_service_mapping(PRINCIPAL, mapping_id, uuid4().hex)[1])
        except Conflict as refused:
            return str(refused.reason)

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = sorted(pool.map(regenerate, range(2)))
    assert outcomes == sorted(["True", MapperConflict.GENERATION_IN_PROGRESS])
    assert sent == [_map(mapping_id, 1), _map(mapping_id, 2)]


class _Rows:
    """The SQL catalog's rows; `changed` gives every service a new description (a new catalog version)."""

    changed = False

    def load(self) -> CatalogRows:
        rows = _catalog_rows()
        if not self.changed:
            return rows
        edited = [service | {"service_description": "Changed."} for service in rows.services]
        return replace(rows, services=edited)


def test_a_run_that_would_repeat_one_that_found_nothing_is_not_started(empty_test_database: None) -> None:
    """Owner 2026-10-28: the AI runs at temperature 0, so the same prompt gets the same answer: after a run
    that found nothing new, the same details, counts and catalog start no run and use none."""
    catalog = _Rows()
    mapper, sent = _mapper(catalog=catalog)
    mapping_id = mapper.create_service_mapping(PRINCIPAL, _request(), uuid4().hex)[0].mapping_id
    _run(mapping_id, _answer().model_dump())
    mapper.regenerate_service_mapping(PRINCIPAL, mapping_id, uuid4().hex)
    _run(mapping_id, _answer().model_dump())  # the same services again: nothing new
    for again in (
        lambda: mapper.regenerate_service_mapping(PRINCIPAL, mapping_id, uuid4().hex),
        lambda: mapper.create_service_mapping(PRINCIPAL, _request(), uuid4().hex),
    ):
        skipped, created = again()
        assert (skipped.mapping_id, skipped.status, skipped.generation, created) == (
            mapping_id,
            Status.DONE,
            2,
            False,
        )
    assert (len(sent), _record(mapping_id)["generations_done"]) == (2, 2)  # no job sent, no run used

    edited = _request().model_copy(update={"service_description": "Generates electricity for the grid."})
    assert mapper.create_service_mapping(PRINCIPAL, edited, uuid4().hex)[1] is True  # new details: a run
    _run(mapping_id, _answer().model_dump())
    assert mapper.regenerate_service_mapping(PRINCIPAL, mapping_id, uuid4().hex)[1] is False
    catalog.changed = True  # the onboarding catalog changed: a run again
    assert mapper.regenerate_service_mapping(PRINCIPAL, mapping_id, uuid4().hex)[1] is True
    assert sent[-1] == _map(mapping_id, 4)


def test_the_status_times_the_latest_runs_activities_only(empty_test_database: None) -> None:
    """Owner 2026-10-28: the status shows how long the latest run took to read the catalog and to find the
    services; a new run (Generate again or Regenerate) shows none until it is done, never the run before."""
    mapper, _ = _mapper()
    mapping_id = mapper.create_service_mapping(PRINCIPAL, _request(), uuid4().hex)[0].mapping_id

    def timings() -> tuple[float | None, float | None]:
        shown = mapper.get_service_mapping_status(PRINCIPAL, mapping_id).progress.timings
        return shown.catalog, shown.services

    assert timings() == (None, None)  # queued
    _run(mapping_id, _answer().model_dump())
    catalog, services = timings()
    assert catalog is not None and services is not None and 0 <= catalog < 60 and 0 <= services < 60
    mapper.regenerate_service_mapping(PRINCIPAL, mapping_id, uuid4().hex)
    assert timings() == (None, None)  # the first run's times are gone
    _run(mapping_id, _second_answer())
    assert None not in timings()


def test_the_run_limit_counts_finished_runs_only(empty_test_database: None) -> None:
    settings = container.get_settings().model_copy(update={"service_mapper_max_generations": 2})
    mapper, _ = _mapper(settings)
    mapping_id = mapper.create_service_mapping(PRINCIPAL, _request(), uuid4().hex)[0].mapping_id
    _run(mapping_id, _answer().model_dump())
    mapper.regenerate_service_mapping(PRINCIPAL, mapping_id, uuid4().hex)
    _fail_run(mapping_id)  # a failed run does not count
    mapper.regenerate_service_mapping(PRINCIPAL, mapping_id, uuid4().hex)
    _run(mapping_id, _second_answer())
    for refused in (
        lambda: mapper.regenerate_service_mapping(PRINCIPAL, mapping_id, uuid4().hex),
        lambda: mapper.create_service_mapping(PRINCIPAL, _request(), uuid4().hex),
    ):
        with pytest.raises(Conflict) as spent:
            refused()
        assert spent.value.reason == MapperConflict.GENERATION_LIMIT_REACHED
        assert spent.value.details == {"mapping_id": mapping_id, "max_generations": 2}
    status = mapper.get_service_mapping_status(PRINCIPAL, mapping_id)
    assert (status.generation, status.generations_done, status.max_generations) == (3, 2, 2)


def test_no_run_limit_when_the_setting_is_zero(empty_test_database: None) -> None:
    settings = container.get_settings().model_copy(update={"service_mapper_max_generations": 0})
    mapper, sent = _mapper(settings)
    mapping_id = mapper.create_service_mapping(PRINCIPAL, _request(), uuid4().hex)[0].mapping_id
    records = get_mongodb()[Collection.SERVICE_MAPPINGS]
    for _run_number in range(6):
        records.update_one(
            {"_id": mapping_id}, {"$set": {"status": Status.DONE}, "$inc": {"generations_done": 1}}
        )
        mapper.regenerate_service_mapping(PRINCIPAL, mapping_id, uuid4().hex)
    assert len(sent) == 7


def test_a_decision_made_while_a_run_goes_on_survives_its_append(empty_test_database: None) -> None:
    mapper, _ = _mapper()
    mapping_id = mapper.create_service_mapping(PRINCIPAL, _request(), uuid4().hex)[0].mapping_id
    _run(mapping_id, _answer().model_dump())
    water = _ids_by_name(mapping_id)["Water Treatment Service"]
    mapper.regenerate_service_mapping(PRINCIPAL, mapping_id, uuid4().hex)
    _run(mapping_id, _second_answer(), during=lambda: _decide_ids(mapper, mapping_id, accept=[water]))
    held = {item["dependency_id"]: item for item in _record(mapping_id)["result"]["dependencies"]}
    assert held[water]["relations"]["upstream"]["isAccepted"] is True
    assert len(held) == 4


def test_a_failed_run_keeps_every_service_and_decision(empty_test_database: None) -> None:
    mapper, _ = _mapper()
    mapping_id = mapper.create_service_mapping(PRINCIPAL, _request(), uuid4().hex)[0].mapping_id
    _run(mapping_id, _answer().model_dump())
    water = _ids_by_name(mapping_id)["Water Treatment Service"]
    _decide_ids(mapper, mapping_id, accept=[water])
    mapper.regenerate_service_mapping(PRINCIPAL, mapping_id, uuid4().hex)
    _fail_run(mapping_id)
    view = mapper.get_service_mapping(PRINCIPAL, mapping_id)
    assert view.status == Status.FAILED and view.error is not None and view.error.reason == AiOutage.BUSY
    assert view.summary.unique_services == 3 and view.upstream_services[0].isAccepted is True
    _decide_ids(mapper, mapping_id, reject=[water])  # still decidable


def test_deciding_before_the_first_run_found_anything_says_to_wait_or_regenerate(
    empty_test_database: None,
) -> None:
    mapper, _ = _mapper()
    mapping_id = mapper.create_service_mapping(PRINCIPAL, _request(), uuid4().hex)[0].mapping_id
    _fail_run(mapping_id)
    with pytest.raises(Conflict) as refused:
        mapper.decide_dependencies(PRINCIPAL, mapping_id, DependencyDecisionRequest(accept=["any"]))
    assert (refused.value.status, refused.value.reason) == (409, None)
    assert refused.value.detail == MapperMessage.MAPPING_NOT_READY


def test_the_same_key_replays_the_run_it_started_and_another_body_is_refused(
    empty_test_database: None,
) -> None:
    mapper, sent = _mapper()
    key, regen_key = uuid4().hex, uuid4().hex
    mapping_id = mapper.create_service_mapping(PRINCIPAL, _request(), key)[0].mapping_id
    _run(mapping_id, _answer().model_dump())
    replayed, created = mapper.create_service_mapping(
        PRINCIPAL, _request(), key
    )  # done since: still a replay
    assert (replayed.mapping_id, replayed.generation, created) == (mapping_id, 1, False)
    assert mapper.regenerate_service_mapping(PRINCIPAL, mapping_id, regen_key)[0].generation == 2
    _run(mapping_id, _second_answer())
    replayed, created = mapper.regenerate_service_mapping(PRINCIPAL, mapping_id, regen_key)
    assert (replayed.generation, created) == (2, False)
    assert len(sent) == 2
    edited = _request().model_copy(update={"service_description": "Generates electricity for the grid."})
    with pytest.raises(Conflict) as other_body:
        mapper.create_service_mapping(PRINCIPAL, edited, key)
    assert other_body.value.detail == MapperMessage.IDEMPOTENCY_KEY_CONFLICT
    derived = "derived-" + uuid4().hex  # the server's own key for a request that sent none
    mapper.create_service_mapping(PRINCIPAL, _request(), derived, derived=True)
    with pytest.raises(Conflict) as repeated:
        mapper.create_service_mapping(PRINCIPAL, _request(), derived, derived=True)
    assert repeated.value.reason == ConflictReason.DUPLICATE_REQUEST
