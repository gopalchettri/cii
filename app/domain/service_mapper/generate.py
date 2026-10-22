"""AI dependency generation with a checked JSON answer; items reconcile would drop are asked again once."""

from pathlib import Path
from typing import Any

from pydantic import ValidationError

from app.ai.chat import ChatModel
from app.core.constants import AiTask
from app.domain.service_mapper.reconcile import answer_problems, reconcile
from app.domain.shared.names import as_json, is_same_name, shorten_text
from app.models.service_mapper.catalog import CatalogService, CatalogSnapshot
from app.models.service_mapper.contract import CreateMappingRequest
from app.models.service_mapper.generation import GeneratedAnswer
from app.search.service_mapper import ServiceCandidateSearch

_SYSTEM = (Path(__file__).parent / "prompts" / "generate.txt").read_text(encoding="utf-8")


def generate_result(
    chat: ChatModel,
    search: ServiceCandidateSearch,
    request: CreateMappingRequest,
    catalog: CatalogSnapshot,
    generation: tuple[str, int],
    counts: tuple[int, int],
) -> dict:
    """The reconciled dependencies of (mapping_id, generation)."""
    answer = generate_answer(chat, search, request, catalog, counts)
    return reconcile(*generation, request, answer, catalog, *counts)


def generate_answer(
    chat: ChatModel,
    search: ServiceCandidateSearch,
    request: CreateMappingRequest,
    catalog: CatalogSnapshot,
    counts: tuple[int, int],
) -> GeneratedAnswer:
    """AI creates both directions, out-of-catalog services included when defensible. The AI sees names only,
    never a catalog ID; a first answer with items reconcile would drop is asked again once with why."""
    candidates = [
        service
        for service in search.candidates(catalog, _queries(request))
        if not is_same_name(service.service_name, request.service_name)
        and not is_same_name(request.service_name, service.service_name)
    ]
    prompt = _user_prompt(chat.max_prompt_chars, request, catalog, candidates, counts)

    def check(answer: dict[str, Any]) -> list[str]:
        try:
            GeneratedAnswer.model_validate(answer)
        except ValidationError as exc:
            return [str(error["loc"]) + ": " + error["msg"] for error in exc.errors()[:10]]
        return []

    def dropped_items(answer: dict[str, Any]) -> list[str]:
        return answer_problems(request, GeneratedAnswer.model_validate(answer), catalog)

    answer = chat.ask_for_checked_json(AiTask.SERVICE_MAPPER, _SYSTEM, prompt, check, dropped_items)
    return GeneratedAnswer.model_validate(answer)


def _queries(request: CreateMappingRequest) -> list[str]:
    role = f"{request.service_name}. {request.service_description}. {request.sector} / {request.subsector}"
    return [
        role,
        f"Direct upstream services and operational inputs needed by: {role}",
        f"Direct downstream services consuming the outputs or capabilities of: {role}",
    ]


def _user_prompt(
    max_chars: int,
    request: CreateMappingRequest,
    catalog: CatalogSnapshot,
    candidates: list[CatalogService],
    counts: tuple[int, int],
) -> str:
    taxonomy: dict[str, list[str]] = {}
    for group in catalog.sector_groups:
        subsectors = taxonomy.setdefault(group.sector_name, [])
        if group.subsector_name:
            subsectors.append(group.subsector_name)
    base: dict[str, Any] = {
        "selected_service": request.model_dump(),
        "sector_taxonomy": taxonomy,
        "upstream_count": counts[0],
        "downstream_count": counts[1],
        "candidate_services": [],
    }
    budget = min(int(max_chars * 0.55), max_chars - len(_SYSTEM) - 4_000)
    for service in _balanced(candidates):
        entry = _candidate_entry(service)
        proposed = as_json(base | {"candidate_services": [*base["candidate_services"], entry]})
        if len(_SYSTEM) + len(proposed) > budget:
            break
        base["candidate_services"].append(entry)
    return as_json(base)


def _balanced(candidates: list[CatalogService]) -> list[CatalogService]:
    first: list[CatalogService] = []
    seen: set[str] = set()
    for service in candidates:
        sector = service.primary_sector.sector_name if service.primary_sector else ""
        if sector not in seen:
            first.append(service)
            seen.add(sector)
    ids = {service.service_id for service in first}
    return [*first, *(service for service in candidates if service.service_id not in ids)]


def _candidate_entry(service: CatalogService) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "service_name": service.service_name,
        "description": shorten_text(service.description, 240),
        "sectors": [
            {"sector": group.sector_name, "subsector": group.subsector_name} for group in service.sectors
        ],
    }
    if service.upstream_context:
        entry["known_upstream"] = shorten_text(service.upstream_context, 240)
    if service.downstream_context:
        entry["known_downstream"] = shorten_text(service.downstream_context, 240)
    return entry
