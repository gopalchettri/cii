"""AI dependency generation with a checked JSON answer; one more call when a direction is short."""

from pathlib import Path
from typing import Any

from pydantic import ValidationError

from app.ai.chat import ChatModel, UnreadableAiAnswer
from app.core.constants import AiTask
from app.domain.service_mapper.reconcile import reconcile
from app.domain.shared.names import as_json, shorten_text
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
    """The reconciled dependencies of (mapping_id, generation) and the prompts sent; a short direction gets
    one more AI call."""
    answer, first_prompt = generate_answer(chat, search, request, catalog, counts)
    result = reconcile(*generation, request, answer, catalog, *counts)
    short = (
        counts[0] - result["summary"]["upstream_count"],
        counts[1] - result["summary"]["downstream_count"],
    )
    if not any(short):
        return result | _prompts(first_prompt)
    chosen = [item["service_name"] for item in result["dependencies"]]
    try:
        more, more_prompt = generate_answer(chat, search, request, catalog, short, chosen)
    except UnreadableAiAnswer:
        return result | _prompts(first_prompt)  # fewer than the count is fine
    combined = answer.model_copy(
        update={
            "upstream_services": [*answer.upstream_services, *more.upstream_services],
            "downstream_services": [*answer.downstream_services, *more.downstream_services],
        }
    )
    return reconcile(*generation, request, combined, catalog, *counts) | _prompts(first_prompt, more_prompt)


def _prompts(*user_prompts: str) -> dict[str, Any]:
    """The exact system and user prompts of the AI calls whose answers a generation used."""
    return {"prompts": {"system_prompt": _SYSTEM, "user_prompts": list(user_prompts)}}


def generate_answer(
    chat: ChatModel,
    search: ServiceCandidateSearch,
    request: CreateMappingRequest,
    catalog: CatalogSnapshot,
    counts: tuple[int, int],
    already_selected: list[str] | None = None,
) -> tuple[GeneratedAnswer, str]:
    """AI creates both directions, including out-of-catalog services when they are defensible; returns the
    answer and the user prompt sent."""
    candidates = search.candidates(catalog, _queries(request))
    prompt, included = _user_prompt(
        chat.max_prompt_chars, request, catalog, candidates, counts, already_selected
    )
    allowed = {service.service_id: service.service_name for service in included}

    def check(answer: dict[str, Any]) -> list[str]:
        try:
            parsed = GeneratedAnswer.model_validate(answer)
        except ValidationError as exc:
            return [str(error["loc"]) + ": " + error["msg"] for error in exc.errors()[:10]]
        return [
            f"catalog_service_id {item.catalog_service_id} is not an exact listed candidate; use null"
            for item in (*parsed.upstream_services, *parsed.downstream_services)
            if item.catalog_service_id is not None
            and (
                item.catalog_service_id not in allowed
                or item.service_name.casefold() != allowed[item.catalog_service_id].casefold()
            )
        ][:10]

    answer = chat.ask_for_checked_json(AiTask.SERVICE_MAPPER, _SYSTEM, prompt, check)
    return GeneratedAnswer.model_validate(answer), prompt


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
    already_selected: list[str] | None,
) -> tuple[str, list[CatalogService]]:
    taxonomy = [
        {"sector": group.sector_name, "subsector": group.subsector_name} for group in catalog.sector_groups
    ]
    base: dict[str, Any] = {
        "selected_service": request.model_dump(),
        "sector_taxonomy": taxonomy,
        "upstream_count": counts[0],
        "downstream_count": counts[1],
        "candidate_services": [],
    }
    if already_selected:
        base["already_selected"] = already_selected
    budget = min(int(max_chars * 0.55), max_chars - len(_SYSTEM) - 4_000)
    included: list[CatalogService] = []
    for service in _balanced(candidates):
        entry = _candidate_entry(service)
        proposed = as_json(base | {"candidate_services": [*base["candidate_services"], entry]})
        if len(_SYSTEM) + len(proposed) > budget:
            break
        base["candidate_services"].append(entry)
        included.append(service)
    return as_json(base), included


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
    return {
        "catalog_service_id": service.service_id,
        "service_name": service.service_name,
        "description": shorten_text(service.description, 240),
        "sectors": [
            {"sector": group.sector_name, "subsector": group.subsector_name} for group in service.sectors
        ],
    }
