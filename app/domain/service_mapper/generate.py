"""AI dependency generation with a checked JSON answer; items reconcile would drop are asked again once."""

from pathlib import Path
from typing import Any

from pydantic import ValidationError

from app.ai.chat import ChatModel
from app.core.constants import AiTask
from app.domain.service_mapper.answer_checks import answer_problems
from app.domain.service_mapper.reconcile import reconcile, selected_service_id
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
    """AI creates both directions from every catalog service grouped by sector and subsector, adding a new
    service only where none provides it. The AI sees names only, never a catalog ID; a first answer with items
    reconcile would drop is asked again once with why."""
    services = _most_relevant_first(search, request, catalog)
    budget = min(int(chat.max_prompt_chars * 0.55), chat.max_prompt_chars - len(_SYSTEM) - 4_000)
    prompt = _user_prompt(request, catalog, services, counts)
    if len(_SYSTEM) + len(prompt) > budget:
        # ponytail: a catalog too large for one prompt keeps its services most similar to the selected one.
        prompt = _user_prompt(request, catalog, [], counts)
        for kept in range(1, len(services) + 1):
            longer = _user_prompt(request, catalog, services[:kept], counts)
            if len(_SYSTEM) + len(longer) > budget:
                break
            prompt = longer

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


def _most_relevant_first(
    search: ServiceCandidateSearch, request: CreateMappingRequest, catalog: CatalogSnapshot
) -> list[CatalogService]:
    """Every catalog service but the selected one, those the search ranks first ahead and the rest after."""
    rank = {
        service.service_id: place
        for place, service in enumerate(search.candidates(catalog, _queries(request)))
    }
    return sorted(
        (service for service in catalog.services if not _is_selected(service, request)),
        key=lambda service: rank.get(service.service_id, len(rank)),
    )


def _is_selected(service: CatalogService, request: CreateMappingRequest) -> bool:
    return is_same_name(service.service_name, request.service_name) or is_same_name(
        request.service_name, service.service_name
    )


def _queries(request: CreateMappingRequest) -> list[str]:
    role = f"{request.service_name}. {request.service_description}. {request.sector} / {request.subsector}"
    return [
        role,
        f"Direct upstream services and operational inputs needed by: {role}",
        f"Direct downstream services consuming the outputs or capabilities of: {role}",
    ]


def _user_prompt(
    request: CreateMappingRequest,
    catalog: CatalogSnapshot,
    services: list[CatalogService],
    counts: tuple[int, int],
) -> str:
    return as_json(
        {
            "selected_service": request.model_dump() | _selected_known_dependencies(request, catalog),
            "upstream_count": counts[0],
            "downstream_count": counts[1],
            "catalog": _catalog_groups(catalog, services),
        }
    )


def _selected_known_dependencies(request: CreateMappingRequest, catalog: CatalogSnapshot) -> dict[str, str]:
    """The selected service's own recorded upstream/downstream from the database, when it is in the catalog:
    what the AI decides on first (it is left out of the catalog list, so it would never see them)."""
    selected_id = selected_service_id(request, catalog)
    service = next((s for s in catalog.services if s.service_id == selected_id), None)
    if service is None:
        return {}
    known = {"known_upstream": service.upstream_context, "known_downstream": service.downstream_context}
    return {key: shorten_text(text, 1000) for key, text in known.items() if text}


def _catalog_groups(catalog: CatalogSnapshot, services: list[CatalogService]) -> list[dict[str, Any]]:
    """Every sector and subsector of the taxonomy with the given services linked to it, in the order of the
    services (most relevant first), empty groups last; a sector-level group (subsector null) is listed only
    when it has services or the sector has no subsectors. A service in several groups is described in the
    first only; the others carry its name alone, so its details are never sent twice."""
    groups: dict[tuple[str, str | None], list[dict[str, Any]]] = {}
    for service in services:
        for place, group in enumerate(service.sectors):
            entry = _service_entry(service) if place == 0 else {"service_name": service.service_name}
            groups.setdefault((group.sector_name, group.subsector_name), []).append(entry)
    for group in sorted(
        catalog.sector_groups, key=lambda group: (group.sector_name, group.subsector_name or "")
    ):
        groups.setdefault((group.sector_name, group.subsector_name), [])
    with_subsectors = {sector for sector, subsector in groups if subsector}
    return [
        {"sector": sector, "subsector": subsector, "services": entries}
        for (sector, subsector), entries in groups.items()
        if subsector or entries or sector not in with_subsectors
    ]


def _service_entry(service: CatalogService) -> dict[str, Any]:
    entry: dict[str, Any] = {"service_name": service.service_name}
    if service.description and service.description.casefold() != service.service_name.casefold():
        entry["description"] = shorten_text(service.description, 240)
    if service.upstream_context:
        entry["known_upstream"] = shorten_text(service.upstream_context, 240)
    if service.downstream_context:
        entry["known_downstream"] = shorten_text(service.downstream_context, 240)
    return entry
