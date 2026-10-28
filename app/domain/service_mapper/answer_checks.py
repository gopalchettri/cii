"""The problems in an AI answer that reconcile would drop or leave incomplete, for the AI's one corrective
re-ask."""

from app.core.constants import MapperLimits
from app.domain.service_mapper.reconcile import resolve_both, selected_service_id
from app.domain.shared.names import is_same_name, name_match_key
from app.models.service_mapper.catalog import CatalogSnapshot
from app.models.service_mapper.contract import CreateMappingRequest
from app.models.service_mapper.generation import GeneratedAnswer, ResolvedDependency

#: Words too common in service names to show two services are the same one.
_GENERIC_WORDS = frozenset(
    {
        "and", "of", "the", "for", "service", "services", "operation", "operations", "management", "system",
        "systems", "network", "networks", "supply", "supplies", "control", "centre", "center", "public",
        "government",
    }
)  # fmt: skip


def answer_problems(
    request: CreateMappingRequest, answer: GeneratedAnswer, catalog: CatalogSnapshot
) -> list[str]:
    """What reconcile would drop or leave without a sector, for the AI's one corrective re-ask; a service in
    both lists is not asked about: reconcile keeps it where the AI ranked it higher."""
    (upstream, upstream_dropped), (downstream, downstream_dropped) = resolve_both(request, answer, catalog)
    new_items = [item for item in (*upstream, *downstream) if item.ai_suggested]
    record = _selected_record(request, catalog)
    return [
        *(f"upstream_services: {problem}" for problem in upstream_dropped),
        *(f"downstream_services: {problem}" for problem in downstream_dropped),
        *(
            f'"{item.service_name}" needs a sector from catalog'
            for item in new_items
            if item.sector is None and catalog.sector_names
        ),
        *filter(None, (_catalog_alternative(item, catalog, request.service_name) for item in new_items)),
        *(
            f'"{item.service_name}" copies the recorded text, not a service: name the specific service that '
            "provides it"
            for item in new_items
            if record and f" {name_match_key(item.service_name)} " in record
        ),
    ]


def _selected_record(request: CreateMappingRequest, catalog: CatalogSnapshot) -> str:
    """The selected service's recorded dependency text, name-normalised and space-padded ("" when none): a new
    service named with a phrase of it copied a heading ("Technology, hosting and cybersecurity providers")."""
    selected_id = selected_service_id(request, catalog)
    service = next((s for s in catalog.services if s.service_id == selected_id), None)
    text = name_match_key(f"{service.upstream_context} | {service.downstream_context}") if service else ""
    return f" {text} " if text else ""


def _catalog_alternative(
    item: ResolvedDependency, catalog: CatalogSnapshot, selected_name: str
) -> str | None:
    """The re-ask for a new service that looks like a catalog one: same sector (and subsector, when given)
    and a distinctive word in common ("Water Supply" and "Water Production & Transmission"). The AI must use
    the catalog service that provides it and keeps its own name only when none does. A merely related service
    in the same group is never offered: offered one, the AI swaps a needed service for it."""
    if item.sector is None:
        return None
    words = _distinctive_words(item.service_name)
    names = [
        service.service_name
        for service in catalog.services
        if not is_same_name(service.service_name, selected_name)
        and words & _distinctive_words(service.service_name)
        and any(
            group.sector_name == item.sector
            and (item.subsector is None or group.subsector_name == item.subsector)
            for group in service.sectors
        )
    ]
    if not names:
        return None
    where = f"{item.sector} / {item.subsector}" if item.subsector else item.sector
    listed = ", ".join(f'"{name}"' for name in names[: MapperLimits.REASK_NAMES_SHOWN])
    return (
        f'"{item.service_name}" is new, but catalog {where} already has {listed}: '
        f'use the one that provides it, or keep "{item.service_name}" only if none does'
    )


def _distinctive_words(name: str) -> set[str]:
    return set(name_match_key(name).split()) - _GENERIC_WORDS
