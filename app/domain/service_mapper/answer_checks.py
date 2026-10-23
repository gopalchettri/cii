"""The problems in an AI answer that reconcile would drop or leave incomplete, for the AI's one corrective
re-ask."""

from app.domain.service_mapper.reconcile import resolve_both
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
    """What reconcile would drop or leave without a sector, for the AI's one corrective re-ask."""
    (upstream, upstream_dropped), (downstream, downstream_dropped) = resolve_both(request, answer, catalog)
    in_both = {item.identity for item in upstream} & {item.identity for item in downstream}
    new_items = [item for item in (*upstream, *downstream) if item.ai_suggested]
    return [
        *(f"upstream_services: {problem}" for problem in upstream_dropped),
        *(f"downstream_services: {problem}" for problem in downstream_dropped),
        *(
            f'"{item.service_name}" is in both lists: keep it only in its strongest direction'
            for item in upstream
            if item.identity in in_both
        ),
        *(
            f'"{item.service_name}" needs a sector from catalog'
            for item in new_items
            if item.sector is None and catalog.sector_names
        ),
        *filter(None, (_catalog_alternative(item, catalog, request.service_name) for item in new_items)),
    ]


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
    listed = ", ".join(f'"{name}"' for name in names[:8])
    return (
        f'"{item.service_name}" is new, but catalog {where} already has {listed}: '
        f'use the one that provides it, or keep "{item.service_name}" only if none does'
    )


def _distinctive_words(name: str) -> set[str]:
    return set(name_match_key(name).split()) - _GENERIC_WORDS
