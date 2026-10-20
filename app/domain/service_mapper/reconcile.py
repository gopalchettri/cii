"""Canonical matching, direct-dependency filtering, global deduplication and directional caps."""

from collections import defaultdict
from dataclasses import asdict
from uuid import NAMESPACE_URL, uuid5

from app.domain.shared.names import is_same_name, name_match_key
from app.models.service_mapper.catalog import CatalogService, CatalogSnapshot
from app.models.service_mapper.contract import CreateMappingRequest
from app.models.service_mapper.generation import GeneratedAnswer, ProposedDependency, ResolvedDependency


def reconcile(
    mapping_id: str,
    generation: int,
    request: CreateMappingRequest,
    answer: GeneratedAnswer,
    catalog: CatalogSnapshot,
    max_upstream: int,
    max_downstream: int,
) -> dict:
    selected_id = _selected_id(request, catalog)
    upstream = _resolve_list(answer.upstream_services, catalog, request.service_name, selected_id)
    downstream = _resolve_list(answer.downstream_services, catalog, request.service_name, selected_id)
    upstream = upstream[:max_upstream]
    downstream = downstream[:max_downstream]
    dependencies = _merge(mapping_id, generation, upstream, downstream, catalog)
    selected = request.model_dump() | {
        "service_id": selected_id,
        "operational_context": answer.operational_context,
    }
    return {
        "selected_service": selected,
        "dependencies": dependencies,
        "catalog_version": catalog.version,
        "summary": {
            "unique_services": len(dependencies),
            "upstream_count": len(upstream),
            "downstream_count": len(downstream),
            "max_upstream": max_upstream,
            "max_downstream": max_downstream,
        },
    }


def _selected_id(request: CreateMappingRequest, catalog: CatalogSnapshot) -> int | None:
    sector, subsector = name_match_key(request.sector), name_match_key(request.subsector)
    matches = [
        service.service_id
        for service in catalog.services
        if is_same_name(service.service_name, request.service_name)
        and any(
            name_match_key(group.sector_name) == sector
            and name_match_key(group.subsector_name or "") == subsector
            for group in service.sectors
        )
    ]
    return matches[0] if len(matches) == 1 else None


def _resolve_list(
    proposals: list[ProposedDependency],
    catalog: CatalogSnapshot,
    selected_name: str,
    selected_id: int | None,
) -> list[ResolvedDependency]:
    by_id = {service.service_id: service for service in catalog.services}
    by_name: dict[str, list[CatalogService]] = defaultdict(list)
    for service in catalog.services:
        by_name[name_match_key(service.service_name)].append(service)
    kept: dict[str, ResolvedDependency] = {}
    for rank, proposal in enumerate(proposals):
        name_matches = by_name.get(name_match_key(proposal.service_name), [])
        if proposal.catalog_service_id is None and len(name_matches) > 1:
            continue  # ambiguous master name requires an explicit, verified ID
        alias_matches = [
            candidate
            for candidate in catalog.services
            if is_same_name(candidate.service_name, proposal.service_name)
        ]
        if proposal.catalog_service_id is None and len(alias_matches) > 1:
            continue  # a shared short form must not become an invented out-of-catalog service
        matched_service = _match_service(proposal, by_id, by_name, catalog.services)
        if proposal.catalog_service_id is not None and matched_service is None:
            continue  # a fabricated or mismatched catalog ID is never presented as a master service
        if matched_service is not None and matched_service.service_id == selected_id:
            continue
        if is_same_name(proposal.service_name, selected_name) or is_same_name(
            selected_name, proposal.service_name
        ):
            continue
        resolved = _resolve_one(proposal, matched_service, catalog, rank)
        if resolved is not None and resolved.identity not in kept:
            kept[resolved.identity] = resolved
    return list(kept.values())


def _match_service(
    proposal: ProposedDependency,
    by_id: dict[int, CatalogService],
    by_name: dict[str, list[CatalogService]],
    services: tuple[CatalogService, ...],
) -> CatalogService | None:
    if proposal.catalog_service_id is not None:
        service = by_id.get(proposal.catalog_service_id)
        return service if service and is_same_name(service.service_name, proposal.service_name) else None
    matches = by_name.get(name_match_key(proposal.service_name), [])
    if len(matches) == 1:
        return matches[0]
    if matches:
        return None  # duplicate names need a verified ID
    aliases = [service for service in services if is_same_name(service.service_name, proposal.service_name)]
    return aliases[0] if len(aliases) == 1 else None


def _resolve_one(
    proposal: ProposedDependency,
    service: CatalogService | None,
    catalog: CatalogSnapshot,
    rank: int,
) -> ResolvedDependency | None:
    if service is not None:
        group = service.primary_sector
        identity = f"id:{service.service_id}"
        return ResolvedDependency(
            identity,
            service.service_id,
            service.service_name,
            group.sector_name if group else None,
            group.subsector_name if group else None,
            False,
            proposal.dependency_reason,
            proposal.applicability,
            rank,
        )
    if len(name_match_key(proposal.service_name).split()) < 2:
        return None  # an unmatched one-word capability is too vague to present as a service
    sector, subsector = _taxonomy(proposal, catalog)
    return ResolvedDependency(
        f"name:{name_match_key(proposal.service_name)}",
        None,
        proposal.service_name,
        sector,
        subsector,
        True,
        proposal.dependency_reason,
        proposal.applicability,
        rank,
    )


def _taxonomy(proposal: ProposedDependency, catalog: CatalogSnapshot) -> tuple[str | None, str | None]:
    sector = next(
        (
            name
            for name in catalog.sector_names
            if name_match_key(name) == name_match_key(proposal.sector or "")
        ),
        None,
    )
    if sector is None:
        return None, None
    matching = [
        group.subsector_name
        for group in catalog.sector_groups
        if group.sector_name == sector
        and group.subsector_name
        and name_match_key(group.subsector_name) == name_match_key(proposal.subsector or "")
    ]
    return sector, matching[0] if len(matching) == 1 else None


def _merge(
    mapping_id: str,
    generation: int,
    upstream: list[ResolvedDependency],
    downstream: list[ResolvedDependency],
    catalog: CatalogSnapshot,
) -> list[dict]:
    records: dict[str, dict] = {}
    by_id = {service.service_id: service for service in catalog.services}
    for direction, items in (("upstream", upstream), ("downstream", downstream)):
        for item in items:
            record = records.setdefault(item.identity, _record(mapping_id, generation, item, by_id))
            record["relations"][direction] = {
                "dependency_reason": item.dependency_reason,
                "applicability": item.applicability,
                "isAccepted": None,
                "accepted_datetime": None,
                "accepted_by": None,
                "reviewed_datetime": None,
                "reviewed_by": None,
            }
    return sorted(records.values(), key=lambda item: (item["rank"], item["dependency_id"]))


def _record(
    mapping_id: str,
    generation: int,
    item: ResolvedDependency,
    by_id: dict[int, CatalogService],
) -> dict:
    matched = by_id.get(item.service_id) if item.service_id is not None else None
    return {
        "dependency_id": uuid5(NAMESPACE_URL, f"{mapping_id}:{generation}:{item.identity}").hex,
        "identity": item.identity,
        "service_id": item.service_id,
        "service_name": item.service_name,
        "sector": item.sector,
        "subsector": item.subsector,
        "ai_suggested": item.ai_suggested,
        "rank": item.rank,
        "additional_sector_associations": [asdict(group) for group in matched.sectors[1:]] if matched else [],
        "entity_associations": [asdict(entity) for entity in matched.entities] if matched else [],
        "relations": {},
    }
