"""Canonical matching, direct-dependency filtering, global deduplication and directional caps."""

from collections import defaultdict
from dataclasses import asdict, replace
from uuid import NAMESPACE_URL, uuid5

from app.core.prompts import PROMPTS
from app.domain.shared.names import is_same_name, name_match_key
from app.models.service_mapper.catalog import CatalogService, CatalogSnapshot
from app.models.service_mapper.contract import CreateMappingRequest
from app.models.service_mapper.generation import GeneratedAnswer, ProposedDependency, ResolvedDependency

_TOO_VAGUE: str = PROMPTS["service_mapper"]["generate"]["too_vague"]


def reconcile(
    mapping_id: str,
    generation: int,
    request: CreateMappingRequest,
    answer: GeneratedAnswer,
    catalog: CatalogSnapshot,
    max_upstream: int,
    max_downstream: int,
) -> dict:
    (upstream, _), (downstream, _) = resolve_both(request, answer, catalog)
    upstream, downstream = _one_direction(upstream, downstream)
    upstream = upstream[:max_upstream]
    downstream = downstream[:max_downstream]
    dependencies = _merge(mapping_id, generation, upstream, downstream, catalog)
    selected = request.model_dump() | {
        "service_id": selected_service_id(request, catalog),
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


def selected_service_id(request: CreateMappingRequest, catalog: CatalogSnapshot) -> int | None:
    """The catalog id of the selected service when exactly one service has its name, sector and subsector."""
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


def resolve_both(
    request: CreateMappingRequest, answer: GeneratedAnswer, catalog: CatalogSnapshot
) -> tuple[tuple[list[ResolvedDependency], list[str]], tuple[list[ResolvedDependency], list[str]]]:
    """Both directions resolved (kept, dropped). A new downstream service that is an upstream new one in
    another form ("Payment Settlement Service" for "Payment Settlement Service (PSS)") takes its identity, so
    it counts once."""
    selected_id = selected_service_id(request, catalog)
    upstream, up_dropped = resolve_proposals(
        answer.upstream_services, catalog, request.service_name, selected_id
    )
    downstream, down_dropped = resolve_proposals(
        answer.downstream_services, catalog, request.service_name, selected_id
    )
    downstream = [
        next((replace(item, identity=up.identity) for up in upstream if _same_new_service(up, item)), item)
        for item in downstream
    ]
    selected = next((service for service in catalog.services if service.service_id == selected_id), None)
    upstream = _recorded_only_with_a_record(
        upstream,
        selected.upstream_context if selected else "",
        {service.service_id: service.downstream_context for service in catalog.services},
    )
    downstream = _recorded_only_with_a_record(
        downstream,
        selected.downstream_context if selected else "",
        {service.service_id: service.upstream_context for service in catalog.services},
    )
    return (upstream, up_dropped), (downstream, down_dropped)


def _recorded_only_with_a_record(
    items: list[ResolvedDependency], selected_record: str, other_records: dict[int, str]
) -> list[ResolvedDependency]:
    """A "Recorded:" reason needs a record of the link in the input (the selected service's known text in this
    direction, or the other service's in the opposite one); without one it says "Inferred:"."""
    # ponytail: any record in that direction counts; free text cannot be matched to one service reliably.
    return [
        replace(item, dependency_reason="Inferred:" + item.dependency_reason.removeprefix("Recorded:"))
        if item.dependency_reason.startswith("Recorded:")
        and not (selected_record or other_records.get(item.service_id or 0))
        else item
        for item in items
    ]


def _same_new_service(a: ResolvedDependency, b: ResolvedDependency) -> bool:
    """Two services the AI named itself that are one service in two forms, either way round."""
    return (
        a.ai_suggested
        and b.ai_suggested
        and (is_same_name(a.service_name, b.service_name) or is_same_name(b.service_name, a.service_name))
    )


def resolve_proposals(
    proposals: list[ProposedDependency],
    catalog: CatalogSnapshot,
    selected_name: str,
    selected_id: int | None,
) -> tuple[list[ResolvedDependency], list[str]]:
    """The kept dependencies in the AI's order, and why each proposal the AI must fix was dropped (the
    selected service itself and a repeat go silently: nothing a user wants goes with them)."""
    by_name: dict[str, list[CatalogService]] = defaultdict(list)
    for service in catalog.services:
        by_name[name_match_key(service.service_name)].append(service)
    labels = {
        name_match_key(name)
        for group in catalog.sector_groups
        for name in (group.sector_name, group.subsector_name)
        if name
    }
    kept: dict[str, ResolvedDependency] = {}
    dropped: list[str] = []
    for rank, proposal in enumerate(proposals):
        name = f'"{proposal.service_name}"'
        matches = _catalog_matches(proposal, by_name, catalog.services)
        if len(matches) > 1:  # a shared name never becomes a guessed or invented service
            dropped.append(
                f"{name} names several catalog services: copy the sector and subsector of the one meant"
            )
        elif (matches and matches[0].service_id == selected_id) or (
            is_same_name(proposal.service_name, selected_name)
            or is_same_name(selected_name, proposal.service_name)
        ):
            continue  # never a dependency of itself
        elif not matches and name_match_key(proposal.service_name) in labels:
            dropped.append(f"{name} is a sector or subsector name, not a service: name the service")
        elif (resolved := _resolve_one(proposal, matches[0] if matches else None, catalog, rank)) is None:
            dropped.append(f"{name} {_TOO_VAGUE}")
        elif resolved.identity in kept or any(_same_new_service(item, resolved) for item in kept.values()):
            continue  # the first, stronger mention stays
        else:
            kept[resolved.identity] = resolved
    return list(kept.values()), dropped


def _one_direction(
    upstream: list[ResolvedDependency], downstream: list[ResolvedDependency]
) -> tuple[list[ResolvedDependency], list[ResolvedDependency]]:
    """A service in both lists stays only where the AI ranked it higher (upstream on a tie)."""
    up_rank = {item.identity: item.rank for item in upstream}
    down_rank = {item.identity: item.rank for item in downstream}
    return (
        [item for item in upstream if item.rank <= down_rank.get(item.identity, item.rank)],
        [item for item in downstream if item.rank < up_rank.get(item.identity, item.rank + 1)],
    )


def _catalog_matches(
    proposal: ProposedDependency,
    by_name: dict[str, list[CatalogService]],
    services: tuple[CatalogService, ...],
) -> list[CatalogService]:
    """The catalog services a proposal names, by exact name or else by a name form ("PGS"); several sharing it
    are narrowed to the one in the proposal's sector and subsector."""
    matches = by_name.get(name_match_key(proposal.service_name)) or [
        service for service in services if is_same_name(service.service_name, proposal.service_name)
    ]
    if len(matches) < 2:
        return matches
    sector, subsector = name_match_key(proposal.sector or ""), name_match_key(proposal.subsector or "")
    narrowed = [
        service
        for service in matches
        if any(
            name_match_key(group.sector_name) == sector
            and name_match_key(group.subsector_name or "") == subsector
            for group in service.sectors
        )
    ]
    return narrowed if len(narrowed) == 1 else matches


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
