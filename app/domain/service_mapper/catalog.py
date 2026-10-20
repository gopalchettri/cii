"""Normalize the four verified SQL results without parsing ambiguous comma-separated associations."""

import hashlib
import json
from dataclasses import asdict
from typing import Any

from app.core.constants import MapperMessage
from app.core.exceptions import SetupError
from app.models.service_mapper.catalog import (
    CatalogRows,
    CatalogService,
    CatalogSnapshot,
    EntityAssociation,
    SectorAssociation,
)


def build_catalog(rows: CatalogRows) -> CatalogSnapshot:
    try:
        return _build_catalog(rows)
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise SetupError(MapperMessage.CATALOG_ROW_INVALID) from exc


def _build_catalog(rows: CatalogRows) -> CatalogSnapshot:
    sectors = _sectors(rows.sectors)
    top_names = tuple(sorted((name for name, parent in sectors.values() if parent is None), key=str.casefold))
    reported = tuple(sorted((str(row["SectorName"]) for row in rows.sector_summary), key=str.casefold))
    if reported != top_names:
        raise ValueError(MapperMessage.CATALOG_ROW_INVALID)
    source = _services(rows.services)
    _check_old_mappings(rows.service_mappings, source, sectors)
    sector_links = _sector_links(rows.sector_links, source, sectors)
    entity_links = _entity_links(rows.entity_links, source, sectors)
    services = tuple(
        _catalog_service(service_id, source[service_id], sector_links, entity_links, sectors)
        for service_id in sorted(source)
    )
    groups = tuple(sorted((_sector_association(key, sectors) for key in sectors), key=_association_order))
    payload = json.dumps(
        {
            "sectors": [asdict(group) for group in groups],
            "services": [asdict(service) for service in services],
        },
        ensure_ascii=False,
        sort_keys=True,
    )
    version = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return CatalogSnapshot(version, top_names, groups, services)


def _sectors(rows: list[dict[str, Any]]) -> dict[int, tuple[str, int | None]]:
    found: dict[int, tuple[str, int | None]] = {}
    for row in rows:
        sector_id, name = int(row["sector_id"]), str(row["sector_name"]).strip()
        parent = row["parent_sector_id"]
        if sector_id <= 0 or not name or sector_id in found:
            raise ValueError(MapperMessage.CATALOG_ROW_INVALID)
        found[sector_id] = name, int(parent) if parent is not None else None
    for _name, parent in found.values():
        if parent is not None and (parent not in found or found[parent][1] is not None):
            raise ValueError(MapperMessage.CATALOG_ROW_INVALID)
    return found


def _services(rows: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
    found: dict[int, dict[str, Any]] = {}
    for row in rows:
        service_id, name = int(row["service_id"]), str(row["service_name"]).strip()
        if service_id <= 0 or not name or service_id in found:
            raise ValueError(MapperMessage.CATALOG_ROW_INVALID)
        found[service_id] = row
    return found


def _check_old_mappings(
    mappings: list[dict[str, Any]],
    services: dict[int, dict[str, Any]],
    sectors: dict[int, tuple[str, int | None]],
) -> None:
    for row in mappings:
        service_id, sector_id = int(row["service_id"]), int(row["sector_id"])
        if service_id not in services or sector_id not in sectors:
            continue  # the onboarding procedure does not filter deleted rows
        if str(row["service_name"]).strip() != str(services[service_id]["service_name"]).strip():
            raise ValueError(MapperMessage.CATALOG_ROW_INVALID)
        if str(row["sector_name"]).strip() != sectors[sector_id][0]:
            raise ValueError(MapperMessage.CATALOG_ROW_INVALID)


def _sector_links(
    rows: list[dict[str, Any]],
    services: dict[int, dict[str, Any]],
    sectors: dict[int, tuple[str, int | None]],
) -> dict[int, set[int]]:
    links: dict[int, set[int]] = {service_id: set() for service_id in services}
    for row in rows:
        service_id, sector_id = int(row["service_id"]), int(row["sector_id"])
        if service_id not in services or sector_id not in sectors:
            raise ValueError(MapperMessage.CATALOG_ROW_INVALID)
        links[service_id].add(sector_id)
    return links


def _entity_links(
    rows: list[dict[str, Any]],
    services: dict[int, dict[str, Any]],
    sectors: dict[int, tuple[str, int | None]],
) -> dict[int, set[EntityAssociation]]:
    links: dict[int, set[EntityAssociation]] = {service_id: set() for service_id in services}
    for row in rows:
        service_id, sector_id = int(row["service_id"]), int(row["sector_id"])
        name = str(row["entity_name"]).strip()
        entity_id = int(row["entity_id"])
        if service_id not in services or sector_id not in sectors or entity_id <= 0 or not name:
            raise ValueError(MapperMessage.CATALOG_ROW_INVALID)
        links[service_id].add(EntityAssociation(entity_id, name, sector_id))
    return links


def _catalog_service(
    service_id: int,
    row: dict[str, Any],
    links: dict[int, set[int]],
    entities: dict[int, set[EntityAssociation]],
    sectors: dict[int, tuple[str, int | None]],
) -> CatalogService:
    associations: set[SectorAssociation] = set()
    linked = links[service_id]
    for sector_id in linked:
        name, parent = sectors[sector_id]
        if parent is None:
            if not any(sectors[other][1] == sector_id for other in linked):
                associations.add(SectorAssociation(sector_id, name, None, None))
        else:
            associations.add(SectorAssociation(parent, sectors[parent][0], sector_id, name))
    ordered = tuple(sorted(associations, key=_association_order))
    return CatalogService(
        service_id,
        str(row["service_name"]).strip(),
        str(row.get("service_description") or "").strip(),
        ordered,
        tuple(sorted(entities[service_id])),
        str(row.get("upstream_dependencies") or "").strip(),
        str(row.get("downstream_dependencies") or "").strip(),
    )


def _association_order(association: SectorAssociation) -> tuple[int, str, str, int]:
    return (
        0 if association.subsector_id is not None else 1,
        association.sector_name.casefold(),
        (association.subsector_name or "").casefold(),
        association.subsector_id or association.sector_id,
    )


def _sector_association(sector_id: int, sectors: dict[int, tuple[str, int | None]]) -> SectorAssociation:
    name, parent = sectors[sector_id]
    if parent is None:
        return SectorAssociation(sector_id, name, None, None)
    return SectorAssociation(parent, sectors[parent][0], sector_id, name)
