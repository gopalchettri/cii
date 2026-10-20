"""Typed, normalized master-service catalog and its raw stored-procedure result sets."""

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CatalogRows:
    sector_summary: list[dict[str, Any]]
    service_mappings: list[dict[str, Any]]
    services: list[dict[str, Any]]
    sectors: list[dict[str, Any]]
    sector_links: list[dict[str, Any]]
    entity_links: list[dict[str, Any]]


@dataclass(frozen=True, order=True)
class SectorAssociation:
    sector_id: int
    sector_name: str
    subsector_id: int | None
    subsector_name: str | None


@dataclass(frozen=True, order=True)
class EntityAssociation:
    entity_id: int
    entity_name: str
    sector_id: int


@dataclass(frozen=True)
class CatalogService:
    service_id: int
    service_name: str
    description: str
    sectors: tuple[SectorAssociation, ...]
    entities: tuple[EntityAssociation, ...]
    upstream_context: str
    downstream_context: str

    @property
    def primary_sector(self) -> SectorAssociation | None:
        return self.sectors[0] if self.sectors else None


@dataclass(frozen=True)
class CatalogSnapshot:
    version: str
    sector_names: tuple[str, ...]
    sector_groups: tuple[SectorAssociation, ...]
    services: tuple[CatalogService, ...]
