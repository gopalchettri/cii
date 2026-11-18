"""The onboarding catalog: its SQL rows checked and normalised, read at most once a minute, and searched."""

import hashlib
import json
import threading
import time
from dataclasses import asdict, dataclass

from app import ai
from app.core.constants import EMBEDDING_SOURCE_TABLE, EmbeddingCorpus
from app.core.database import get_stored_procedure_client
from app.core.exceptions import SetupError
from app.crud import service_mapper as crud
from app.search.indexes import HybridIndex, fuse_by_rank

_CACHE_SECONDS = 60
_CANDIDATE_POOL = 80
_catalog_lock, _index_lock = threading.Lock(), threading.Lock()
_catalog: dict = {}  # this process's catalog and when it is read again
_index: dict = {}  # this process's hybrid index of the catalog, and its catalog version


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
    def primary_names(self) -> tuple[str | None, str | None]:
        """The first group's sector and subsector names; (None, None) without a sector."""
        return (self.sectors[0].sector_name, self.sectors[0].subsector_name) if self.sectors else (None, None)


@dataclass(frozen=True)
class CatalogSnapshot:
    version: str
    sector_names: tuple[str, ...]
    sector_groups: tuple[SectorAssociation, ...]
    services: tuple[CatalogService, ...]


def catalog_snapshot() -> CatalogSnapshot:
    """The catalog, read from SQL Server at most once every _CACHE_SECONDS in this process."""
    with _catalog_lock:
        now = time.monotonic()
        if "catalog" not in _catalog or now >= _catalog["until"]:
            rows = crud.load_catalog_rows(get_stored_procedure_client())
            _catalog.update(catalog=build_catalog(*rows), until=now + _CACHE_SECONDS)
        return _catalog["catalog"]


def build_catalog(
    service_rows: list[dict], sector_rows: list[dict], sector_links: list[dict], entity_links: list[dict]
) -> CatalogSnapshot:
    """The catalog the procedures returned; SetupError when a row is invalid or names an unknown id."""
    try:
        return _build(service_rows, sector_rows, sector_links, entity_links)
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise SetupError("The Service Mapper SQL catalog contains an invalid or inconsistent row.") from exc


def _build(
    service_rows: list[dict], sector_rows: list[dict], sector_links: list[dict], entity_links: list[dict]
) -> CatalogSnapshot:
    sectors = _sectors(sector_rows)
    rows: dict[int, dict] = {}
    for row in service_rows:
        service_id, name = int(row["service_id"]), str(row["service_name"]).strip()
        _check(service_id > 0 and name and service_id not in rows)
        rows[service_id] = row
    links: dict[int, set[int]] = {service_id: set() for service_id in rows}
    for row in sector_links:  # an unknown service or sector is a KeyError
        links[int(row["service_id"])].add(int(row["sector_id"]))
    entities: dict[int, set[EntityAssociation]] = {service_id: set() for service_id in rows}
    for row in entity_links:
        entity_id, sector_id = int(row["entity_id"]), int(row["sector_id"])
        name = str(row["entity_name"]).strip()
        _check(entity_id > 0 and name and sector_id in sectors)
        entities[int(row["service_id"])].add(EntityAssociation(entity_id, name, sector_id))
    services = tuple(
        _service(rows[service_id], links[service_id], entities[service_id], sectors) for service_id in sorted(rows)
    )
    groups = tuple(sorted((_association(sector_id, sectors) for sector_id in sectors), key=_association_order))
    shown = {"sectors": [asdict(group) for group in groups], "services": [asdict(service) for service in services]}
    version = hashlib.sha256(json.dumps(shown, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
    top_names = tuple(sorted((name for name, parent in sectors.values() if parent is None), key=str.casefold))
    return CatalogSnapshot(version, top_names, groups, services)


def _sectors(sector_rows: list[dict]) -> dict[int, tuple[str, int | None]]:
    sectors: dict[int, tuple[str, int | None]] = {}  # id: (name, parent id)
    for row in sector_rows:
        sector_id, name, parent = (int(row["sector_id"]), str(row["sector_name"]).strip(), row["parent_sector_id"])
        _check(sector_id > 0 and name and sector_id not in sectors)
        sectors[sector_id] = name, int(parent) if parent is not None else None
    _check(
        all(parent is None or (parent in sectors and sectors[parent][1] is None) for _name, parent in sectors.values())
    )
    return sectors


def _check(valid: object) -> None:
    if not valid:
        raise ValueError


def _service(row: dict, linked: set[int], entities: set[EntityAssociation], sectors: dict) -> CatalogService:
    groups = {
        _association(sector_id, sectors)
        for sector_id in linked
        if sectors[sector_id][1] is not None or not any(sectors[other][1] == sector_id for other in linked)
    }
    return CatalogService(
        int(row["service_id"]),
        str(row["service_name"]).strip(),
        str(row.get("service_description") or "").strip(),
        tuple(sorted(groups, key=_association_order)),
        tuple(sorted(entities)),
        str(row.get("upstream_dependencies") or "").strip(),
        str(row.get("downstream_dependencies") or "").strip(),
    )


def _association(sector_id: int, sectors: dict[int, tuple[str, int | None]]) -> SectorAssociation:
    name, parent = sectors[sector_id]
    if parent is None:
        return SectorAssociation(sector_id, name, None, None)
    return SectorAssociation(parent, sectors[parent][0], sector_id, name)


def _association_order(association: SectorAssociation) -> tuple[int, str, str, int]:
    return (
        0 if association.subsector_id is not None else 1,
        association.sector_name.casefold(),
        (association.subsector_name or "").casefold(),
        association.subsector_id or association.sector_id,
    )


def candidates(catalog: CatalogSnapshot, queries: list[str]) -> list[CatalogService]:
    """The services semantic and keyword search rank first for these questions, fused by rank."""
    if not catalog.services:
        return []
    embeddings = ai.embeddings.get_embedding_model()
    with _index_lock:  # built once per catalog version
        if _index.get("version") != catalog.version:
            texts = [_described(service) for service in catalog.services]
            table = EMBEDDING_SOURCE_TABLE[EmbeddingCorpus.SERVICE]
            sources = [{"table": table, "id": s.service_id, "label": s.service_name} for s in catalog.services]
            vectors = embeddings.embed_library_texts(EmbeddingCorpus.SERVICE, texts, sources)
            _index.update(index=HybridIndex(texts, vectors), version=catalog.version)
        index = _index["index"]
    vectors = embeddings.embed_search_queries(queries, EmbeddingCorpus.SERVICE)
    rankings = [
        [hit.position for hit in index.search(query, vector, _CANDIDATE_POOL)]
        for query, vector in zip(queries, vectors, strict=True)
    ]
    # catalog positions follow service ids (build_catalog), so ties still go to the lower service id
    return [catalog.services[position] for position, _score in fuse_by_rank(rankings)[:_CANDIDATE_POOL]]


def _described(service: CatalogService) -> str:
    groups = "; ".join(f"{g.sector_name} / {g.subsector_name or g.sector_name}" for g in service.sectors)
    return f"{service.service_name}. {service.description}. Sectors: {groups}"
