"""Short-lived SQL snapshot cache shared by Service Mapper calls in one process."""

import threading
import time

from app.core.constants import Cache
from app.data_access.service_mapper.catalog_repository import ServiceCatalogRepository
from app.domain.service_mapper.catalog import build_catalog
from app.models.service_mapper.catalog import CatalogSnapshot


class ServiceCatalogProvider:
    def __init__(self, repository: ServiceCatalogRepository) -> None:
        self._repository = repository
        self._lock = threading.Lock()
        self._snapshot: CatalogSnapshot | None = None
        self._next_check = 0.0

    def snapshot(self) -> CatalogSnapshot:
        now = time.monotonic()
        if self._snapshot is not None and now < self._next_check:
            return self._snapshot
        with self._lock:
            now = time.monotonic()
            if self._snapshot is not None and now < self._next_check:
                return self._snapshot
            built = build_catalog(self._repository.load())
            self._snapshot = built
            self._next_check = now + Cache.SERVICE_MAPPER_CATALOG_SECONDS
            return built
