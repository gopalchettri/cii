"""Generate one Service Mapper run under the existing fenced MongoDB job lease."""

import time

from app.ai.chat import ChatModel, TruncatedAiAnswer, UnreadableAiAnswer
from app.core.constants import ErrorCode, MapperMessage
from app.core.exceptions import JobFailed
from app.data_access.jobs.job_repository import JobLease
from app.data_access.service_mapper.mapping_repository import MappingRepository
from app.domain.service_mapper.generate import generate_result
from app.models.service_mapper.contract import CreateMappingRequest
from app.search.service_mapper import ServiceCandidateSearch
from app.worker.service_mapper.catalog_provider import ServiceCatalogProvider


class ServiceMapperJob:
    def __init__(
        self,
        mappings: MappingRepository,
        catalog: ServiceCatalogProvider,
        search: ServiceCandidateSearch,
        chat: ChatModel,
    ) -> None:
        self._mappings = mappings
        self._catalog = catalog
        self._search = search
        self._chat = chat

    def generate(self, lease: JobLease) -> None:
        """One run: the services the mapping does not hold yet, added after those it holds."""
        record = lease.record
        request = CreateMappingRequest.model_validate(record["request"])
        limits = record["limits"]
        held = (record.get("result") or {}).get("dependencies") or []
        started = time.perf_counter()
        catalog = self._catalog.snapshot()
        catalog_read = time.perf_counter()
        try:
            found = generate_result(
                self._chat,
                self._search,
                request,
                catalog,
                (lease.record_id, lease.epoch),
                (limits["max_upstream"], limits["max_downstream"]),
                held,
            )
        except UnreadableAiAnswer as exc:
            raise JobFailed(ErrorCode.INTERNAL_ERROR, MapperMessage.AI_ANSWER_INVALID) from exc
        except TruncatedAiAnswer as exc:
            raise JobFailed(ErrorCode.INTERNAL_ERROR, MapperMessage.AI_ANSWER_TOO_LONG) from exc
        seconds = {"catalog_s": catalog_read - started, "services_s": time.perf_counter() - catalog_read}
        self._mappings.finish_generation(lease, found, seconds)
