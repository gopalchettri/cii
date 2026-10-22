"""Generate one Service Mapper round under the existing fenced MongoDB job lease."""

from app.ai.chat import ChatModel, TruncatedAiAnswer, UnreadableAiAnswer
from app.core.constants import ErrorCode, MapperMessage
from app.core.exceptions import JobFailed
from app.data_access.jobs.job_repository import JobLease
from app.data_access.service_mapper.mapping_repository import MappingHistoryRepository, MappingRepository
from app.domain.service_mapper.generate import generate_result
from app.models.service_mapper.contract import CreateMappingRequest
from app.search.service_mapper import ServiceCandidateSearch
from app.worker.service_mapper.catalog_provider import ServiceCatalogProvider


class ServiceMapperJob:
    def __init__(
        self,
        mappings: MappingRepository,
        history: MappingHistoryRepository,
        catalog: ServiceCatalogProvider,
        search: ServiceCandidateSearch,
        chat: ChatModel,
    ) -> None:
        self._mappings = mappings
        self._history = history
        self._catalog = catalog
        self._search = search
        self._chat = chat

    def generate(self, lease: JobLease) -> None:
        record = lease.record
        if frozen := record.get("pending_archive"):
            self._history.archive(frozen)
            self._mappings.clear_pending_archive(lease.record_id, frozen["generation"])
        request = CreateMappingRequest.model_validate(record["request"])
        limits = record["limits"]
        catalog = self._catalog.snapshot()
        try:
            result = generate_result(
                self._chat,
                self._search,
                request,
                catalog,
                (lease.record_id, lease.epoch),
                (limits["max_upstream"], limits["max_downstream"]),
            )
        except UnreadableAiAnswer as exc:
            raise JobFailed(ErrorCode.INTERNAL_ERROR, MapperMessage.AI_ANSWER_INVALID) from exc
        except TruncatedAiAnswer as exc:
            raise JobFailed(ErrorCode.INTERNAL_ERROR, MapperMessage.AI_ANSWER_TOO_LONG) from exc
        self._mappings.finish_generation(lease, result)
