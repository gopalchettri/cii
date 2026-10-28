"""Builds every long-lived object once and passes it in: routers ask through Depends, worker tasks when they
run. A provider gets its dependencies by calling their providers, so one patched before the first build is
seen."""

from collections.abc import Iterable

from app.ai.chat import ChatModel, chat_model_from
from app.ai.common import apply_proxy_settings
from app.ai.embeddings import EmbeddingModel, embedding_model_from
from app.ai.module_chat import module_chat
from app.ai.rerank import RerankModel, rerank_model_from
from app.ai.slots import AiRequestRate, AiSlots
from app.core.config import get_settings
from app.core.constants import ROUTED_QUEUES, AiLimits, ChatModule
from app.core.database import get_mongodb, get_redis_client, get_stored_procedure_client
from app.core.readiness import count_online_workers, log_mongodb_topology, log_redis_eviction_policy
from app.core.singletons import singleton
from app.data_access.admin.admin_job_repository import AdminJobRepository
from app.data_access.admin.ai_call_repository import AiCallRepository
from app.data_access.admin.api_client_repository import ApiClientRepository
from app.data_access.admin.audit_repository import AuditRepository
from app.data_access.admin.embedding_repository import EmbeddingRepository
from app.data_access.admin.query_vector_repository import QueryVectorRepository
from app.data_access.base import MongoRepository
from app.data_access.external_intelligence.intel_feed_repository import IntelFeedRepository
from app.data_access.external_intelligence.intel_record_repository import IntelRecordRepository
from app.data_access.external_intelligence.intel_snapshot_repository import IntelSnapshotRepository
from app.data_access.external_intelligence.intelligence_switch import IntelligenceSwitch
from app.data_access.jobs.job_repository import JobRepository
from app.data_access.jobs.work_control_repository import WorkControlRepository
from app.data_access.library.control_repository import ControlRepository
from app.data_access.library.sql_operation_repository import SqlOperationRepository
from app.data_access.library.threat_repository import ThreatRepository
from app.data_access.remediation.remediation_repository import RemediationRepository
from app.data_access.scenario.asset_repository import AssetRepository
from app.data_access.scenario.threat_scenario_repository import ThreatScenarioRepository
from app.data_access.scenario.threat_scenario_session_repository import ThreatScenarioSessionRepository
from app.data_access.service_mapper.catalog_repository import ServiceCatalogRepository
from app.data_access.service_mapper.mapping_repository import MappingRepository
from app.domain.external_intelligence.evidence_finder import EvidenceFinder
from app.domain.external_intelligence.rerank_gate import rerank_gate_for
from app.domain.scenario.controls import ControlMapper
from app.domain.scenario.plan import ThreatFinder
from app.realtime.publisher import (
    publish_mapping_status,
    publish_remediation_status,
    publish_session_status,
)
from app.search.external_intelligence.index_keeper import EvidenceIndexKeeper
from app.search.external_intelligence.intelligence_metrics import SNAPSHOT_AGE_SECONDS
from app.search.library_cache import LibraryCache
from app.search.service import LibrarySearch
from app.search.service_mapper import ServiceCandidateSearch
from app.services.admin.admin_service import AdminService
from app.services.external_intelligence.external_intelligence_service import ExternalIntelligenceService
from app.services.job_monitor.job_monitor_service import JobMonitorService
from app.services.jobs.job_service import JobService
from app.services.library.threat_library_service import ThreatLibraryService
from app.services.remediation.remediation_plan_service import RemediationPlanService
from app.services.scenario.threat_scenario_service import ThreatScenarioService
from app.services.service_mapper.service_mapper_service import ServiceMapperService
from app.worker.celery_app import count_waiting_messages, send_admin_job, send_job
from app.worker.external_intelligence.refresh_sources import SourceRefresher
from app.worker.external_intelligence.sources.source_catalogue import SourceCatalogue
from app.worker.remediation.remediation_plan_job import RemediationPlanJob
from app.worker.scenario.controls_job import ControlsJob
from app.worker.scenario.plan_job import PlanJob
from app.worker.scenario.write_job import ScenarioWriteJob
from app.worker.service_mapper.catalog_provider import ServiceCatalogProvider
from app.worker.service_mapper.job import ServiceMapperJob

#: How long this process waits for a free AI slot or request turn, and whether it waits out a rate-limited
#: (HTTP 429) request: the API answers callers, so it waits briefly and retries a 429 as any busy answer; a
#: worker waits longer and waits out a 429, because its job would otherwise only be retried later
#: (set_up_worker).
_ai_slot_wait_seconds: float = AiLimits.API_SLOT_WAIT_SECONDS
_waits_out_rate_limits = False


# --- AI gateways


@singleton
def apply_proxy_once() -> None:
    """Sets the proxy of the process's outside calls, before the first AI gateway or source refresh."""
    apply_proxy_settings(get_settings())


@singleton
def get_ai_slots() -> AiSlots:
    """The search calls' slots (embedding, reranker). Every AI call is recorded, at cap 0 too: a gateway 429
    limits the calls then in flight."""
    return AiSlots(get_redis_client(), get_settings().max_concurrent_ai_calls, _ai_slot_wait_seconds)


@singleton
def get_module_ai_slots() -> dict[ChatModule, tuple[AiSlots, AiSlots]]:
    """Each module's own slots for its chat calls, (main, fallback): its 429s and its calls at once never slow
    another module or the search calls. A fallback cap of 0 needs no Redis."""
    redis, settings, wait = get_redis_client(), get_settings(), _ai_slot_wait_seconds
    pools = {}
    for module in ChatModule:
        chat, fallback_key = module_chat(settings, module), f"{AiLimits.FALLBACK_SLOTS_KEY}:{module}"
        fallback_cap = chat.max_concurrent_fallback_calls
        pools[module] = (
            AiSlots(redis, chat.max_concurrent_ai_calls, wait, f"{AiLimits.SLOTS_KEY}:{module}"),
            AiSlots(redis if fallback_cap else None, fallback_cap, wait, fallback_key),
        )
    return pools


def ai_request_rate_for(
    model: str, per_minute: int, tokens_per_minute: int = 0, scope: str = ""
) -> AiRequestRate:
    """`model`'s own request-rate limiter in `scope` (a module's), with this process's waits; each gateway
    builds its model's once."""
    redis = get_redis_client() if per_minute or tokens_per_minute else None
    return AiRequestRate(
        redis, model, per_minute, _ai_slot_wait_seconds, _waits_out_rate_limits, tokens_per_minute, scope
    )


@singleton
def get_ai_call_repository() -> AiCallRepository:
    return AiCallRepository()


@singleton
def get_query_vector_repository() -> QueryVectorRepository:
    return QueryVectorRepository()


@singleton
def get_embedding_repository() -> EmbeddingRepository:
    return EmbeddingRepository()


def _chat_model_of(module: ChatModule) -> ChatModel:
    """`module`'s chat model: its own settings (CII_<MODULE>_CHAT_...), slots and request turns."""
    apply_proxy_once()
    settings = get_settings()
    chat, (slots, fallback_slots) = module_chat(settings, module), get_module_ai_slots()[module]
    return chat_model_from(
        chat,
        settings.ai_key_header,
        get_ai_call_repository(),
        slots,
        ai_request_rate_for(chat.model, chat.requests_per_minute, chat.tokens_per_minute, module),
        fallback_slots,
        ai_request_rate_for(chat.fallback_model, chat.fallback_requests_per_minute, scope=module),
    )


@singleton
def get_scenario_chat_model() -> ChatModel:
    """Threat finding and scenario writing."""
    return _chat_model_of(ChatModule.SCENARIO)


@singleton
def get_remediation_chat_model() -> ChatModel:
    return _chat_model_of(ChatModule.REMEDIATION)


@singleton
def get_service_mapper_chat_model() -> ChatModel:
    return _chat_model_of(ChatModule.SERVICE_MAPPER)


@singleton
def get_embedding_model() -> EmbeddingModel:
    apply_proxy_once()
    settings = get_settings()
    return embedding_model_from(
        settings,
        get_embedding_repository(),
        get_query_vector_repository(),
        get_ai_slots(),
        ai_request_rate_for(settings.embedding_model, settings.embedding_requests_per_minute),
    )


@singleton
def get_rerank_model() -> RerankModel:
    apply_proxy_once()
    settings = get_settings()
    request_rate = ai_request_rate_for(settings.rerank_model, settings.rerank_requests_per_minute)
    return rerank_model_from(settings, get_ai_slots(), request_rate)


# --- library and admin


@singleton
def get_sql_operation_repository() -> SqlOperationRepository:
    return SqlOperationRepository(get_stored_procedure_client())


@singleton
def get_threat_repository() -> ThreatRepository:
    return ThreatRepository(get_stored_procedure_client(), get_sql_operation_repository())


@singleton
def get_control_repository() -> ControlRepository:
    return ControlRepository(get_stored_procedure_client())


@singleton
def get_library_cache() -> LibraryCache:
    return LibraryCache(get_threat_repository(), get_control_repository())


@singleton
def get_library_search() -> LibrarySearch:
    return LibrarySearch(get_library_cache(), get_embedding_model())


@singleton
def get_api_client_repository() -> ApiClientRepository:
    return ApiClientRepository()


@singleton
def get_audit_repository() -> AuditRepository:
    return AuditRepository()


@singleton
def get_admin_job_repository() -> AdminJobRepository:
    return AdminJobRepository()


@singleton
def get_admin_service() -> AdminService:
    return AdminService(
        get_api_client_repository(), get_admin_job_repository(), get_audit_repository(), send_admin_job
    )


@singleton
def get_threat_library_service() -> ThreatLibraryService:
    return ThreatLibraryService(get_threat_repository(), get_audit_repository())


# --- external intelligence (with it off, nothing here is built until asked for)


@singleton
def get_intel_feed_repository() -> IntelFeedRepository:
    return IntelFeedRepository()


@singleton
def get_intel_record_repository() -> IntelRecordRepository:
    return IntelRecordRepository()


@singleton
def get_intel_snapshot_repository() -> IntelSnapshotRepository:
    return IntelSnapshotRepository()


@singleton
def get_intelligence_switch() -> IntelligenceSwitch:
    return IntelligenceSwitch(
        get_intel_feed_repository(), lambda: get_settings().external_intelligence_enabled
    )


@singleton
def get_evidence_index_keeper() -> EvidenceIndexKeeper:
    """The evidence index keeper, its snapshot age exported as a gauge."""
    settings = get_settings()
    keeper = EvidenceIndexKeeper(
        get_intel_record_repository(),
        get_intel_snapshot_repository(),
        get_intel_feed_repository(),
        get_embedding_model(),
        get_rerank_model(),
        settings.embedding_model,
        settings.rerank_model,
    )
    SNAPSHOT_AGE_SECONDS.set_function(keeper.snapshot_age_seconds)
    return keeper


@singleton
def get_evidence_finder() -> EvidenceFinder:
    """The evidence finder: it holds no run's state, follows the active snapshot's index and holds the
    process's one rerank gate."""
    keeper, settings = get_evidence_index_keeper(), get_settings()
    gate = rerank_gate_for(settings.rerank_base_url)
    return EvidenceFinder(
        lambda: keeper.current_index(),
        settings.evidence_similarity_threshold,
        gate=gate,
        candidates=settings.evidence_candidates,
        kept_per_threat=settings.evidence_kept_per_threat,
    )


@singleton
def get_source_refresher() -> SourceRefresher:
    apply_proxy_once()
    records = get_intel_record_repository()
    return SourceRefresher(
        SourceCatalogue(records),
        records,
        get_intel_feed_repository(),
        get_evidence_index_keeper(),
        get_audit_repository(),
    )


@singleton
def get_external_intelligence_service() -> ExternalIntelligenceService:
    return ExternalIntelligenceService(
        get_settings(),
        get_intelligence_switch(),
        get_intel_feed_repository(),
        get_intel_record_repository(),
        get_intel_snapshot_repository(),
        get_embedding_repository(),
        get_admin_job_repository(),
        get_audit_repository(),
        get_evidence_index_keeper(),
        send_admin_job,
    )


@singleton
def get_service_mapper_service() -> ServiceMapperService:
    return ServiceMapperService(
        get_mapping_repository(),
        get_settings(),
        send_job,
        get_service_catalog_repository(),
        get_audit_repository(),
        publish_mapping_status,
    )


@singleton
def get_service_catalog_repository() -> ServiceCatalogRepository:
    return ServiceCatalogRepository(get_stored_procedure_client())


@singleton
def get_service_catalog_provider() -> ServiceCatalogProvider:
    return ServiceCatalogProvider(get_service_catalog_repository())


@singleton
def get_service_candidate_search() -> ServiceCandidateSearch:
    return ServiceCandidateSearch(get_embedding_model())


@singleton
def get_mapping_repository() -> MappingRepository:
    return MappingRepository()


@singleton
def get_service_mapper_job() -> ServiceMapperJob:
    return ServiceMapperJob(
        get_mapping_repository(),
        get_service_catalog_provider(),
        get_service_candidate_search(),
        get_service_mapper_chat_model(),
    )


# --- scenario, remediation and jobs


@singleton
def get_threat_scenario_repository() -> ThreatScenarioRepository:
    return ThreatScenarioRepository()


@singleton
def get_threat_scenario_session_repository() -> ThreatScenarioSessionRepository:
    return ThreatScenarioSessionRepository(scenarios=get_threat_scenario_repository())


@singleton
def get_asset_repository() -> AssetRepository:
    return AssetRepository(get_stored_procedure_client())


@singleton
def get_remediation_repository() -> RemediationRepository:
    return RemediationRepository()


@singleton
def get_work_control_repository() -> WorkControlRepository:
    return WorkControlRepository(
        get_threat_scenario_session_repository(),
        get_threat_scenario_repository(),
        get_remediation_repository(),
        get_mapping_repository(),
    )


@singleton
def get_threat_scenario_service() -> ThreatScenarioService:
    return ThreatScenarioService(
        sessions=get_threat_scenario_session_repository(),
        scenarios=get_threat_scenario_repository(),
        assets=get_asset_repository(),
        work_control=get_work_control_repository(),
        threats=get_threat_repository(),
        threat_library=get_library_cache().get_threat_library,
        switch=get_intelligence_switch(),
        intel_snapshots=get_intel_snapshot_repository(),
        audit=get_audit_repository(),
        send_job=send_job,
        publish_session_status=publish_session_status,
    )


@singleton
def get_remediation_plan_service() -> RemediationPlanService:
    return RemediationPlanService(
        remediations=get_remediation_repository(),
        scenarios=get_threat_scenario_repository(),
        sessions=get_threat_scenario_session_repository(),
        assets=get_asset_repository(),
        library=get_library_cache(),
        audit=get_audit_repository(),
        send_job=send_job,
        publish_remediation_status=publish_remediation_status,
    )


@singleton
def get_job_service() -> JobService:
    return JobService(
        get_work_control_repository(),
        get_threat_scenario_session_repository(),
        get_audit_repository(),
        publish_session_status,
        publish_remediation_status,
    )


@singleton
def get_job_monitor_service() -> JobMonitorService:
    from app.worker.jobs import JOB_COLLECTIONS

    return JobMonitorService(
        {collection: JobRepository(get_mongodb()[collection]) for collection in JOB_COLLECTIONS},
        get_admin_job_repository(),
        ROUTED_QUEUES,
        count_waiting_messages,
        count_online_workers,
        get_audit_repository(),
    )


@singleton
def get_plan_job() -> PlanJob:
    finder = ThreatFinder(
        get_scenario_chat_model(), get_library_search(), get_rerank_model(), get_embedding_model()
    )
    return PlanJob(finder, get_intelligence_switch())


@singleton
def get_scenario_write_job() -> ScenarioWriteJob:
    return ScenarioWriteJob(
        sessions=get_threat_scenario_session_repository(),
        scenarios=get_threat_scenario_repository(),
        chat=get_scenario_chat_model(),
        threat_library=get_library_cache().get_threat_library,
        switch=get_intelligence_switch(),
        evidence_finder=get_evidence_finder,  # the provider: with intelligence off nothing is built
        feeds=get_intel_feed_repository(),
        audit=get_audit_repository(),
    )


@singleton
def get_controls_job() -> ControlsJob:
    return ControlsJob(
        get_threat_scenario_session_repository(),
        get_threat_scenario_repository(),
        get_work_control_repository(),
        get_library_search(),
        get_rerank_model(),
    )


@singleton
def get_remediation_plan_job() -> RemediationPlanJob:
    return RemediationPlanJob(
        get_remediation_repository(),
        get_threat_scenario_repository(),
        get_threat_scenario_session_repository(),
        get_threat_repository(),
        get_audit_repository(),
        get_library_search(),
        ControlMapper(get_rerank_model()),
        get_remediation_chat_model(),
    )


# --- start-up


def create_all_indexes(job_collections: Iterable[str] = ()) -> None:
    """Every MongoDB index and expiry TSG uses, made at start-up (the API's lifespan, each worker's start):
    idempotent, never on a request or job path, and a failure stops start-up with its reason.
    `job_collections`: the worker's leased-job collections, whose indexes serve the reaper's scans."""
    repository: MongoRepository
    for repository in (
        get_api_client_repository(),
        get_threat_scenario_session_repository(),
        get_threat_scenario_repository(),
        get_remediation_repository(),
        get_mapping_repository(),
        get_audit_repository(),
        get_ai_call_repository(),
        get_embedding_repository(),
    ):
        repository.create_indexes()
    get_embedding_repository().retire_unknown_vector_corpora()
    for repository in (
        get_query_vector_repository(),
        get_admin_job_repository(),
        get_sql_operation_repository(),
    ):
        repository.create_indexes()
    for collection in job_collections:
        JobRepository(get_mongodb()[collection]).create_indexes()
    if get_settings().external_intelligence_enabled:  # off: no intelligence collection exists
        get_intel_record_repository().create_indexes()
        get_intel_snapshot_repository().create_indexes()
        get_intel_feed_repository().create_missing_intel_feeds()


def set_up_api() -> None:
    """The API's start-up: every index, the MongoDB topology and Redis eviction policy lines, then the AI
    gateways (building one looks up its model's profile: a model with no profile stops start-up here)."""
    create_all_indexes()
    log_mongodb_topology()
    log_redis_eviction_policy()
    build_ai_gateways()


def set_up_worker(job_collections: Iterable[str]) -> None:
    """A worker's start-up, as the API's: every index (the reaper's scans included), the Redis eviction policy
    line, then the AI gateways, which take the worker's longer AI slot wait and wait out a rate-limited
    request."""
    global _ai_slot_wait_seconds, _waits_out_rate_limits
    _ai_slot_wait_seconds = AiLimits.WORKER_SLOT_WAIT_SECONDS
    _waits_out_rate_limits = True
    create_all_indexes(job_collections)
    log_redis_eviction_policy()
    build_ai_gateways()


def build_ai_gateways() -> None:
    """Every AI gateway, each module's chat model included: one whose model has no profile stops start-up."""
    get_scenario_chat_model()
    get_remediation_chat_model()
    get_service_mapper_chat_model()
    get_embedding_model()
    get_rerank_model()
