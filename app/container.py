"""Builds every long-lived object once and passes it in: routers ask through Depends, worker tasks when they
run. A provider gets its dependencies by calling their providers, so one patched before the first build is
seen."""

from collections.abc import Iterable

from app.ai.chat import ChatModel, chat_model_from
from app.ai.common import apply_proxy_settings
from app.ai.embeddings import EmbeddingModel, embedding_model_from
from app.ai.rerank import RerankModel, rerank_model_from
from app.ai.slots import AiSlots
from app.core.config import get_settings
from app.core.constants import AiLimits
from app.core.database import get_mongodb, get_redis_client, get_stored_procedure_client
from app.core.readiness import log_mongodb_topology
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
from app.data_access.service_mapper.mapping_repository import MappingHistoryRepository, MappingRepository
from app.domain.external_intelligence.evidence_finder import EvidenceFinder
from app.domain.external_intelligence.rerank_gate import rerank_gate_for
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
from app.services.jobs.job_service import JobService
from app.services.library.threat_library_service import ThreatLibraryService
from app.services.remediation.remediation_plan_service import RemediationPlanService
from app.services.scenario.threat_scenario_service import ThreatScenarioService
from app.services.service_mapper.service_mapper_service import ServiceMapperService
from app.worker.celery_app import send_admin_job, send_job
from app.worker.external_intelligence.refresh_sources import SourceRefresher
from app.worker.external_intelligence.sources.source_catalogue import SourceCatalogue
from app.worker.remediation.plan_inputs import PlanInputs
from app.worker.remediation.remediation_plan_job import RemediationPlanJob
from app.worker.scenario.controls_job import ControlsJob
from app.worker.scenario.plan_job import PlanJob
from app.worker.scenario.write_job import ScenarioWriteJob
from app.worker.service_mapper.catalog_provider import ServiceCatalogProvider
from app.worker.service_mapper.job import ServiceMapperJob

#: How long this process waits for a free AI slot: the API answers callers, so it waits briefly; a worker
#: waits longer, because its job would otherwise only be retried later (set_up_worker).
_ai_slot_wait_seconds: float = AiLimits.API_SLOT_WAIT_SECONDS


# --- AI gateways


@singleton
def apply_proxy_once() -> None:
    """Sets the proxy of the process's outside calls, before the first AI gateway or source refresh."""
    apply_proxy_settings(get_settings())


@singleton
def get_ai_slots() -> AiSlots:
    cap = get_settings().max_concurrent_ai_calls
    return AiSlots(get_redis_client() if cap else None, cap, _ai_slot_wait_seconds)


@singleton
def get_ai_call_repository() -> AiCallRepository:
    return AiCallRepository()


@singleton
def get_query_vector_repository() -> QueryVectorRepository:
    return QueryVectorRepository()


@singleton
def get_embedding_repository() -> EmbeddingRepository:
    return EmbeddingRepository()


@singleton
def get_chat_model() -> ChatModel:
    apply_proxy_once()
    return chat_model_from(get_settings(), get_ai_call_repository(), get_ai_slots())


@singleton
def get_embedding_model() -> EmbeddingModel:
    apply_proxy_once()
    return embedding_model_from(
        get_settings(), get_embedding_repository(), get_query_vector_repository(), get_ai_slots()
    )


@singleton
def get_rerank_model() -> RerankModel:
    apply_proxy_once()
    return rerank_model_from(get_settings(), get_ai_slots())


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
    return EvidenceFinder(lambda: keeper.current_index(), settings.evidence_similarity_threshold, gate=gate)


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
        get_mapping_history_repository(),
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
def get_mapping_history_repository() -> MappingHistoryRepository:
    return MappingHistoryRepository()


@singleton
def get_service_mapper_job() -> ServiceMapperJob:
    return ServiceMapperJob(
        get_mapping_repository(),
        get_mapping_history_repository(),
        get_service_catalog_provider(),
        get_service_candidate_search(),
        get_chat_model(),
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
def get_plan_job() -> PlanJob:
    finder = ThreatFinder(get_chat_model(), get_library_search(), get_rerank_model(), get_embedding_model())
    return PlanJob(finder, get_intelligence_switch(), get_threat_scenario_repository())


@singleton
def get_scenario_write_job() -> ScenarioWriteJob:
    return ScenarioWriteJob(
        sessions=get_threat_scenario_session_repository(),
        scenarios=get_threat_scenario_repository(),
        chat=get_chat_model(),
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
    inputs = PlanInputs(
        search=get_library_search(),
        rerank=get_rerank_model(),
        threats=get_threat_repository(),
        scenarios=get_threat_scenario_repository(),
        sessions=get_threat_scenario_session_repository(),
        remediations=get_remediation_repository(),
        audit=get_audit_repository(),
    )
    return RemediationPlanJob(get_remediation_repository(), get_chat_model(), inputs, get_audit_repository())


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
        get_mapping_history_repository(),
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
    """The API's start-up: every index, the MongoDB topology line, then the AI gateways (building one looks up
    its model's profile: a model with no profile stops start-up here)."""
    create_all_indexes()
    log_mongodb_topology()
    get_chat_model()
    get_embedding_model()
    get_rerank_model()


def set_up_worker(job_collections: Iterable[str]) -> None:
    """A worker's start-up, as the API's: every index (the reaper's scans included), then the AI gateways,
    which take the worker's longer AI slot wait."""
    global _ai_slot_wait_seconds
    _ai_slot_wait_seconds = AiLimits.WORKER_SLOT_WAIT_SECONDS
    create_all_indexes(job_collections)
    get_chat_model()
    get_embedding_model()
    get_rerank_model()
