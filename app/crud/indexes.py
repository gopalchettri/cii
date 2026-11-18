"""Every MongoDB index and expiry TSG uses, made at start-up."""

from collections.abc import Iterable

from app.core.config import get_settings
from app.core.constants import Collection
from app.core.database import get_mongodb
from app.crud import admin as admin_crud
from app.crud import admin_jobs, ai_calls, ai_usage
from app.crud import service_mapper as service_mapper_crud
from app.crud.base import MongoRepository
from app.crud.jobs import JobRepository


def create_all_indexes(job_collections: Iterable[str] = ()) -> None:
    """Every MongoDB index and expiry TSG uses, made at start-up (the API's lifespan, each worker's start):
    idempotent, never on a request or job path, and a failure stops start-up with its reason.
    `job_collections`: the worker's leased-job collections, whose indexes serve the reaper's scans."""
    from app.crud.attack import get_attack_repository
    from app.crud.audit import get_audit_repository
    from app.crud.base import get_query_vector_repository
    from app.crud.embeddings import get_embedding_repository
    from app.crud.intel import get_intel_feed_repository, get_intel_record_repository, get_intel_snapshot_repository
    from app.crud.library import get_sql_operation_repository
    from app.crud.remediation import get_remediation_repository
    from app.crud.scenarios import get_threat_scenario_repository, get_threat_scenario_session_repository

    repository: MongoRepository
    for repository in (
        admin_crud.store(get_mongodb()),
        get_threat_scenario_session_repository(),
        get_threat_scenario_repository(),
        get_remediation_repository(),
        get_audit_repository(),
        ai_calls.store(get_mongodb()[Collection.AI_CALLS]),
        *(ai_usage.store(get_mongodb(), name) for name in ai_usage.INDEXES),
        get_embedding_repository(),
    ):
        repository.create_indexes()
    service_mapper_crud.create_indexes(get_mongodb())
    for repository in (
        get_query_vector_repository(),
        admin_jobs.get_admin_job_repository(),
        get_sql_operation_repository(),
    ):
        repository.create_indexes()
    for collection in job_collections:
        JobRepository(get_mongodb()[collection]).create_indexes()
    if get_settings().external_intelligence_enabled:  # off: no intelligence collection exists
        get_intel_record_repository().create_indexes()
        get_intel_snapshot_repository().create_indexes()
        get_attack_repository().create_indexes()  # tsg_control_links is read by _id alone: no index of its own
        get_intel_feed_repository().create_missing_intel_feeds()
