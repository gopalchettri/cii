"""Every MongoDB index and expiry TSG uses, made in one place at start-up (the API's lifespan and each
worker's start): idempotent, never on a request or job path, and a failure stops start-up with its reason."""

from collections.abc import Iterable

from app.core.constants import AiLimits, Collection
from app.core.database import get_mongodb
from app.data_access.admin_jobs import AdminJobRecords
from app.data_access.ai_calls import AiCallRecords
from app.data_access.api_clients import ApiClientRepository
from app.data_access.audit import ensure_audit_indexes
from app.data_access.embeddings import LibraryVectors, QueryVectors
from app.data_access.job_records import JobRecords
from app.data_access.remediations import RemediationRepository
from app.data_access.scenarios import ScenarioRepository
from app.data_access.sessions import SessionRepository


def ensure_indexes(job_collections: Iterable[str] = ()) -> None:
    """`job_collections`: the collections whose records carry a leased job (the worker's JOB_COLLECTIONS);
    their indexes serve the reaper's scans, so only workers make them."""
    db = get_mongodb()
    ApiClientRepository(db).ensure_indexes()
    SessionRepository(db).ensure_indexes()
    ScenarioRepository(db).ensure_indexes()
    RemediationRepository(db).ensure_indexes()
    ensure_audit_indexes()
    AiCallRecords(db[Collection.AI_CALLS]).keep_for_days(AiLimits.CALL_RECORD_DAYS)
    LibraryVectors(db[Collection.EMBEDDINGS]).ensure_indexes()
    QueryVectors(db[Collection.QUERY_VECTORS]).ensure_indexes()
    AdminJobRecords(db).ensure_indexes()
    for collection in job_collections:
        JobRecords(db[collection]).ensure_indexes()
