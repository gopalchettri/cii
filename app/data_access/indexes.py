"""Every MongoDB index and expiry TSG uses, made in one place at start-up (the API's lifespan and each
worker's start): idempotent, never on a request or job path, and a failure stops start-up with its reason."""

from collections.abc import Iterable

from app.core.config import get_settings
from app.core.constants import Collection
from app.core.database import get_mongodb
from app.data_access.admin_jobs import AdminJobRecords
from app.data_access.ai_calls import AiCallRecords
from app.data_access.api_clients import ApiClientRepository
from app.data_access.audit import ensure_audit_indexes
from app.data_access.embeddings import LibraryVectors, QueryVectors
from app.data_access.external_intelligence.feed_status_store import FeedStatusStore
from app.data_access.external_intelligence.intel_record_store import IntelRecordStore
from app.data_access.external_intelligence.snapshot_pointer_store import SnapshotPointerStore
from app.data_access.job_records import JobRecords
from app.data_access.remediations import RemediationRepository
from app.data_access.scenario.runs import SessionRepository
from app.data_access.scenario.scenarios import ScenarioRepository


def ensure_indexes(job_collections: Iterable[str] = ()) -> None:
    """`job_collections`: the collections whose records carry a leased job (the worker's JOB_COLLECTIONS);
    their indexes serve the reaper's scans, so only workers make them."""
    db = get_mongodb()
    ApiClientRepository(db).ensure_indexes()
    SessionRepository(db).ensure_indexes()
    ScenarioRepository(db).ensure_indexes()
    RemediationRepository(db).ensure_indexes()
    ensure_audit_indexes()
    AiCallRecords(db[Collection.AI_CALLS]).ensure_indexes()
    LibraryVectors(db[Collection.EMBEDDINGS]).ensure_indexes()
    QueryVectors(db[Collection.QUERY_VECTORS]).ensure_indexes()
    AdminJobRecords(db).ensure_indexes()
    for collection in job_collections:
        JobRecords(db[collection]).ensure_indexes()
    if get_settings().external_intelligence_enabled:  # off: no intelligence collection exists
        IntelRecordStore(db).ensure_indexes()
        SnapshotPointerStore(db).ensure_indexes()
        FeedStatusStore(db).seed_sources()
