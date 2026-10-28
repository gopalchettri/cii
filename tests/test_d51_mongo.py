"""MongoDB: every write waits for a majority, a write the replicas did not confirm is an outage, the controls
sweep reads only what it can change, and archived Service Mapper generations expire."""

import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pymongo.collection import Collection as MongoCollection
from pymongo.errors import BulkWriteError, ExecutionTimeout, WriteConcernError, WTimeoutError
from structlog.testing import capture_logs

from app.core import readiness
from app.core.constants import (
    Collection,
    Controls,
    Decision,
    EmbeddingCorpus,
    ErrorCode,
    ErrorMessage,
    IntelSource,
    Limits,
    LogEvent,
    ScenarioStatus,
    Status,
    TaskName,
    Timeouts,
)
from app.core.database import get_mongodb
from app.data_access.admin.embedding_repository import EmbeddingRepository
from app.data_access.base import VectorRepository
from app.data_access.external_intelligence.intel_record_repository import IntelRecordRepository
from app.data_access.jobs.job_repository import new_job
from app.data_access.jobs.work_control_repository import WorkControlRepository
from app.data_access.remediation.remediation_repository import RemediationRepository
from app.data_access.scenario.threat_scenario_repository import ThreatScenarioRepository
from app.data_access.service_mapper.mapping_repository import MappingHistoryRepository
from app.models.external_intelligence.intel_record import RejectedRecord
from app.worker import jobs
from tests import test_review as review
from tests.test_review import api_key, service  # noqa: F401 - fixtures used by name

UNCONFIRMED_WRITES = [
    WTimeoutError("waiting for replication timed out", 64),
    WriteConcernError("primary stepped down", 189),
    ExecutionTimeout("operation exceeded time limit", 50),
]
REPLICATION_TIMED_OUT = {
    "code": 64,
    "errmsg": "waiting for replication timed out",
    "errInfo": {"wtimeout": True},
}
#: Each way the app writes in bulk; a lagging replica set reaches every one.
BULK_WRITERS: dict[str, Callable[[], Any]] = {
    "scenario decisions": lambda: ThreatScenarioRepository().update_scenario_decisions(
        ["any"], Decision.PENDING, Decision.ACCEPTED, {}
    ),
    "library vectors": lambda: EmbeddingRepository().update_library_vector_corpus(
        EmbeddingCorpus.THREAT, {"key": [{"id": "row"}]}, {"key": {"sources": []}}
    ),
    "intel import": lambda: IntelRecordRepository().save_intel_records(
        [], [RejectedRecord(IntelSource.CISA_KEV, "CVE-1", "bad", "hash")], datetime.now(UTC)
    ),
    "vector cache": lambda: VectorRepository(Collection.EMBEDDINGS).save_vectors([{"_id": "key"}]),
}


def test_every_write_waits_for_a_majority_for_a_bounded_time() -> None:
    """The server's default decided durability before; the wait ends before the socket timeout, so the
    server answers WTimeoutError instead of the link being cut."""
    write_concern = get_mongodb().write_concern.document
    assert write_concern["w"] == "majority"
    assert 0 < write_concern["wtimeout"] < Timeouts.MONGO_SOCKET_MS
    written = get_mongodb()["d51_write_concern"].insert_one({"_id": uuid.uuid4().hex})  # a standalone too
    assert written.acknowledged


def test_the_start_up_topology_line_names_the_write_concern_writes_use() -> None:
    with capture_logs() as logs:
        readiness.log_mongodb_topology()
    line = next(line for line in logs if line["event"] == LogEvent.MONGODB_TOPOLOGY)
    assert line["replica_set"] and line["write_concern"] == get_mongodb().write_concern.document


@pytest.mark.parametrize("driver_error", UNCONFIRMED_WRITES, ids=lambda error: type(error).__name__)
def test_an_unconfirmed_write_answers_503_not_500(client: TestClient, driver_error: Exception) -> None:
    path = f"/test-only/unconfirmed/{type(driver_error).__name__}"

    def raise_driver_error() -> None:
        raise driver_error

    client.app.add_api_route(path, raise_driver_error)  # type: ignore[attr-defined]
    response = client.get(path)
    assert response.status_code == 503
    assert response.headers["Retry-After"] == str(Limits.RETRY_AFTER_SECONDS)
    assert response.json()["code"] == ErrorCode.UNAVAILABLE
    assert response.json()["detail"] == ErrorMessage.MONGO_UNREACHABLE


class RetryRequested(Exception):
    """Stands in for Celery's Retry."""


def _assert_job_given_back_for_a_retry(monkeypatch: pytest.MonkeyPatch, work: Callable[[], Any]) -> None:
    """A queued job running `work` is given back for a retry as an outage, never failed."""
    monkeypatch.setitem(jobs.JOB_COLLECTIONS, Collection.SESSIONS, lambda _record_id: None)
    record_id, now = uuid.uuid4().hex, datetime.now(UTC)
    record = {"_id": record_id, "entity_id": 86, "asset_id": 103, "status": Status.QUEUED, "updated_at": now}
    sessions = get_mongodb()[Collection.SESSIONS]
    sessions.insert_one(record | {"job": new_job(TaskName.FIND_THREATS, 1, now)})
    task = SimpleNamespace(
        name=TaskName.FIND_THREATS, request=SimpleNamespace(id="task-1"), retry=lambda **_: RetryRequested()
    )
    with capture_logs() as logs, pytest.raises(RetryRequested):
        jobs.run_leased_job(task, Collection.SESSIONS, record_id, 1, lambda _lease: work())  # type: ignore[arg-type]
    assert LogEvent.JOB_FAILED not in [line["event"] for line in logs]
    saved = sessions.find_one({"_id": record_id})
    assert saved["status"] == Status.QUEUED
    assert saved["job"]["retry"]["message"] == ErrorMessage.MONGO_UNREACHABLE


@pytest.mark.parametrize("driver_error", UNCONFIRMED_WRITES, ids=lambda error: type(error).__name__)
def test_an_unconfirmed_write_gives_the_job_back_for_a_retry(
    monkeypatch: pytest.MonkeyPatch, driver_error: Exception
) -> None:
    def work() -> None:
        raise driver_error

    _assert_job_given_back_for_a_retry(monkeypatch, work)


def _bulk_writes_answer(
    monkeypatch: pytest.MonkeyPatch, concern_error: dict[str, Any], write_errors: list[dict[str, Any]]
) -> None:
    """Every bulk write raises what pymongo raises when the replicas did not confirm it: a BulkWriteError
    carrying `concern_error` (and `write_errors`), never a WriteConcernError."""
    details = {"writeErrors": write_errors, "writeConcernErrors": [concern_error], "upserted": []}
    counts = dict.fromkeys(["nInserted", "nUpserted", "nMatched", "nModified", "nRemoved"], 0)

    def unconfirmed(*_args: Any, **_options: Any) -> None:
        raise BulkWriteError(details | counts)

    monkeypatch.setattr(MongoCollection, "bulk_write", unconfirmed)


@pytest.fixture
def replicas_lagging(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every bulk write waits past its write concern's time limit."""
    _bulk_writes_answer(monkeypatch, REPLICATION_TIMED_OUT, [])


@pytest.mark.parametrize("write", BULK_WRITERS.values(), ids=BULK_WRITERS)
@pytest.mark.usefixtures("replicas_lagging")
def test_an_unconfirmed_bulk_write_is_an_outage(write: Callable[[], Any]) -> None:
    """Before: a bulk write raised BulkWriteError, outside MONGO_UNAVAILABLE_ERRORS, so it was a bug."""
    with pytest.raises(WTimeoutError):
        write()


@pytest.mark.parametrize("write", BULK_WRITERS.values(), ids=BULK_WRITERS)
def test_an_unconfirmed_bulk_write_gives_the_job_back_for_a_retry(
    monkeypatch: pytest.MonkeyPatch, write: Callable[[], Any]
) -> None:
    _bulk_writes_answer(monkeypatch, REPLICATION_TIMED_OUT, [])
    _assert_job_given_back_for_a_retry(monkeypatch, write)


@pytest.mark.parametrize("action", ["accept", "scenarios/reject"])
@pytest.mark.usefixtures("replicas_lagging", "service")
def test_a_decision_the_replicas_did_not_confirm_answers_503(
    client: TestClient,
    api_key: str,  # noqa: F811 - the fixture
    action: str,
) -> None:
    record_id = review._run()
    chosen = {"scenario_ids": [review._scenario(record_id, "p1")]}
    response = review._post(client, api_key, f"/v1/sessions/{record_id}/{action}", chosen)
    assert response.status_code == 503
    assert response.headers["Retry-After"] == str(Limits.RETRY_AFTER_SECONDS)
    assert response.json()["detail"] == ErrorMessage.MONGO_UNREACHABLE


def test_a_write_concern_error_that_is_no_timeout_is_still_an_outage(monkeypatch: pytest.MonkeyPatch) -> None:
    _bulk_writes_answer(monkeypatch, {"code": 100, "errmsg": "Not enough data-bearing nodes"}, [])
    with pytest.raises(WriteConcernError) as raised:
        BULK_WRITERS["library vectors"]()
    assert not isinstance(raised.value, WTimeoutError)


def test_a_duplicate_with_an_unconfirmed_write_is_an_outage(monkeypatch: pytest.MonkeyPatch) -> None:
    """A duplicate key is skipped, but the rest of the write was not confirmed either."""
    duplicate = {"index": 0, "code": 11000, "errmsg": "E11000 duplicate key error"}
    _bulk_writes_answer(monkeypatch, REPLICATION_TIMED_OUT, [duplicate])
    with pytest.raises(WTimeoutError):
        BULK_WRITERS["vector cache"]()


def test_every_bulk_write_goes_through_the_one_that_raises_outages() -> None:
    """A repository calling collection.bulk_write itself would answer an unconfirmed write as a bug again."""
    app = Path(__file__).parents[1] / "app"
    direct = [path.name for path in app.rglob("*.py") if ".bulk_write(" in path.read_text(encoding="utf-8")]
    assert direct == ["base.py"]


def test_a_refused_write_stays_a_bug_when_also_unconfirmed(monkeypatch: pytest.MonkeyPatch) -> None:
    refused = {"index": 0, "code": 121, "errmsg": "Document failed validation"}
    _bulk_writes_answer(monkeypatch, REPLICATION_TIMED_OUT, [refused])
    for write in BULK_WRITERS.values():
        with pytest.raises(BulkWriteError):
            write()


def _examined(command: dict[str, Any]) -> int:
    """Index keys plus documents MongoDB examines to answer `command` on tsg_scenarios."""
    explained = get_mongodb().command("explain", command, verbosity="executionStats")["executionStats"]
    return explained["totalKeysExamined"] + explained["totalDocsExamined"]


def _find(query: dict[str, Any]) -> dict[str, Any]:
    return {"find": Collection.SCENARIOS, "filter": query}


def _scenario(session_id: str, created_at: datetime, **controls: Any) -> dict[str, Any]:
    """A written scenario of `session_id`, newest version, with `controls`."""
    return {
        "_id": uuid.uuid4().hex,
        "session_id": session_id,
        "status": ScenarioStatus.DONE,
        "source": "generated",
        "superseded_by": None,
        "created_at": created_at,
        "controls": controls,
    }


def _settle_with(spy: SimpleNamespace) -> None:
    """The sweep's settle step reading tsg_scenarios through `spy`, which finds nothing, so no session is
    read."""
    scenarios = ThreatScenarioRepository(spy)  # type: ignore[arg-type]
    work = WorkControlRepository(None, scenarios, RemediationRepository(), None)  # type: ignore[arg-type]
    work.settle_stopped_scenario_sessions()


def test_the_sweep_never_reads_controls_failed_for_good() -> None:
    """Controls that used every attempt never leave tsg_scenarios: the sweep's reads never grow with them."""
    asked: list[dict[str, Any]] = []
    spy = SimpleNamespace(
        find=lambda query, _fields: asked.append(query) or [],
        distinct=lambda _key, query: asked.append(query) or [],
        update_many=lambda *_args, **_options: None,
    )
    now = datetime.now(UTC)
    ThreatScenarioRepository(spy).requeue_stalled_controls(now)  # type: ignore[arg-type]
    _settle_with(spy)
    sweep_reads = [_find(asked[0]), _find(asked[1])]  # the requeue's, then the settle's
    long_ago = now - timedelta(hours=2)
    spent = {"status": Status.FAILED, "attempts": Controls.MAX_ATTEMPTS, "last_attempt_at": long_ago}

    def add_spent_cards() -> list[int]:
        """20 more spent cards, then what each sweep read examines (a scan reads one key past its end)."""
        get_mongodb()[Collection.SCENARIOS].insert_many(
            [_scenario(f"run-{uuid.uuid4().hex}", long_ago, **spent) for _ in range(20)]
        )
        return [_examined(read) for read in sweep_reads]

    assert add_spent_cards() == add_spent_cards()


def test_the_orphan_check_reads_only_the_last_hours_scenarios() -> None:
    asked: list[dict[str, Any]] = []
    spy = SimpleNamespace(find=lambda *_args: [], distinct=lambda _key, query: asked.append(query) or [])
    _settle_with(spy)
    orphans = {"distinct": Collection.SCENARIOS, "key": "session_id", "query": asked[0]}
    before = _examined(orphans)
    long_ago = datetime.now(UTC) - timedelta(hours=2)
    get_mongodb()[Collection.SCENARIOS].insert_many(
        [_scenario(f"run-{uuid.uuid4().hex}", long_ago, status=Status.DONE) for _ in range(20)]
    )
    assert _examined(orphans) == before


def test_start_up_drops_the_retired_failed_controls_index() -> None:
    scenarios = ThreatScenarioRepository()
    scenarios.collection.create_index([("controls.status", 1), ("controls.last_attempt_at", 1)])
    scenarios.create_indexes()
    assert "controls.status_1_controls.last_attempt_at_1" not in scenarios.collection.index_information()


def test_archived_mapping_generations_are_kept_and_an_old_expiry_index_is_dropped() -> None:
    """Owner 2026-10-28: replaced Service Mapper answers are never deleted. A database that already built
    the 90-day expiry index loses it at start-up, so MongoDB deletes nothing from the history."""
    history = MappingHistoryRepository()
    history.collection.create_index("archived_at", expireAfterSeconds=int(timedelta(days=90).total_seconds()))
    history.create_indexes()
    indexes = history.collection.index_information()
    assert [name for name, index in indexes.items() if "expireAfterSeconds" in index] == []
