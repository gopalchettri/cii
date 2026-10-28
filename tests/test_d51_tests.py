"""Failure branches only their main path covered: a live update Redis refuses, a cancel during a job's last
attempt, a reaper pass on reads another pass already settled, and a run's controls lease lost mid-turn."""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from celery.exceptions import Ignore
from redis.exceptions import ConnectionError as RedisConnectionError
from structlog.testing import capture_logs

from app.core.config import get_settings
from app.core.constants import Collection, Controls, ErrorMessage, Lease, LogEvent, Status, TaskName
from app.core.database import get_mongodb
from app.core.exceptions import Unavailable
from app.data_access.jobs.job_repository import JobLease, JobRepository, ended_job_fields
from app.realtime import publisher
from app.worker import jobs, reaper
from app.worker.scenario import controls_job
from tests.test_control_mapping import (  # noqa: F401 - fixture used by name
    _controls_of,
    _deliver,
    _run_record,
    mapping_run,
)
from tests.test_worker import (  # noqa: F401 - fixture used by name
    _insert_job,
    _job_failures,
    _records,
    _task,
    published,
)


@pytest.mark.parametrize("refused_at", ["publish", "connect"])
def test_a_live_update_redis_refuses_is_logged_and_never_fails_the_saved_change(
    monkeypatch: pytest.MonkeyPatch, refused_at: str
) -> None:
    """Each refused publish is one warning naming its channel, never raised: a job whose every announcement
    failed still finishes."""

    def refused(*_args: Any) -> Any:
        raise RedisConnectionError("refused")

    client = SimpleNamespace(publish=refused)
    monkeypatch.setattr(publisher, "get_redis_client", refused if refused_at == "connect" else lambda: client)
    record_id = _insert_job()
    with capture_logs() as logs:
        publisher.publish_session_status("run-1")
        publisher.publish_remediation_status("plan-1")
        publisher.publish_mapping_status("mapping-1")
        jobs.run_leased_job(
            _task(),
            Collection.SESSIONS,
            record_id,
            1,
            lambda lease: lease.update_job(ended_job_fields(Status.DONE)),
        )
    failed = [
        (line["channel"], line["log_level"])
        for line in logs
        if line["event"] == LogEvent.EVENT_PUBLISH_FAILED
    ]
    channels = [publisher.session_channel("run-1"), publisher.remediation_channel("plan-1")]
    channels += [publisher.mapping_channel("mapping-1")] + [publisher.session_channel(record_id)] * 2
    assert failed == [(channel, "warning") for channel in channels]  # the job's: claimed, then done
    assert _records().find_one({"_id": record_id})["status"] == Status.DONE


def test_a_job_its_owner_cancelled_during_its_last_attempt_ends_quietly(
    published: list[str],  # noqa: F811 - the imported fixture
) -> None:
    """On the last attempt an outage fails the job; once its owner cancelled it, nothing is failed or retried:
    the delivery ends with no outcome and the record keeps the cancel."""
    record_id = _insert_job(attempts=Lease.MAX_ATTEMPTS - 1)

    def cancelled_then_outage(_lease: JobLease) -> None:
        _records().update_one({"_id": record_id}, {"$set": {"status": Status.CANCELLED}})
        raise Unavailable(ErrorMessage.AI_UNREACHABLE)

    with capture_logs() as logs, pytest.raises(Ignore):
        jobs.run_leased_job(_task(), Collection.SESSIONS, record_id, 1, cancelled_then_outage)
    record = _records().find_one({"_id": record_id})
    assert (record["status"], record["job"]["attempts"]) == (Status.CANCELLED, Lease.MAX_ATTEMPTS)
    assert "error" not in record["job"]
    events = {line["event"] for line in logs}
    assert LogEvent.JOB_STOPPED_BY_OWNER in events
    assert not {LogEvent.JOB_FAILED, LogEvent.JOB_RETRY_SCHEDULED, LogEvent.JOB_LEASE_LOST} & events
    assert published == [record_id]  # its claim only


def _reads(records: list[dict[str, Any]]) -> Callable[..., list[dict[str, Any]]]:
    """A reaper scan that returns `records` for the runs, read earlier, and nothing elsewhere."""
    return lambda repository, _when: records if repository._records.name == Collection.SESSIONS else []


def test_a_reaper_pass_on_reads_another_pass_already_settled_repeats_nothing(
    published: list[str],  # noqa: F811 - the imported fixture
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Beat can start a pass while one still runs (3 threads, twin pods). Every reaper write applies only to
    the record as its pass read it, so a pass on older reads sends, fails and counts nothing again, and never
    requeues a job a new delivery took meanwhile."""
    for collection in jobs.JOB_COLLECTIONS:
        get_mongodb()[collection].delete_many({})
    sent: list[tuple] = []
    monkeypatch.setattr(reaper, "send_job", lambda *args, **_priority: sent.append(args) or True)
    monkeypatch.setattr(reaper, "count_waiting_messages", lambda _queue: 0)
    long_ago = datetime.now(UTC) - timedelta(hours=1)
    dead = _insert_job(Status.RUNNING, attempts=1, lease_until=long_ago, task_id="gone")
    worn_out = _insert_job(Status.RUNNING, attempts=Lease.MAX_ATTEMPTS, lease_until=long_ago, task_id="gone")
    lost = _insert_job(Status.QUEUED, due_at=long_ago)
    now, runs = datetime.now(UTC), JobRepository(_records())
    expired = list(runs.list_expired_jobs(now))
    unsent = list(runs.list_unsent_jobs(now - timedelta(seconds=Lease.REQUEUE_QUEUED_AFTER_SECONDS)))
    failures_before = _job_failures()
    reaper.reap_jobs()
    assert runs.claim_job(dead, 1, TaskName.FIND_THREATS, "new-delivery") is not None  # the re-send ran
    monkeypatch.setattr(JobRepository, "list_expired_jobs", _reads(expired))
    monkeypatch.setattr(JobRepository, "list_unsent_jobs", _reads(unsent))
    reaper.reap_jobs()
    assert sorted(record_id for _, record_id, _ in sent) == sorted([dead, lost])
    assert _job_failures() == failures_before + 1
    taken = _records().find_one({"_id": dead})["job"]
    assert (taken["task_id"], taken["lease_until"] > now) == ("new-delivery", True)
    assert _records().find_one({"_id": lost})["job"]["resends"] == 1
    assert sorted(published) == sorted([dead, worn_out])


def test_a_delivery_whose_run_was_taken_over_mid_turn_maps_no_more_and_leaves_the_new_lease(
    mapping_run: dict[str, Any],  # noqa: F811 - the imported fixture
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The run's delivery lease ran out while one scenario was mapped and another delivery took the run: this
    one stops after that scenario, leaving the rest, the lease and the next message to the new holder."""
    record_id = mapping_run["record_id"]
    monkeypatch.setattr(get_settings(), "rerank_base_url", "")  # one by one: a turn has a second claim
    monkeypatch.setattr(Controls, "PER_DELIVERY", 2)
    map_one = controls_job.RunControls._map_one
    another = {"task_id": "another", "until": datetime.now(UTC) + timedelta(minutes=5)}

    def map_then_lose_the_run(self: controls_job.RunControls, scenario: dict[str, Any]) -> int:
        mapped = map_one(self, scenario)
        get_mongodb()[Collection.SESSIONS].update_one(
            {"_id": record_id}, {"$set": {"controls_delivery": another}}
        )
        return mapped

    monkeypatch.setattr(controls_job.RunControls, "_map_one", map_then_lose_the_run)
    assert _deliver(record_id, "task-1") == 1
    assert _controls_of(f"{record_id}-2")["status"] == Status.QUEUED
    assert _run_record(record_id)["controls_delivery"]["task_id"] == "another"
    assert mapping_run["sent"] == []
