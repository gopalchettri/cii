"""The claim path of a leased job: a retry takes back its own claim whose answer was lost, a takeover's queue
wait counts from when the old lease ran out (a take-back's from its own last claim or renewal), a job waiting
for another job never flickers running, and a refused send shows on the job's own status body."""

import random
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from celery.exceptions import Ignore
from prometheus_client import REGISTRY
from pymongo.errors import AutoReconnect

from app import container
from app.core.constants import Collection, Decision, ErrorMessage, Lease, Status, TaskName
from app.core.constants.job_modules import module_of
from app.core.database import get_mongodb
from app.core.exceptions import WaitingForAnotherJob
from app.data_access.jobs.job_repository import JobLease, JobRepository, new_job
from app.domain.scenario.results import build_board
from app.domain.service_mapper.views import mapping_status
from app.models.admin.api_clients import Principal
from app.models.remediation.plan import RemediationStatus, RemediationSummary, version_status
from app.models.scenario.views import session_status_from_record
from app.worker import celery_app, jobs
from app.worker.celery_app import BrokerUnavailable, send_job

#: This module's own organisation: other tests' work never shows in its jobs list.
ENTITY = random.randint(10_000_000, 99_999_999)  # noqa: S311 - test data, not security


class RetryRequested(Exception):
    """Stands in for Celery's Retry."""


def _insert(collection: str, task: TaskName, status: Status = Status.QUEUED, **job: Any) -> str:
    """A job record with every field its status body reads, `job` over a fresh job of `task`; its id."""
    record_id, now = uuid.uuid4().hex, datetime.now(UTC)
    record = {
        "_id": record_id,
        "entity_id": ENTITY,
        "asset_id": 103,
        "tenant_id": "tenant-1",
        "scenario_id": uuid.uuid4().hex,  # one plan per scenario
        "session_id": "session-1",
        "decision": Decision.PENDING,
        "generation": 1,
        "status": status,
        "created_at": now,
        "updated_at": now,
        "job": new_job(task, 1, now) | job,
    }
    get_mongodb()[collection].insert_one(record)
    return record_id


def _task(task_id: str = "task-1", retries: int = 0, name: str = TaskName.FIND_THREATS) -> Any:
    """What run_leased_job uses of a Celery delivery: name, id, retry count, and retry (Celery raises it)."""
    return SimpleNamespace(
        name=name,
        request=SimpleNamespace(id=task_id, retries=retries, hostname="worker-1"),
        retry=lambda **_options: RetryRequested(),
    )


@pytest.fixture
def published(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Every status announcement of a session or a plan, in order."""
    announced: list[str] = []
    monkeypatch.setitem(jobs.JOB_COLLECTIONS, Collection.SESSIONS, announced.append)
    monkeypatch.setitem(jobs.JOB_COLLECTIONS, Collection.REMEDIATIONS, announced.append)
    return announced


def test_a_retry_takes_back_its_own_claim_whose_answer_was_lost(
    monkeypatch: pytest.MonkeyPatch, published: list[str]
) -> None:
    """MongoDB saved the claim but its answer was lost: the delivery's retry found its own live lease, was
    dropped as `leased`, and the job idled until the lease ran out and the reaper re-sent it, an attempt
    spent for nothing."""
    record_id = _insert(Collection.SESSIONS, TaskName.FIND_THREATS)
    real_claim = JobRepository.claim_job

    def claim_then_lose_the_answer(self: JobRepository, *args: Any, **kwargs: Any) -> None:
        real_claim(self, *args, **kwargs)
        raise AutoReconnect("connection closed before the reply")

    monkeypatch.setattr(JobRepository, "claim_job", claim_then_lose_the_answer)
    with pytest.raises(RetryRequested):
        jobs.run_leased_job(_task(retries=0), Collection.SESSIONS, record_id, 1, lambda _lease: None)
    monkeypatch.setattr(JobRepository, "claim_job", real_claim)
    with pytest.raises(Ignore):  # a redelivered copy of that delivery (same retry count) never steals it
        jobs.run_leased_job(_task(retries=0), Collection.SESSIONS, record_id, 1, lambda _lease: None)
    ran: list[int] = []
    jobs.run_leased_job(
        _task(retries=1), Collection.SESSIONS, record_id, 1, lambda lease: ran.append(lease.attempts)
    )
    assert ran == [2]


def _queue_waits() -> tuple[float, float]:
    """(waits observed, waits over a minute) of tsg_job_queue_wait_seconds for the threats task."""
    labels = {"task": TaskName.FIND_THREATS, "module": module_of(TaskName.FIND_THREATS)}
    count = REGISTRY.get_sample_value("tsg_job_queue_wait_seconds_count", labels) or 0.0
    within = REGISTRY.get_sample_value("tsg_job_queue_wait_seconds_bucket", labels | {"le": "60.0"}) or 0.0
    return count, count - within


def test_a_takeover_counts_its_wait_from_when_the_old_lease_ran_out(published: list[str]) -> None:
    """A redelivery taking over a dead delivery's job counted its wait from the job's first due time: the
    dead run and the lease's expiry, often over an hour, raising JobQueueWaitHigh for one sample."""
    now = datetime.now(UTC)
    record_id = _insert(
        Collection.SESSIONS,
        TaskName.FIND_THREATS,
        Status.RUNNING,
        due_at=now - timedelta(hours=2),
        lease_until=now - timedelta(seconds=10),
        attempts=1,
        task_id="dead",
    )
    waits, slow = _queue_waits()
    jobs.run_leased_job(_task("redelivered"), Collection.SESSIONS, record_id, 1, lambda _lease: None)
    assert _queue_waits() == (waits + 1, slow)
    assert get_mongodb()[Collection.SESSIONS].find_one({"_id": record_id})["job"]["attempts"] == 2


def test_a_take_back_after_a_failed_give_back_counts_its_wait_from_its_own_last_claim(
    monkeypatch: pytest.MonkeyPatch, published: list[str]
) -> None:
    """A MongoDB blip failed a job's write and then its give-back, so the record stayed running under a live
    lease; the retry took it back counting its queue wait from the job's first due time, hours earlier: one
    slow sample that raised JobQueueWaitHigh."""
    record_id = _insert(
        Collection.SESSIONS, TaskName.FIND_THREATS, due_at=datetime.now(UTC) - timedelta(hours=2)
    )
    real_update = JobLease.update_job

    def store_down(*_args: Any, **_kwargs: Any) -> None:
        raise AutoReconnect("store down")

    def written_while_the_store_blips(lease: JobLease) -> None:
        monkeypatch.setattr(JobLease, "update_job", store_down)
        lease.update_job({"counts.written": 1})  # the job's write; its give-back then fails the same way

    with pytest.raises(RetryRequested):
        jobs.run_leased_job(
            _task(retries=0), Collection.SESSIONS, record_id, 1, written_while_the_store_blips
        )
    monkeypatch.setattr(JobLease, "update_job", real_update)
    assert get_mongodb()[Collection.SESSIONS].find_one({"_id": record_id})["status"] == Status.RUNNING
    waits, slow = _queue_waits()
    ran: list[int] = []
    jobs.run_leased_job(
        _task(retries=1), Collection.SESSIONS, record_id, 1, lambda lease: ran.append(lease.attempts)
    )
    assert ran == [2]  # taken back at once, not left to the reaper
    assert _queue_waits() == (waits + 1, slow)


def _plan_statuses(record_id: str) -> tuple[Status, ...]:
    """(latest_status, progress.generation, a list's latest_status, its GET /v1/jobs row's status, the
    latest version's status a decision reads) as a client reads the plan now."""
    plans = get_mongodb()[Collection.REMEDIATIONS]
    status = RemediationStatus.from_record(
        plans.find_one({"_id": record_id}, RemediationStatus.RECORD_FIELDS), scenario_accepted=True
    )
    listed = RemediationSummary.from_record(
        plans.find_one({"_id": record_id}, RemediationSummary.RECORD_FIELDS)
    )
    caller = Principal(client_id="c1", user_id="u1", entity_id=ENTITY, tenant_id="tenant-1")
    jobs_list = container.get_job_service().list_jobs(caller).jobs
    job_row = next(job for job in jobs_list if job.remediation_id == record_id)
    decided = container.get_remediation_repository().get(fields="change", _id=record_id)
    decided_status = version_status(decided, {"version": decided["job"]["epoch"]})
    return (
        status.latest_status,
        status.progress.generation,
        listed.latest_status,
        job_row.status,
        decided_status,
    )


def test_a_plan_waiting_for_another_job_never_reads_running_and_is_announced_once(
    published: list[str],
) -> None:
    """Each 15 s look claimed the plan (running, announced), then gave it back (queued, announced): the
    stream and the status flickered running and queued for as long as the controls were being mapped."""
    record_id = _insert(Collection.REMEDIATIONS, TaskName.WRITE_PLAN)
    seen: list[tuple[Status, ...]] = []

    def controls_being_mapped(_lease: JobLease) -> None:
        seen.append(_plan_statuses(record_id))
        raise WaitingForAnotherJob("controls being mapped")

    for _look in range(2):
        with pytest.raises(jobs.JobWaiting):
            jobs.run_leased_job(
                _task(name=TaskName.WRITE_PLAN), Collection.REMEDIATIONS, record_id, 1, controls_being_mapped
            )
        assert published == [record_id, record_id]  # the first look's claim and give-back; nothing after
        get_mongodb()[Collection.REMEDIATIONS].update_one(
            {"_id": record_id}, {"$set": {"job.due_at": datetime.now(UTC)}}
        )
    assert seen[1] == (Status.QUEUED,) * 5  # the second look's claim: still queued
    assert _plan_statuses(record_id) == (Status.QUEUED,) * 5

    def runs(lease: JobLease) -> None:
        lease.renew_job()  # past the gate: its first fenced write
        seen.append(_plan_statuses(record_id))

    jobs.run_leased_job(_task(name=TaskName.WRITE_PLAN), Collection.REMEDIATIONS, record_id, 1, runs)
    assert seen[2] == (Status.RUNNING,) * 5
    assert published[2:] == [record_id]  # its end


@pytest.mark.parametrize(
    ("task", "collection", "retrying"),
    [
        (
            TaskName.FIND_THREATS,
            "tsg_sessions",
            lambda record: build_board(session_status_from_record(record)).progress.retrying,
        ),
        (
            TaskName.WRITE_PLAN,
            "tsg_remediations",
            lambda record: RemediationStatus.from_record(record, True).progress.retrying,
        ),
        (TaskName.MAP_SERVICES, "tsg_service_mappings", lambda record: mapping_status(record, 5).retrying),
    ],
)
def test_a_refused_send_shows_on_the_jobs_own_status(
    monkeypatch: pytest.MonkeyPatch, task: TaskName, collection: str, retrying: Any
) -> None:
    """A send the broker refused was only logged (and shown on GET /v1/admin/jobs): the run, plan or mapping
    status read a plain queued job with nothing to say why it did not start."""
    record_id = _insert(collection, task)

    def refused(*_args: Any, **_message: Any) -> None:
        raise BrokerUnavailable("down")

    monkeypatch.setattr(celery_app, "send_task", refused)
    before = datetime.now(UTC)
    assert send_job(task, record_id, 1) is False
    records = get_mongodb()[collection]
    notice = retrying(records.find_one({"_id": record_id}))
    assert (notice.message, notice.reason, notice.attempt) == (ErrorMessage.REDIS_UNREACHABLE, None, 0)
    retry_after = timedelta(seconds=Lease.REQUEUE_QUEUED_AFTER_SECONDS)
    assert before + retry_after <= notice.retry_at.replace(tzinfo=UTC) <= datetime.now(UTC) + retry_after
    assert JobRepository(records).claim_job(record_id, 1, task, "picked-up") is not None
    assert retrying(records.find_one({"_id": record_id})) is None  # its delivery started: no notice


def test_a_refused_send_with_no_job_record_or_no_store_writes_nothing_and_never_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A controls send has no job record of its own (a done run's controls); MongoDB down too only skips the
    notice: send_job still answers False, so the API call that sent it still succeeds."""
    done_run = _insert(Collection.SESSIONS, TaskName.WRITE_SCENARIOS, Status.DONE)

    def refused(*_args: Any, **_message: Any) -> None:
        raise BrokerUnavailable("down")

    monkeypatch.setattr(celery_app, "send_task", refused)
    assert send_job(TaskName.MAP_CONTROLS, done_run, 0) is False
    assert get_mongodb()[Collection.SESSIONS].find_one({"_id": done_run})["job"].get("retry") is None

    def store_down(*_args: Any, **_kwargs: Any) -> None:
        raise AutoReconnect("down")

    monkeypatch.setattr(JobRepository, "note_unsent_job", store_down, raising=False)
    assert send_job(TaskName.FIND_THREATS, _insert(Collection.SESSIONS, TaskName.FIND_THREATS), 1) is False
