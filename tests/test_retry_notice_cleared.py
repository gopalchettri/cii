"""A retry notice is cleared when a worker claims the job for its next try, so no status shows an old outage
while that try runs."""

import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from app.core.constants import AI_OUTAGE_MESSAGES, AiOutage, Collection, Decision, Status, Step, TaskName
from app.core.database import get_mongodb
from app.data_access.jobs.job_repository import JobRepository
from app.domain.scenario.results import build_board
from app.domain.service_mapper.views import mapping_status, mapping_view
from app.models.remediation.plan import RemediationStatus
from app.models.scenario.views import session_status_from_record

#: Each job collection: its job's task, its record's own fields, and how its status reads the notice.
_READERS: dict[Collection, tuple[TaskName, dict[str, Any], list[Callable[[dict[str, Any]], Any]]]] = {
    Collection.SESSIONS: (
        TaskName.FIND_THREATS,
        {"entity_id": 86, "asset_id": 103, "step": Step.THREATS},
        [lambda record: build_board(session_status_from_record(record)).progress.retrying],
    ),
    Collection.REMEDIATIONS: (
        TaskName.WRITE_PLAN,
        {"entity_id": 86, "scenario_id": "s-1", "session_id": "run-1", "decision": Decision.PENDING},
        [lambda record: RemediationStatus.from_record(record).progress.retrying],
    ),
    Collection.SERVICE_MAPPINGS: (
        TaskName.MAP_SERVICES,
        {"tenant_id": "t-1", "entity_id": 86, "generation": 1, "created_at": datetime.now(UTC)},
        [lambda record: mapping_status(record).retrying, lambda record: mapping_view(record).retrying],
    ),
}


@pytest.mark.parametrize("collection", list(_READERS))
def test_claiming_the_next_try_clears_the_retry_notice_every_status_shows(collection: Collection) -> None:
    task, fields, readers = _READERS[collection]
    records = get_mongodb()[collection]
    now = datetime.now(UTC)
    notice = {
        "reason": AiOutage.BUSY,
        "message": AI_OUTAGE_MESSAGES[AiOutage.BUSY],
        "attempt": 1,
        "max_attempts": 5,
        "retry_at": now - timedelta(seconds=1),
    }
    record_id = uuid.uuid4().hex
    job = {"task": task, "epoch": 1, "attempts": 1, "due_at": now, "retry": notice}
    records.insert_one({"_id": record_id, "status": Status.QUEUED, "updated_at": now, "job": job, **fields})
    queued = records.find_one({"_id": record_id})
    assert all(read(queued) is not None for read in readers)  # waiting for its next try: shown

    assert JobRepository(records).claim_job(record_id, 1, task, "retry-2") is not None
    running = records.find_one({"_id": record_id})
    records.delete_one({"_id": record_id})  # the shared test database keeps no leased record for later tests
    assert running["status"] == Status.RUNNING and running["job"]["retry"] is None
    assert [read(running) for read in readers] == [None] * len(readers)
