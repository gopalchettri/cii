"""A mapping that failed for an outage leaves no lasting mark: its own Idempotency-Key starts a new try."""

import contextlib
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest

from app import container
from app.core.constants import (
    AI_OUTAGE_MESSAGES,
    AiOutage,
    Collection,
    ErrorCode,
    Lease,
    MapperConflict,
    MappingOverall,
    Status,
    TaskName,
)
from app.core.database import get_mongodb
from app.core.exceptions import Conflict, Unavailable
from app.data_access.admin.audit_repository import AuditRepository
from app.data_access.jobs.job_repository import JobLease
from app.data_access.service_mapper.mapping_repository import MappingHistoryRepository, MappingRepository
from app.domain.service_mapper.reconcile import reconcile
from app.models.service_mapper.contract import DependencyDecisionRequest, MappingAccepted
from app.services.service_mapper.service_mapper_service import ServiceMapperService
from app.worker import jobs
from tests.test_service_mapper import PRINCIPAL, _answer, _catalog, _record, _request


def _mapper() -> tuple[ServiceMapperService, list[tuple[Any, ...]]]:
    """The mapper service and every job it sends."""
    sent: list[tuple[Any, ...]] = []
    mapper = ServiceMapperService(
        MappingRepository(),
        MappingHistoryRepository(),
        container.get_settings(),
        lambda *job: sent.append(job),
        None,  # type: ignore[arg-type]
        AuditRepository(),
        lambda _mapping_id: None,
    )
    return mapper, sent


def _busy() -> Unavailable:
    return Unavailable(AI_OUTAGE_MESSAGES[AiOutage.BUSY], reason=AiOutage.BUSY)


def _fail_on_the_last_try(mapping_id: str, error: Exception) -> None:
    """The current generation's last try raises `error`; the worker settles the mapping as it does on UAT."""
    records = get_mongodb()[Collection.SERVICE_MAPPINGS]
    generation = records.find_one({"_id": mapping_id})["generation"]
    records.update_one({"_id": mapping_id}, {"$set": {"job.attempts": Lease.MAX_ATTEMPTS - 1}})
    task: Any = SimpleNamespace(
        name=TaskName.MAP_SERVICES, request=SimpleNamespace(id=uuid4().hex), retry=None
    )

    def work(_lease: JobLease) -> None:
        raise error

    with contextlib.suppress(type(error)):  # run_leased_job re-raises what it settled
        jobs.run_leased_job(task, Collection.SERVICE_MAPPINGS, mapping_id, generation, work)
    assert records.find_one({"_id": mapping_id})["status"] == Status.FAILED


def _map(mapping_id: str, generation: int) -> tuple[TaskName, str, int]:
    return TaskName.MAP_SERVICES, mapping_id, generation


def test_regenerate_with_a_new_key_after_an_outage_failure_starts_the_next_generation() -> None:
    regen_key = uuid4().hex
    mapper, sent = _mapper()
    mapping_id = mapper.create_service_mapping(PRINCIPAL, _request(), None)[0].mapping_id
    _fail_on_the_last_try(mapping_id, _busy())
    failed = mapper.get_service_mapping_status(PRINCIPAL, mapping_id)
    assert failed.error is not None and (failed.error.code, failed.error.reason) == ("unavailable", "ai_busy")
    started, created = mapper.regenerate_service_mapping(PRINCIPAL, mapping_id, regen_key)
    assert (started.generation, created, sent[-1]) == (2, True, _map(mapping_id, 2))
    status = mapper.get_service_mapping_status(PRINCIPAL, mapping_id)
    assert (status.progress.overall, status.error, status.retrying) == (MappingOverall.GENERATING, None, None)
    archived = get_mongodb()[Collection.SERVICE_MAPPING_HISTORY].find_one({"_id": f"{mapping_id}:1"})
    assert archived["error"]["code"] == ErrorCode.UNAVAILABLE


def test_the_same_create_key_after_an_outage_failure_starts_a_new_try() -> None:
    create_key = uuid4().hex
    mapper, sent = _mapper()
    mapping_id = mapper.create_service_mapping(PRINCIPAL, _request(), create_key)[0].mapping_id
    for generation in (2, 3):  # each outage failure: the same key and body send one new try
        _fail_on_the_last_try(mapping_id, _busy())
        retried, created = mapper.create_service_mapping(PRINCIPAL, _request(), create_key)
        assert (retried.mapping_id, retried.generation, created) == (mapping_id, generation, True)
        assert sent == [_map(mapping_id, n) for n in range(1, generation + 1)]
    replayed, created = mapper.create_service_mapping(PRINCIPAL, _request(), create_key)
    assert (replayed.generation, created, len(sent)) == (3, False, 3)  # queued: a replay
    assert _record(mapping_id)["status"] == Status.QUEUED


def test_the_same_regenerate_key_after_an_outage_failure_starts_a_new_try() -> None:
    regen_key = uuid4().hex
    mapper, sent = _mapper()
    mapping_id = mapper.create_service_mapping(PRINCIPAL, _request(), None)[0].mapping_id
    _fail_on_the_last_try(mapping_id, _busy())
    first, _ = mapper.regenerate_service_mapping(PRINCIPAL, mapping_id, regen_key)
    _fail_on_the_last_try(mapping_id, _busy())
    retried, created = mapper.regenerate_service_mapping(PRINCIPAL, mapping_id, regen_key)
    assert (first.generation, retried.generation, created) == (2, 3, True)
    assert sent == [_map(mapping_id, 1), _map(mapping_id, 2), _map(mapping_id, 3)]
    replayed, created = mapper.regenerate_service_mapping(PRINCIPAL, mapping_id, regen_key)
    assert (replayed.generation, created, len(sent)) == (3, False, 3)  # queued: a replay
    with pytest.raises(Conflict) as running:
        mapper.regenerate_service_mapping(PRINCIPAL, mapping_id, uuid4().hex)
    assert running.value.reason == MapperConflict.GENERATION_IN_PROGRESS


def test_a_key_whose_generation_failed_for_another_reason_still_replays() -> None:
    create_key, regen_key = uuid4().hex, uuid4().hex
    mapper, sent = _mapper()
    mapping_id = mapper.create_service_mapping(PRINCIPAL, _request(), create_key)[0].mapping_id
    _fail_on_the_last_try(mapping_id, RuntimeError("a bug"))
    assert _record(mapping_id)["job"]["error"]["code"] == ErrorCode.INTERNAL_ERROR
    replayed, created = mapper.create_service_mapping(PRINCIPAL, _request(), create_key)
    assert (replayed.generation, created) == (1, False)
    mapper.regenerate_service_mapping(PRINCIPAL, mapping_id, regen_key)
    _fail_on_the_last_try(mapping_id, RuntimeError("a bug"))
    replayed, created = mapper.regenerate_service_mapping(PRINCIPAL, mapping_id, regen_key)
    assert (replayed.generation, created, len(sent)) == (2, False, 2)
    assert _record(mapping_id)["status"] == Status.FAILED


def test_an_older_key_replays_when_a_later_generation_failed_for_an_outage() -> None:
    create_key, regen_key = uuid4().hex, uuid4().hex
    mapper, sent = _mapper()
    mapping_id = mapper.create_service_mapping(PRINCIPAL, _request(), create_key)[0].mapping_id
    result = reconcile(mapping_id, 1, _request(), _answer(), _catalog(), 20, 20)
    get_mongodb()[Collection.SERVICE_MAPPINGS].update_one(
        {"_id": mapping_id}, {"$set": {"status": Status.DONE, "active": False, "result": result}}
    )
    mapper.regenerate_service_mapping(PRINCIPAL, mapping_id, regen_key)
    _fail_on_the_last_try(mapping_id, _busy())
    replayed, created = mapper.create_service_mapping(PRINCIPAL, _request(), create_key)
    assert (replayed.generation, created, len(sent)) == (1, False, 2)  # generation 1 finished: a replay
    retried, created = mapper.regenerate_service_mapping(PRINCIPAL, mapping_id, regen_key)
    assert (retried.generation, created, sent[-1]) == (3, True, _map(mapping_id, 3))


def _before_the_first_cas(monkeypatch: pytest.MonkeyPatch, competitor: Callable[[], object]) -> None:
    """`competitor` runs to the end just before the first start_generation, so that CAS loses to it."""
    start_generation = MappingRepository.start_generation
    raced: list[bool] = []

    def racing(self: MappingRepository, *args: Any) -> bool:
        if not raced:
            raced.append(True)
            competitor()
        return start_generation(self, *args)

    monkeypatch.setattr(MappingRepository, "start_generation", racing)


def test_two_replays_of_an_outage_failed_create_at_once_send_one_new_try(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    create_key = uuid4().hex
    mapper, sent = _mapper()
    mapping_id = mapper.create_service_mapping(PRINCIPAL, _request(), create_key)[0].mapping_id
    _fail_on_the_last_try(mapping_id, _busy())
    first: list[tuple[MappingAccepted, bool]] = []
    _before_the_first_cas(
        monkeypatch, lambda: first.append(mapper.create_service_mapping(PRINCIPAL, _request(), create_key))
    )
    second = mapper.create_service_mapping(PRINCIPAL, _request(), create_key)  # its CAS loses: a replay
    answers = [(accepted.generation, created) for accepted, created in [*first, second]]
    assert answers == [(2, True), (2, False)]
    assert sent == [_map(mapping_id, 1), _map(mapping_id, 2)]


@pytest.mark.parametrize("competitor_fails", [False, True], ids=["still_queued", "failed_again"])
def test_a_create_replay_that_loses_to_another_keys_regenerate_replays(
    monkeypatch: pytest.MonkeyPatch, competitor_fails: bool
) -> None:
    create_key = uuid4().hex
    mapper, sent = _mapper()
    mapping_id = mapper.create_service_mapping(PRINCIPAL, _request(), create_key)[0].mapping_id
    _fail_on_the_last_try(mapping_id, _busy())

    def regenerate_with_another_key() -> None:
        mapper.regenerate_service_mapping(PRINCIPAL, mapping_id, uuid4().hex)
        if competitor_fails:
            _fail_on_the_last_try(mapping_id, _busy())

    _before_the_first_cas(monkeypatch, regenerate_with_another_key)
    replayed, created = mapper.create_service_mapping(PRINCIPAL, _request(), create_key)
    assert (replayed.generation, created) == (1, False)  # generation 1 is no longer the latest: a replay
    assert sent == [_map(mapping_id, 1), _map(mapping_id, 2)]


def test_deciding_on_a_failed_mapping_says_to_regenerate_it() -> None:
    mapper, _ = _mapper()
    mapping_id = mapper.create_service_mapping(PRINCIPAL, _request(), None)[0].mapping_id
    _fail_on_the_last_try(mapping_id, _busy())
    with pytest.raises(Conflict) as refused:
        mapper.decide_dependencies(PRINCIPAL, mapping_id, DependencyDecisionRequest(accept=["any"]))
    assert (refused.value.status, refused.value.code, refused.value.reason) == (409, ErrorCode.CONFLICT, None)
    assert "failed" in refused.value.detail and "regenerate" in refused.value.detail
