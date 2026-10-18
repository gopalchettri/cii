"""The review API (Step 14, BUILD_PLAN S38-S39): accept (#4) and reject (#5); T-SCN-13..19. Runs and scenarios
are written straight into the test MongoDB; the library is a small in-memory one."""

import threading
import uuid
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.core.constants import (
    AuditAction,
    Collection,
    ConflictReason,
    Decision,
    Header,
    ScenarioStatus,
    Status,
    Step,
    StrideCategory,
    TargetProblem,
)
from app.core.database import get_mongodb
from app.core.exceptions import Conflict
from app.data_access.scenario.repository import scenarios, session_status_from_record
from app.domain.scenario.plan import why_no_path_left
from app.domain.scenario.review import decided_stamp
from app.models.api_clients import Principal
from app.models.library import LibraryThreat, ThreatLibrary
from app.models.scenario.views import AcceptRequest, ScenarioIdsRequest
from app.services.api_clients import get_api_client_service
from app.services.scenario import review as review_module
from app.services.scenario.review import ReviewService, get_review_service

#: Library threat 1 is live; 99 was retired after its scenario was written.
LIBRARY = ThreatLibrary(
    threats=(LibraryThreat(1, "Firmware tampering", 1, "Malware", (StrideCategory.TAMPERING,), ()),),
    actors=(),
)
PUBLISHED: list[str] = []


@pytest.fixture(scope="module")
def api_key() -> str:
    _, key = get_api_client_service().mint_api_client(f"review-{uuid.uuid4().hex[:8]}", None, "test")
    return key


@pytest.fixture
def service(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> Iterator[ReviewService]:
    built = ReviewService(lambda: LIBRARY)
    client.app.dependency_overrides[get_review_service] = lambda: built  # type: ignore[attr-defined]
    monkeypatch.setattr(review_module, "publish_session_status", PUBLISHED.append)
    yield built
    client.app.dependency_overrides.pop(get_review_service, None)  # type: ignore[attr-defined]


def _identity(api_key: str, entity_id: int = 86) -> dict[str, str]:
    return {
        Header.API_KEY: api_key,
        Header.USER_ID: "u1",
        Header.ENTITY_ID: str(entity_id),
        Header.TENANT_ID: "DESC",
    }


def _run(status: Status = Status.DONE, step: Step = Step.SCENARIOS) -> str:
    record_id = uuid.uuid4().hex
    get_mongodb()[Collection.SESSIONS].insert_one(
        {"_id": record_id, "entity_id": 86, "asset_id": 1, "status": status, "step": step, "counts": {},
         "job": {"epoch": 1}, "updated_at": datetime.now(UTC)}
    )  # fmt: skip
    return record_id


def _scenario(record_id: str, path_id: str, **fields: Any) -> str:
    """A written, pending, current version 1 of `path_id` on library threat 1; `fields` override any of it."""
    scenario_id = uuid.uuid4().hex
    record = {
        "_id": scenario_id, "session_id": record_id, "entity_id": 86, "asset_id": 1, "path_id": path_id,
        "version": 1, "source": "generated", "status": ScenarioStatus.DONE, "decision": Decision.PENDING,
        "decided_by": None, "decided_at": None, "replaces": None, "superseded_by": None,
        "content": {"title": f"Scenario {path_id}", "threat": {"library_id": 1, "ai_generated": False}},
        "controls": {"status": Status.QUEUED}, "created_at": datetime.now(UTC),
    }  # fmt: skip
    get_mongodb()[Collection.SCENARIOS].insert_one(record | fields)
    return scenario_id


def _decision(scenario_id: str) -> str:
    return get_mongodb()[Collection.SCENARIOS].find_one({"_id": scenario_id})["decision"]


def _audits(record_id: str, action: AuditAction) -> list[dict[str, Any]]:
    return list(get_mongodb()[Collection.AUDIT].find({"target.id": record_id, "action": action}))


def _post(client: TestClient, api_key: str, path: str, body: Any, entity_id: int = 86) -> Any:
    return client.post(path, json=body, headers=_identity(api_key, entity_id))


def test_accepting_decides_once_counts_audits_and_tells_watchers(
    client: TestClient, api_key: str, service: ReviewService
) -> None:
    """T-SCN-13: one update, the run's counts, one audit record, the calling system stored, a live update; a
    repeat (a double click) gives the same answer and writes nothing more."""
    record_id = _run()
    first, second = _scenario(record_id, "p1"), _scenario(record_id, "p2", controls={"status": Status.DONE})
    _scenario(record_id, "p3")
    PUBLISHED.clear()
    url = f"/v1/sessions/{record_id}/accept"
    answer = _post(client, api_key, url, {"scenario_ids": [first, second]})
    assert answer.status_code == 200, answer.text
    expected = {"accepted": [first, second], "replaced": [], "skipped": [], "controls_pending": [first]}
    assert answer.json() == expected
    run = get_mongodb()[Collection.SESSIONS].find_one({"_id": record_id})
    assert (run["counts"]["accepted"], run["counts"]["pending"]) == (2, 1)
    stored = get_mongodb()[Collection.SCENARIOS].find_one({"_id": first})
    client_id = get_api_client_service().find_client_id_for_api_key(api_key)
    assert (stored["decided_by"], stored["decided_by_client"]) == ("u1", client_id)
    assert [record_id] == PUBLISHED and len(_audits(record_id, AuditAction.SCENARIOS_ACCEPTED)) == 1
    again = _post(client, api_key, url, {"scenario_ids": [first, second]})
    assert again.json() == expected and len(_audits(record_id, AuditAction.SCENARIOS_ACCEPTED)) == 1
    # A repeat records nothing; it refreshes the counts again, which heals counts a first call that failed
    # after its decision write could not refresh (G143).
    assert [record_id, record_id] == PUBLISHED


def test_every_id_at_fault_is_named_and_nothing_is_written(
    client: TestClient, api_key: str, service: ReviewService
) -> None:
    """T-SCN-14: unknown (another run's scenario, a hidden blocked draft), a failure card, a rejected one, two
    versions of one path, a retired library threat: one 409 lists them all; the good id is not accepted
    either. An AI-proposed threat has no library row and passes."""
    record_id, other_run = _run(), _run()
    good = _scenario(record_id, "p1")
    faults = {
        "missing": TargetProblem.UNKNOWN,
        _scenario(other_run, "p1"): TargetProblem.UNKNOWN,
        _scenario(record_id, "p2", status=ScenarioStatus.FAILED): TargetProblem.FAILURE_SCENARIO,
        _scenario(record_id, "p3", decision=Decision.REJECTED): TargetProblem.ALREADY_REJECTED,
        _scenario(record_id, "p4"): TargetProblem.DUPLICATE_VERSION,
        _scenario(record_id, "p4", version=2): TargetProblem.DUPLICATE_VERSION,
        _scenario(record_id, "p5", status=ScenarioStatus.BLOCKED): TargetProblem.UNKNOWN,
        _scenario(record_id, "p6", content={"threat": {"library_id": 99}}): TargetProblem.LIBRARY_INACTIVE,
    }
    url = f"/v1/sessions/{record_id}/accept"
    answer = _post(client, api_key, url, {"scenario_ids": [good, *faults]})
    assert answer.status_code == 409, answer.text
    body = answer.json()
    assert body["reason"] == ConflictReason.SCENARIOS_NOT_DECIDABLE
    assert {error["scenario_id"]: error["reason"] for error in body["errors"]} == faults
    assert _decision(good) == Decision.PENDING
    ai_threat = _scenario(record_id, "p7", content={"threat": {"library_id": None, "ai_generated": True}})
    assert _post(client, api_key, url, {"scenario_ids": [ai_threat]}).status_code == 200


def test_one_accepted_version_per_path_unless_replace_accepted(
    client: TestClient, api_key: str, service: ReviewService
) -> None:
    """T-SCN-15/16: a second version of an accepted path → 409 duplicate_version; with replace_accepted the
    old one goes back to pending. An older (replaced) version may be accepted again (owner, 2026-10-09)."""
    record_id = _run()
    newer = _scenario(record_id, "p1", version=2)
    older = _scenario(record_id, "p1", decision=Decision.ACCEPTED, superseded_by=newer)
    url = f"/v1/sessions/{record_id}/accept"
    refused = _post(client, api_key, url, {"scenario_ids": [newer]})
    assert refused.status_code == 409 and refused.json()["reason"] == ConflictReason.DUPLICATE_VERSION
    replaced = _post(client, api_key, url, {"scenario_ids": [newer], "replace_accepted": True}).json()
    assert (replaced["replaced"], replaced["accepted"]) == ([older], [newer])
    assert (_decision(older), _decision(newer)) == (Decision.PENDING, Decision.ACCEPTED)
    back = _post(client, api_key, url, {"scenario_ids": [older], "replace_accepted": True}).json()
    assert back["accepted"] == [older] and _decision(newer) == Decision.PENDING


def test_accept_all_is_idempotent_and_never_replaces(
    client: TestClient, api_key: str, service: ReviewService
) -> None:
    """T-SCN-17 (S37 ruling): every current written scenario not rejected; one already accepted is listed
    again; a path with another accepted version and a retired threat are skipped; a repeat → the same answer;
    a run with nothing to accept → 409 nothing_to_accept."""
    record_id = _run()
    pending, accepted = _scenario(record_id, "p1"), _scenario(record_id, "p2", decision=Decision.ACCEPTED)
    _scenario(record_id, "p3", decision=Decision.REJECTED)
    newer = _scenario(record_id, "p4", version=2)
    _scenario(record_id, "p4", decision=Decision.ACCEPTED, superseded_by=newer)
    retired = _scenario(record_id, "p5", content={"threat": {"library_id": 99}})
    # Two current versions of one path (a regenerate crash never healed): the older one is taken.
    older, twin = _scenario(record_id, "p6"), _scenario(record_id, "p6", version=2)
    url = f"/v1/sessions/{record_id}/accept"
    answer = _post(client, api_key, url, {"scenario_ids": "all"}).json()
    assert sorted(answer["accepted"]) == sorted([pending, accepted, older]) and answer["replaced"] == []
    skipped = {item["scenario_id"]: item["reason"] for item in answer["skipped"]}
    assert skipped == {
        newer: TargetProblem.DUPLICATE_VERSION,
        retired: TargetProblem.LIBRARY_INACTIVE,
        twin: TargetProblem.DUPLICATE_VERSION,
    }
    assert _post(client, api_key, url, {"scenario_ids": "all"}).json() == answer
    nothing = _post(client, api_key, f"/v1/sessions/{_run()}/accept", {"scenario_ids": "all"})
    assert nothing.status_code == 409 and nothing.json()["reason"] == ConflictReason.NOTHING_TO_ACCEPT


def test_reject_is_final_and_a_repeat_changes_nothing(
    client: TestClient, api_key: str, service: ReviewService
) -> None:
    """T-SCN-18: an accepted scenario cannot be rejected (decisions are final, S37); a rejected one is listed
    again on a repeat, with one audit record and the run's count."""
    record_id = _run()
    accepted, pending = _scenario(record_id, "p1", decision=Decision.ACCEPTED), _scenario(record_id, "p2")
    url = f"/v1/sessions/{record_id}/scenarios/reject"
    refused = _post(client, api_key, url, {"scenario_ids": [accepted, pending]}).json()
    assert refused["errors"] == [{"scenario_id": accepted, "reason": TargetProblem.ALREADY_ACCEPTED}]
    expected = {"rejected": [pending], "skipped": []}
    assert _post(client, api_key, url, {"scenario_ids": [pending]}).json() == expected
    assert _post(client, api_key, url, {"scenario_ids": [pending]}).json() == expected
    assert len(_audits(record_id, AuditAction.SCENARIOS_REJECTED)) == 1
    assert get_mongodb()[Collection.SESSIONS].find_one({"_id": record_id})["counts"]["rejected"] == 1


def _at_the_same_moment(monkeypatch: pytest.MonkeyPatch, calls: list[Callable[[], Any]]) -> list[Any]:
    """The calls in parallel threads, each reading its targets before any of them writes."""
    barrier = threading.Barrier(len(calls))
    read = review_module.list_review_targets
    waited: set[int] = set()

    def read_then_wait(session_id: str, ids: list[str]) -> dict[str, dict[str, Any]]:
        found = read(session_id, ids)
        if threading.get_ident() not in waited:  # each call's first read only; its race re-read runs free
            waited.add(threading.get_ident())
            barrier.wait(timeout=10)
        return found

    monkeypatch.setattr(review_module, "list_review_targets", read_then_wait)
    results: list[Any] = [None] * len(calls)
    errors: list[Exception | None] = [None] * len(calls)

    def run(index: int) -> None:
        try:
            results[index] = calls[index]()
        except Exception as error:  # re-raised below, in the test's own thread
            errors[index] = error

    threads = [threading.Thread(target=run, args=(index,)) for index in range(len(calls))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    # A call's own error, never "None has no attribute accepted" (2026-10-12: a failure showed no cause).
    assert not any(thread.is_alive() for thread in threads), "a call did not finish in 30 s"
    if failed := next((error for error in errors if error is not None), None):
        raise failed
    return results


def test_a_call_failing_in_its_thread_fails_the_test_with_its_own_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ZeroDivisionError):
        _at_the_same_moment(monkeypatch, [lambda: 1 / 0, lambda: "fine"])


def test_two_calls_at_the_same_moment_exactly_one_wins(
    service: ReviewService, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T-SCN-19: an accept and a reject of one scenario, then two accepts of two versions of one path (the
    unique index decides): one changes it, the other reports changed_concurrently; never both."""
    record_id = _run()
    run = session_status_from_record(get_mongodb()[Collection.SESSIONS].find_one({"_id": record_id}))
    principal = Principal("client", "u1", 86, "DESC")
    target = _scenario(record_id, "p1")
    accept, reject = _at_the_same_moment(
        monkeypatch,
        [
            lambda: service.accept(principal, run, AcceptRequest(scenario_ids=[target])),
            lambda: service.reject(principal, run, ScenarioIdsRequest(scenario_ids=[target])),
        ],
    )
    assert [accept.accepted, reject.rejected].count([target]) == 1
    lost = [item.reason for item in (*accept.skipped, *reject.skipped)]
    assert lost == [TargetProblem.CHANGED_CONCURRENTLY]
    first, second = _scenario(record_id, "p2"), _scenario(record_id, "p2", version=2)
    one, two = _at_the_same_moment(
        monkeypatch,
        [
            lambda: _accept_or_refused(service, principal, run, first),
            lambda: _accept_or_refused(service, principal, run, second),
        ],
    )
    assert sorted([len(one), len(two)]) == [0, 1]
    assert [_decision(first), _decision(second)].count(Decision.ACCEPTED) == 1


def _accept_or_refused(service: ReviewService, principal: Principal, run: Any, scenario_id: str) -> list[str]:
    """What one of two racing accepts accepted. The loser either lost at the unique index (skipped,
    changed_concurrently) or, when the winner had already written before it read, was refused (409
    duplicate_version): both are right, and never are both accepted (the test read the second as a failure
    in 1 run of 6, 2026-10-13)."""
    try:
        return service.accept(principal, run, AcceptRequest(scenario_ids=[scenario_id])).accepted
    except Conflict as refused:
        assert refused.reason == ConflictReason.DUPLICATE_VERSION
        return []


def test_review_waits_for_generation_and_serves_the_callers_entity_only(
    client: TestClient, api_key: str, service: ReviewService
) -> None:
    """Rule S3 and T-SEC: 409 generation_in_progress while queued or running (in any step), run_failed for a
    run that failed finding threats; another entity's run → 403, nothing changed."""
    for status, step, reason in (
        (Status.RUNNING, Step.SCENARIOS, ConflictReason.GENERATION_IN_PROGRESS),
        (Status.QUEUED, Step.THREATS, ConflictReason.GENERATION_IN_PROGRESS),
        (Status.FAILED, Step.THREATS, ConflictReason.RUN_FAILED),
    ):
        answer = _post(client, api_key, f"/v1/sessions/{_run(status, step)}/accept", {"scenario_ids": ["x"]})
        assert (answer.status_code, answer.json()["reason"]) == (409, reason)
    record_id = _run()
    scenario_id = _scenario(record_id, "p1")
    for path in ("accept", "scenarios/reject"):
        body = {"scenario_ids": [scenario_id]}
        assert _post(client, api_key, f"/v1/sessions/{record_id}/{path}", body, 87).status_code == 403
    assert _decision(scenario_id) == Decision.PENDING


@pytest.mark.parametrize(
    "body",
    [
        {"scenario_ids": []},
        {"scenario_ids": [f"s{number}" for number in range(51)]},
        {"scenario_ids": ["s1", "s1"]},
        {"scenario_ids": ["x" * 65]},
        {"scenario_ids": "every"},
        {"scenario_ids": ["s1"], "replace_acepted": True},
    ],
)
def test_review_bodies_are_checked(
    client: TestClient, api_key: str, service: ReviewService, body: Any
) -> None:
    """S38: 1-50 ids, each once, bounded; "all" only; an unknown (misspelt) field refused, never ignored."""
    assert _post(client, api_key, f"/v1/sessions/{_run()}/accept", body).status_code == 422


def test_why_no_path_is_left_to_write() -> None:
    """S38: the next-set refusal names its reason (abandoned paths first, then the scenario count)."""
    written = {"selected": True, "served": "s", "abandoned": False}
    left_out = {"selected": False, "served": None, "abandoned": False}
    abandoned = {"selected": True, "served": None, "abandoned": True}
    assert why_no_path_left([written]) == ConflictReason.NOTHING_LEFT
    assert why_no_path_left([written, left_out]) == ConflictReason.TARGET_REACHED
    assert why_no_path_left([written, left_out, abandoned]) == ConflictReason.SCENARIOS_ABANDONED


def test_a_store_failure_after_the_decision_never_loses_its_audit_and_a_repeat_heals_the_counts(
    service: ReviewService, monkeypatch: pytest.MonkeyPatch
) -> None:
    """G143: the decision is saved, then the counts write fails (the caller gets 503): the audit record was
    written first; the caller's retry changes no decision, records nothing more and refreshes the counts."""
    from pymongo.errors import AutoReconnect

    record_id = _run()
    target = _scenario(record_id, "p1")
    run = session_status_from_record(get_mongodb()[Collection.SESSIONS].find_one({"_id": record_id}))
    refresh, calls = scenarios.update_scenario_session_counts, []

    def fails_once(session_id: str) -> dict[str, int]:
        calls.append(session_id)
        if len(calls) == 1:
            raise AutoReconnect("MongoDB went away")
        return refresh(session_id)

    monkeypatch.setattr(scenarios, "update_scenario_session_counts", fails_once)
    principal = Principal("client", "u1", 86, "DESC")
    with pytest.raises(AutoReconnect):
        service.accept(principal, run, AcceptRequest(scenario_ids=[target]))
    assert len(_audits(record_id, AuditAction.SCENARIOS_ACCEPTED)) == 1
    assert service.accept(principal, run, AcceptRequest(scenario_ids=[target])).accepted == [target]
    assert len(_audits(record_id, AuditAction.SCENARIOS_ACCEPTED)) == 1
    assert get_mongodb()[Collection.SESSIONS].find_one({"_id": record_id})["counts"]["accepted"] == 1


def test_one_refused_id_never_leaves_the_others_untried() -> None:
    """G144: the one-accepted-version index refuses one target; every other id is still decided (an
    update_many stops at the first refusal)."""
    record_id = _run()
    refused = _scenario(record_id, "p1")
    _scenario(record_id, "p1", decision=Decision.ACCEPTED, version=2)
    others = [_scenario(record_id, f"p{number}") for number in range(2, 6)]
    stamp = decided_stamp(Principal("client", "u1", 86, "DESC"), datetime.now(UTC), uuid.uuid4().hex)
    ids = [refused, *others]
    changed = scenarios.update_scenario_decisions(ids, Decision.PENDING, Decision.ACCEPTED, stamp)
    assert changed == 4
    assert [_decision(scenario_id) for scenario_id in others] == [Decision.ACCEPTED] * 4
    assert _decision(refused) == Decision.PENDING


def test_two_identical_clicks_at_once_audit_and_count_once(
    service: ReviewService, monkeypatch: pytest.MonkeyPatch
) -> None:
    """G145: both clicks answer accepted; only the one whose write changed it records it."""
    record_id = _run()
    target = _scenario(record_id, "p1")
    run = session_status_from_record(get_mongodb()[Collection.SESSIONS].find_one({"_id": record_id}))
    principal = Principal("client", "u1", 86, "DESC")
    one, two = _at_the_same_moment(
        monkeypatch,
        [
            lambda: service.accept(principal, run, AcceptRequest(scenario_ids=[target])),
            lambda: service.accept(principal, run, AcceptRequest(scenario_ids=[target])),
        ],
    )
    assert one.accepted == two.accepted == [target]
    assert len(_audits(record_id, AuditAction.SCENARIOS_ACCEPTED)) == 1


def test_an_accepted_scenario_stays_listed_after_its_threat_is_retired(
    client: TestClient, api_key: str, service: ReviewService
) -> None:
    """G146: a repeat (by id or "all") lists an accepted scenario again even after a curator retired its
    library threat; only a pending one is refused library_inactive."""
    record_id = _run()
    retired = {"content": {"threat": {"library_id": 99}}}
    accepted = _scenario(record_id, "p1", decision=Decision.ACCEPTED, **retired)
    url = f"/v1/sessions/{record_id}/accept"
    assert _post(client, api_key, url, {"scenario_ids": [accepted]}).json()["accepted"] == [accepted]
    answer = _post(client, api_key, url, {"scenario_ids": "all"}).json()
    assert answer["accepted"] == [accepted] and answer["skipped"] == []
