"""The import schedule an admin saves: the next run (daily, weekly, across a daylight-saving change), the
default written once, the claim only one check wins (real MongoDB, threads), the two routes, and beat's
check, which imports only when the schedule is due."""

import itertools
import json
import os
import subprocess
import sys
import threading
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from kombu.exceptions import OperationalError as BrokerUnavailable
from structlog.testing import capture_logs

from app.core.config import get_settings
from app.core.constants import Collection, IntelDocId, IntelLimits, IntelSchedule, IntelSource, LogEvent, TaskName
from app.core.database import get_mongodb
from app.crud.intel import IntelScheduleRepository, get_intel_schedule_repository
from app.domain.intel import refresh as intel_refresh
from app.domain.intel import schedule
from app.domain.intel.schedule import claim_due_run, find_next_run, read_schedule, retry_claimed_run, save_schedule
from app.schemas.intel import IntelScheduleBody
from app.schemas.intel_records import RefreshResult, RefreshSummary, SourceRefresh
from app.worker import intel as worker_intel
from app.worker.celery_app import celery_app
from app.worker.intel import refresh_external_intelligence
from tests.checkout import REPO
from tests.external_intelligence.conftest import Intel

URL = "/v1/tsg/intel/schedule"
NOW = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)  # a Tuesday
NEXT_SUNDAY = datetime(2026, 11, 22, 2, 0, tzinfo=UTC)
DAILY = {"enabled": True, "frequency": "daily", "time": "02:00", "timezone": "UTC"}
WEEKLY = {"enabled": True, "frequency": "weekly", "day_of_week": 6, "time": "02:00", "timezone": "UTC"}


def _at(text: str) -> datetime:
    return datetime.fromisoformat(text).replace(tzinfo=UTC)


def _stored() -> dict[str, Any] | None:
    return get_mongodb()[Collection.EXTERNAL_FEED_STATUS].find_one({"_id": IntelDocId.SCHEDULE})


def _store(**values: Any) -> None:
    """A schedule document as an admin saved it, with `values` over a weekly Sunday 02:00 UTC."""
    document = WEEKLY | {"next_run_at": NEXT_SUNDAY, "last_run_at": None, "updated_at": NOW} | values
    get_mongodb()[Collection.EXTERNAL_FEED_STATUS].replace_one({"_id": IntelDocId.SCHEDULE}, document, upsert=True)


@pytest.fixture
def schedule_on(monkeypatch: pytest.MonkeyPatch) -> None:
    """The master switch on, no schedule saved, and the schedule's and the worker's clock fixed at NOW."""
    monkeypatch.setattr(get_settings(), "external_intelligence_enabled", True)
    monkeypatch.setattr(schedule, "utc_now", lambda: NOW)
    monkeypatch.setattr(worker_intel, "utc_now", lambda: NOW)
    get_mongodb()[Collection.EXTERNAL_FEED_STATUS].delete_one({"_id": IntelDocId.SCHEDULE})


@pytest.mark.parametrize(
    ("values", "after", "expected"),
    [
        (DAILY, "2026-11-17T01:59:59", "2026-11-17T02:00:00"),
        (DAILY, "2026-11-17T02:00:00", "2026-11-18T02:00:00"),  # strictly after: never the instant it is asked at
        (DAILY | {"time": "23:30", "timezone": "Asia/Dubai"}, "2026-11-17T12:00:00", "2026-11-17T19:30:00"),
        (WEEKLY, "2026-11-17T12:00:00", "2026-11-22T02:00:00"),
        (WEEKLY, "2026-11-22T01:00:00", "2026-11-22T02:00:00"),  # its own day, before the time
        (WEEKLY, "2026-11-22T02:00:00", "2026-11-29T02:00:00"),
        # Sunday 02:00 in Dubai is Saturday 22:00 UTC: the weekday is the zone's, not UTC's
        (WEEKLY | {"timezone": "Asia/Dubai"}, "2026-11-17T12:00:00", "2026-11-21T22:00:00"),
        (WEEKLY | {"day_of_week": 0}, "2026-11-17T12:00:00", "2026-11-23T02:00:00"),
    ],
)
def test_the_next_run_is_the_first_local_time_strictly_after(values: dict, after: str, expected: str) -> None:
    """Mutation: `>=` for `>` in find_next_run, or the weekday taken from the UTC date."""
    assert find_next_run(values, _at(after)) == _at(expected)


@pytest.mark.parametrize(
    ("values", "after", "expected"),
    [
        # London, clocks forward 29 March 2026: 09:00 stays 09:00 local, so it moves an hour earlier in UTC
        (DAILY | {"time": "09:00", "timezone": "Europe/London"}, "2026-03-28T08:00:00", "2026-03-28T09:00:00"),
        (DAILY | {"time": "09:00", "timezone": "Europe/London"}, "2026-03-28T09:00:00", "2026-03-29T08:00:00"),
        # and back on 25 October 2026
        (DAILY | {"time": "09:00", "timezone": "Europe/London"}, "2026-10-24T08:00:00", "2026-10-25T09:00:00"),
        # New York, weekly on Sunday 02:30: on 8 March 2026 that time is skipped, so it runs at 03:30 local
        (WEEKLY | {"time": "02:30", "timezone": "America/New_York"}, "2026-03-02T00:00:00", "2026-03-08T07:30:00"),
        (WEEKLY | {"time": "02:30", "timezone": "America/New_York"}, "2026-03-08T07:30:00", "2026-03-15T06:30:00"),
        # 01:30 comes twice on 1 November 2026: the first pass only
        (DAILY | {"time": "01:30", "timezone": "America/New_York"}, "2026-11-01T00:00:00", "2026-11-01T05:30:00"),
        (DAILY | {"time": "01:30", "timezone": "America/New_York"}, "2026-11-01T05:30:00", "2026-11-02T06:30:00"),
    ],
)
def test_a_daylight_saving_change_keeps_the_local_time(values: dict, after: str, expected: str) -> None:
    """Mutation: a fixed UTC offset for the zone, or 24 h added instead of one calendar day."""
    assert find_next_run(values, _at(after)) == _at(expected)


def test_the_next_run_is_counted_from_the_day_in_the_schedules_zone() -> None:
    """New York is still on Monday the 16th when UTC is on the 17th: that evening's 23:00 is the next run.
    Mutation: take the day from the UTC date and that evening's run is skipped (a day late, or a week)."""
    evening = {"time": "23:00", "timezone": "America/New_York"}
    after = _at("2026-11-17T02:00:00")  # 21:00 on the 16th in New York
    assert find_next_run(DAILY | evening, after) == _at("2026-11-17T04:00:00")
    assert find_next_run(WEEKLY | evening | {"day_of_week": 0}, after) == _at("2026-11-17T04:00:00")


@pytest.mark.usefixtures("schedule_on")
def test_a_database_with_no_schedule_gets_the_default_once_due_at_once() -> None:
    """A new or upgraded system holds no ATT&CK graph: with its first run at the default slot it waited up to a
    week for one. Mutation: store find_next_run(default) as the first run and the first check claims nothing."""
    first = read_schedule()
    assert first == WEEKLY | {"next_run_at": NOW, "last_run_at": None, "updated_at": None}
    repository = get_intel_schedule_repository()
    kept = repository.create_missing_schedule(DAILY | {"next_run_at": None})  # $setOnInsert: the saved one stays
    assert kept == first == read_schedule() and _stored()["frequency"] == "weekly"
    assert claim_due_run(NOW) is True  # beat's first check imports once
    assert (_stored()["next_run_at"], _stored()["last_run_at"]) == (NEXT_SUNDAY, NOW)  # then the weekly slot
    assert claim_due_run(NOW + timedelta(minutes=1)) is False


@pytest.mark.usefixtures("schedule_on")
def test_a_due_run_is_claimed_once_and_moves_to_the_next_slot() -> None:
    _store()
    assert claim_due_run(NEXT_SUNDAY - timedelta(seconds=1)) is False and _stored()["last_run_at"] is None
    with capture_logs() as logs:
        assert claim_due_run(NEXT_SUNDAY) is True
    stored = _stored()
    assert (stored["next_run_at"], stored["last_run_at"]) == (NEXT_SUNDAY + timedelta(days=7), NEXT_SUNDAY)
    claimed = next(line for line in logs if line["event"] == LogEvent.EXTERNAL_INTELLIGENCE_SCHEDULE_CLAIMED)
    # As text: the log file writes a datetime as Python code, "datetime.datetime(2026, ...)" (live run, 17 Nov).
    assert claimed["planned_at"] == NEXT_SUNDAY.isoformat()
    assert claimed["next_run_at"] == stored["next_run_at"].replace(tzinfo=UTC).isoformat()
    assert stored["updated_at"] == NOW  # the admin's own time: a claim is no edit
    assert claim_due_run(NEXT_SUNDAY + timedelta(minutes=1)) is False


@pytest.mark.usefixtures("schedule_on")
def test_a_disabled_schedule_is_never_due() -> None:
    saved = save_schedule(IntelScheduleBody(**WEEKLY | {"enabled": False}), "op-1")
    assert saved["enabled"] is False and saved["next_run_at"] is None
    before = _stored()
    assert claim_due_run(NOW + timedelta(days=365)) is False and _stored() == before


@pytest.mark.usefixtures("schedule_on")
def test_a_missed_slot_runs_once_and_is_not_replayed() -> None:
    """Beat was down for three weeks: one import at the next check, then the next slot from now."""
    _store(next_run_at=NEXT_SUNDAY)
    late = NEXT_SUNDAY + timedelta(days=23, hours=5)
    assert claim_due_run(late) is True
    stored = _stored()
    assert stored["last_run_at"] == late and stored["next_run_at"] == find_next_run(WEEKLY, late) > late
    assert claim_due_run(late + timedelta(minutes=1)) is False


@pytest.mark.usefixtures("schedule_on")
def test_an_enabled_schedule_without_a_next_run_is_given_one_and_is_not_due() -> None:
    _store(next_run_at=None)
    assert claim_due_run(NOW) is False
    stored = _stored()
    assert (stored["next_run_at"], stored["last_run_at"]) == (NEXT_SUNDAY, None)
    assert claim_due_run(NEXT_SUNDAY) is True


@pytest.mark.usefixtures("schedule_on")
def test_of_two_checks_at_once_only_one_claims_the_run(monkeypatch: pytest.MonkeyPatch) -> None:
    """Two beat ticks or pods, each at its own instant: every check has read the same document before any
    writes. Mutation: drop next_run_at from the claim's filter and each one wins."""
    _store()
    checks = 6
    repository, all_have_read = get_intel_schedule_repository(), threading.Barrier(checks)
    write = repository.update_unchanged_schedule

    def write_together(seen: dict[str, Any], changes: dict[str, Any]) -> bool:
        all_have_read.wait(10)
        return write(seen, changes)

    monkeypatch.setattr(repository, "update_unchanged_schedule", write_together)
    won: list[bool] = []
    instants = [NEXT_SUNDAY + timedelta(seconds=late) for late in range(checks)]
    threads = [threading.Thread(target=lambda at=at: won.append(claim_due_run(at))) for at in instants]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(20)
    assert sorted(won) == [False] * (checks - 1) + [True]
    assert _stored()["next_run_at"] == NEXT_SUNDAY + timedelta(days=7)


@pytest.mark.usefixtures("schedule_on")
@pytest.mark.parametrize("edit", [{"time": "03:00"}, {"timezone": "Asia/Dubai"}, {"enabled": False}, DAILY])
def test_an_admins_edit_between_the_read_and_the_claim_makes_the_claim_lose(
    monkeypatch: pytest.MonkeyPatch, edit: dict[str, Any]
) -> None:
    """Mutation: claim on _id alone and the admin's new next run is overwritten by the old schedule's."""
    _store(next_run_at=NOW - timedelta(minutes=5))
    repository = get_intel_schedule_repository()
    write = repository.update_unchanged_schedule

    def edited_first(seen: dict[str, Any], changes: dict[str, Any]) -> bool:
        save_schedule(IntelScheduleBody(**WEEKLY | edit), "op-2")
        return write(seen, changes)

    monkeypatch.setattr(repository, "update_unchanged_schedule", edited_first)
    assert claim_due_run(NOW) is False
    stored, wanted = _stored(), IntelScheduleBody(**WEEKLY | edit).model_dump(mode="json")
    assert {name: stored[name] for name in wanted} == wanted and stored["last_run_at"] is None
    assert stored["next_run_at"] == (find_next_run(wanted, NOW) if wanted["enabled"] else None)


@pytest.mark.usefixtures("schedule_on")
def test_a_schedule_disabled_between_the_read_and_the_claim_is_given_no_next_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An enabled schedule without a next run is only given one: both hold no next run, so `enabled` decides.
    Mutation: claim on next_run_at alone and the schedule the admin just disabled shows a next run."""
    _store(next_run_at=None)
    repository = get_intel_schedule_repository()
    write = repository.update_unchanged_schedule

    def disabled_first(seen: dict[str, Any], changes: dict[str, Any]) -> bool:
        save_schedule(IntelScheduleBody(**WEEKLY | {"enabled": False}), "op-2")
        return write(seen, changes)

    monkeypatch.setattr(repository, "update_unchanged_schedule", disabled_first)
    assert claim_due_run(NOW) is False
    assert (_stored()["enabled"], _stored()["next_run_at"]) == (False, None)


class _CountedCalls:
    """A pymongo collection that keeps the name and arguments of each call made on it."""

    def __init__(self, collection: Any) -> None:
        self._collection, self.calls = collection, []

    def __getattr__(self, name: str) -> Any:
        def call(*args: Any, **kwargs: Any) -> Any:
            self.calls.append((name, args, kwargs))
            return getattr(self._collection, name)(*args, **kwargs)

        return call


@pytest.mark.usefixtures("schedule_on")
def test_a_check_that_is_not_due_costs_one_small_read_and_no_write(monkeypatch: pytest.MonkeyPatch) -> None:
    _store()
    counted = _CountedCalls(get_mongodb()[Collection.EXTERNAL_FEED_STATUS])
    monkeypatch.setattr(schedule, "get_intel_schedule_repository", lambda: IntelScheduleRepository(counted))
    assert claim_due_run(NOW) is False
    ((name, (where, fields), _),) = counted.calls
    assert (name, where) == ("find_one", {"_id": IntelDocId.SCHEDULE})
    assert fields["_id"] == 0 and {"enabled", "next_run_at", "timezone"} < set(fields)  # never the whole document


@pytest.fixture
def api(client: TestClient, schedule_on: None) -> TestClient:
    return client


def _audit() -> list[dict[str, Any]]:
    return list(get_mongodb()[Collection.AUDIT].find({"action": "external_intelligence.schedule_changed"}))


def test_the_schedule_is_read_with_no_key_and_starts_as_the_default(api: TestClient) -> None:
    shown = api.get(URL)
    assert shown.status_code == 200
    assert shown.json() == WEEKLY | {"next_run_at": "2026-11-17T12:00:00Z", "last_run_at": None, "updated_at": None}


def test_a_saved_schedule_is_stored_with_its_next_run_and_audited(api: TestClient) -> None:
    api.get(URL)  # the default is in force before the change
    body = {"enabled": True, "frequency": "weekly", "day_of_week": 2, "time": "01:30", "timezone": "Asia/Dubai"}
    audited = len(_audit())
    saved = api.put(URL, json=body, headers={"X-User-Id": "op-7"})
    assert saved.status_code == 200
    # Wednesday 01:30 in Dubai is Tuesday 21:30 UTC
    assert saved.json() == body | {
        "next_run_at": "2026-11-17T21:30:00Z",
        "last_run_at": None,
        "updated_at": "2026-11-17T12:00:00Z",
    }
    assert api.get(URL).json() == saved.json() and _stored()["updated_by"] == "op-7"
    rows = _audit()
    assert len(rows) == audited + 1
    row = rows[-1]
    assert (row["actor"], row["target"]) == (
        {"admin": True, "user_id": "op-7"},
        {"type": "external_intelligence_source", "id": "schedule"},
    )
    assert (row["before"], row["after"]) == (WEEKLY, body)


def test_a_second_change_is_audited_with_the_schedule_it_replaced(api: TestClient) -> None:
    """Mutation: audit the default as "before" and the record loses what the admin had saved."""
    first = DAILY | {"day_of_week": None, "time": "04:15"}
    assert api.put(URL, json=first).status_code == 200
    assert api.put(URL, json=WEEKLY | {"day_of_week": 1}).status_code == 200
    row = _audit()[-1]
    assert (row["before"], row["after"]) == (first, WEEKLY | {"day_of_week": 1})


def test_a_daily_schedule_keeps_no_day_and_a_disabled_one_no_next_run(api: TestClient) -> None:
    daily = api.put(URL, json=DAILY | {"day_of_week": 3}).json()
    assert (daily["day_of_week"], daily["next_run_at"]) == (None, "2026-11-18T02:00:00Z")
    _store(last_run_at=NOW - timedelta(days=1))
    off = api.put(URL, json=DAILY | {"enabled": False}).json()
    assert (off["enabled"], off["next_run_at"]) == (False, None)
    assert off["last_run_at"] == "2026-11-16T12:00:00Z"  # an edit keeps the last run


@pytest.mark.parametrize(
    "body",
    [
        WEEKLY | {"timezone": "Mars/Olympus"},
        WEEKLY | {"timezone": ""},
        WEEKLY | {"time": "24:00"},
        WEEKLY | {"time": "2:00"},
        WEEKLY | {"time": "02:60"},
        WEEKLY | {"time": "0\u0662:00"},  # an Arabic-Indic 2: a digit to the body's pattern, no time to Python
        WEEKLY | {"time": "1\uff19:30", "enabled": False},  # a full-width 9: was stored unseen while disabled
        {key: value for key, value in WEEKLY.items() if key != "day_of_week"},  # weekly without its day
        WEEKLY | {"day_of_week": 7},
        WEEKLY | {"frequency": "hourly"},
        WEEKLY | {"enabled": "yes"},
        WEEKLY | {"next_run_at": "2026-11-18T00:00:00Z"},  # an unknown field
        {},
    ],
)
def test_a_schedule_that_cannot_run_is_refused_and_nothing_is_saved(api: TestClient, body: dict[str, Any]) -> None:
    audited = len(_audit())
    assert api.put(URL, json=body).status_code == 422
    assert _stored() is None and len(_audit()) == audited


@pytest.mark.parametrize("time", ["02:00:00", "02:000", " 02:00", "at 02:00"])
def test_a_time_with_anything_around_its_hour_and_minute_is_refused(api: TestClient, time: str) -> None:
    """Mutation: a pattern that only has to be found in the text and "02:00:00" is stored: no next run can be
    counted from it."""
    assert api.put(URL, json=WEEKLY | {"time": time}).status_code == 422
    assert _stored() is None


def test_with_the_master_switch_off_the_schedule_reads_as_the_default_and_nothing_is_written(
    client: TestClient,
) -> None:
    """Off equals the original: no intelligence collection appears (the suite runs off)."""
    database = get_mongodb()
    database.drop_collection(Collection.EXTERNAL_FEED_STATUS)
    shown = client.get(URL)
    assert shown.status_code == 200
    assert shown.json() == WEEKLY | {"next_run_at": None, "last_run_at": None, "updated_at": None}
    assert client.put(URL, json=WEEKLY).status_code == 409
    assert Collection.EXTERNAL_FEED_STATUS not in database.list_collection_names()


@pytest.fixture
def linking_sent(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """The names of the tasks the worker sent."""
    sent: list[str] = []
    monkeypatch.setattr(celery_app, "send_task", lambda name, **_message: sent.append(name))
    return sent


def test_beats_first_check_on_a_database_with_no_schedule_imports_on_a_clock_that_moves(
    intel: Intel, schedule_on: None, linking_sent: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The default's first run was a second clock read, later than the check's own: on a real clock the first
    check found it not due yet and the first import waited one more minute (a fixed test clock hid it).
    Mutation: read the clock again for the default's first run and this check imports nothing."""
    ticks = itertools.count()

    def moving_clock() -> datetime:
        return NOW + timedelta(milliseconds=next(ticks))

    monkeypatch.setattr(schedule, "utc_now", moving_clock)
    monkeypatch.setattr(worker_intel, "utc_now", moving_clock)
    refresh_external_intelligence()
    assert intel.refresher.calls == [("due", None)] and linking_sent == [TaskName.LINK_MITIGATIONS]
    assert (_stored()["next_run_at"], _stored()["last_run_at"]) == (NEXT_SUNDAY, NOW)  # the check's own instant


def test_beats_check_imports_nothing_until_the_schedule_is_due_then_once(
    intel: Intel, schedule_on: None, linking_sent: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The linking follows every import, a changed graph or not: sent only for a new graph, one linking that
    failed, found the lock held or was lost was never tried again until MITRE's next release."""
    _store(next_run_at=NOW + timedelta(minutes=1))
    refresh_external_intelligence()
    assert intel.refresher.calls == [] and _stored()["last_run_at"] is None and linking_sent == []
    monkeypatch.setattr(worker_intel, "utc_now", lambda: NOW + timedelta(minutes=1))
    refresh_external_intelligence()
    refresh_external_intelligence()  # the next check, and any second pod's
    assert intel.refresher.calls == [("due", None)] and linking_sent == [TaskName.LINK_MITIGATIONS]
    assert _stored()["next_run_at"] == NEXT_SUNDAY


def test_an_import_stands_when_its_linking_cannot_be_queued(
    intel: Intel, schedule_on: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broker_down(name: str, **_message: Any) -> None:
        raise BrokerUnavailable("the broker is unreachable")

    monkeypatch.setattr(celery_app, "send_task", broker_down)
    _store(next_run_at=NOW - timedelta(hours=1))
    with capture_logs() as logs:
        refresh_external_intelligence()
    assert intel.refresher.calls == [("due", None)]
    assert LogEvent.CONTROL_LINKS_NOT_QUEUED in [line["event"] for line in logs]


def _failing() -> RefreshSummary:
    failed = SourceRefresh(IntelSource.ATTACK_ICS, RefreshResult.FAILED, error="The source did not answer.")
    return RefreshSummary((failed,), True)


def test_a_scheduled_import_that_failed_is_due_again_within_the_hour_until_it_succeeds(
    intel: Intel, schedule_on: None, linking_sent: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The claim moves the next run a week on before the import: a source MITRE did not answer waited a week.
    Mutation: drop the retry and next_run_at stays at next Sunday after the failure."""
    _store(next_run_at=NOW - timedelta(minutes=1))
    outcomes = iter([_failing(), _failing(), RefreshSummary((), True)])
    monkeypatch.setattr(intel_refresh, "refresh_all_sources", lambda now, keep_going=None: next(outcomes))
    retry = timedelta(seconds=IntelSchedule.RETRY_SECONDS)
    refresh_external_intelligence()
    assert (_stored()["next_run_at"], _stored()["last_run_at"]) == (NOW + retry, NOW)
    refresh_external_intelligence()  # not due again yet: no outcome is read
    monkeypatch.setattr(worker_intel, "utc_now", lambda: NOW + retry)
    refresh_external_intelligence()  # fails again: one more hour
    assert _stored()["next_run_at"] == NOW + 2 * retry
    monkeypatch.setattr(worker_intel, "utc_now", lambda: NOW + 2 * retry)
    refresh_external_intelligence()  # succeeds: back on its slot
    assert (_stored()["next_run_at"], _stored()["last_run_at"]) == (NEXT_SUNDAY, NOW + 2 * retry)
    assert next(outcomes, None) is None and len(linking_sent) == 3


def test_a_scheduled_import_that_broke_is_due_again_within_the_hour(
    intel: Intel, schedule_on: None, linking_sent: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(now: datetime, keep_going: Any = None) -> RefreshSummary:
        raise RuntimeError("MongoDB went away")

    _store(next_run_at=NOW - timedelta(minutes=1))
    monkeypatch.setattr(intel_refresh, "refresh_all_sources", broken)
    with pytest.raises(RuntimeError):
        refresh_external_intelligence()
    assert _stored()["next_run_at"] == NOW + timedelta(seconds=IntelSchedule.RETRY_SECONDS)
    assert linking_sent == []  # nothing was imported


def test_a_retry_never_passes_the_next_slot_and_never_undoes_an_admins_edit(
    schedule_on: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Mutation: drop either guard and a failed import moves a nearer slot later, or overwrites the schedule an
    admin saved while it ran."""
    _store(**DAILY | {"time": "12:30"}, day_of_week=None, next_run_at=NOW - timedelta(hours=1))
    assert claim_due_run(NOW) is True
    retry_claimed_run(NOW)
    assert _stored()["next_run_at"] == NOW + timedelta(minutes=30)  # its own slot comes first
    _store(next_run_at=NOW - timedelta(hours=1))
    assert claim_due_run(NOW) is True
    monkeypatch.setattr(schedule, "utc_now", lambda: NOW + timedelta(minutes=5))  # while the import runs
    for edit in ({"day_of_week": 2}, {"enabled": False}):
        edited = save_schedule(IntelScheduleBody(**WEEKLY | edit), "op-2")
        retry_claimed_run(NOW)
        assert _stored()["next_run_at"] == edited["next_run_at"]
    assert _stored()["next_run_at"] is None  # disabled: nothing is due


@pytest.mark.usefixtures("schedule_on")
def test_a_failed_import_is_due_again_one_hour_after_its_claim() -> None:
    """Mutation: another IntelSchedule.RETRY_SECONDS and a failed import waits longer than the hour."""
    _store(next_run_at=NOW - timedelta(minutes=1))
    assert claim_due_run(NOW) is True
    retry_claimed_run(NOW)
    assert _stored()["next_run_at"] == NOW + timedelta(hours=1)


@pytest.mark.usefixtures("schedule_on")
def test_a_retry_gives_a_disabled_schedule_no_next_run() -> None:
    """Mutation: retry when the schedule holds no next run and a schedule disabled earlier is due in an hour."""
    _store(enabled=False, next_run_at=None, updated_at=NOW - timedelta(days=1))
    retry_claimed_run(NOW)
    assert _stored()["next_run_at"] is None


def test_beats_check_asks_no_schedule_while_the_switch_is_off(
    intel: Intel, schedule_on: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    _store(next_run_at=NOW - timedelta(hours=1))
    intel.switch.enabled = False
    monkeypatch.setattr(schedule, "get_intel_schedule_repository", lambda: 1 / 0)
    refresh_external_intelligence()
    assert intel.refresher.calls == [] and _stored()["last_run_at"] is None  # still due once it is back on


def test_beat_checks_every_minute_only_while_external_intelligence_is_on() -> None:
    """The beat schedule is built at import, so a second interpreter reads it with the master switch on."""
    show = (
        "import json; from app.worker.celery_app import celery_app; "
        f"print(json.dumps(celery_app.conf.beat_schedule.get('{TaskName.REFRESH_EXTERNAL_INTELLIGENCE.value}')))"
    )
    env = os.environ | {"EXTERNAL_INTELLIGENCE_ENABLED": "true"}
    ran = subprocess.run(  # noqa: S603 - this interpreter, a fixed command
        [sys.executable, "-c", show], cwd=REPO, env=env, check=True, timeout=120, capture_output=True, text=True
    )
    entry = json.loads(ran.stdout.strip().splitlines()[-1])
    assert IntelLimits.CHECK_EVERY_SECONDS == 60
    # Three intervals to expire: Celery judges expiry on the worker pod's own clock, and UAT pods were 76 s
    # apart; with one interval every check arrived expired and the schedule never started an import.
    assert entry == {"task": TaskName.REFRESH_EXTERNAL_INTELLIGENCE, "schedule": 60, "options": {"expires": 180}}
    assert TaskName.REFRESH_EXTERNAL_INTELLIGENCE not in celery_app.conf.beat_schedule  # this suite runs off
