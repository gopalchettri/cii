"""The import schedule an admin saves: beat asks every minute, MongoDB decides which check starts the import."""

from collections.abc import Mapping
from datetime import UTC, datetime, time, timedelta
from typing import Any
from zoneinfo import ZoneInfo

import structlog

from app.core.clock import utc_now
from app.core.constants import AuditAction, AuditTarget, IntelDocId, IntelSchedule, LogEvent, ScheduleFrequency
from app.crud.audit import get_audit_repository
from app.crud.intel import get_intel_schedule_repository
from app.domain.shared.audit import admin_actor, audit_target
from app.schemas.intel import IntelScheduleBody

log = structlog.get_logger(__name__)
#: What an admin sets, with the values a database holding no schedule starts from.
_DEFAULT: dict[str, Any] = {
    "enabled": IntelSchedule.DEFAULT_ENABLED,
    "frequency": IntelSchedule.DEFAULT_FREQUENCY.value,
    "day_of_week": IntelSchedule.DEFAULT_DAY_OF_WEEK,
    "time": IntelSchedule.DEFAULT_TIME,
    "timezone": IntelSchedule.DEFAULT_TIMEZONE,
}


def find_next_run(schedule: Mapping[str, Any], after: datetime) -> datetime:
    """The first instant strictly after `after` at the schedule's local time (on its weekday when weekly)."""
    zone = ZoneInfo(schedule["timezone"])
    day, step = after.astimezone(zone).date(), timedelta(days=1)
    if schedule["frequency"] == ScheduleFrequency.WEEKLY:
        day += timedelta(days=(schedule["day_of_week"] - day.weekday()) % 7)
        step = timedelta(days=7)
    # Calendar days in the zone, so a daylight-saving change keeps the local time; a local time the change
    # skips runs an hour later that day, one it repeats runs at its first pass.
    local_time = time.fromisoformat(schedule["time"])
    first, second = (datetime.combine(on, local_time, zone).astimezone(UTC) for on in (day, day + step))
    return first if first > after else second


def read_schedule(now: datetime | None = None) -> dict[str, Any]:
    """The saved schedule; a database holding none stores the default one, due at `now` (the switch off too)."""
    never_run = _DEFAULT | {"next_run_at": None, "last_run_at": None, "updated_at": None}
    repository = get_intel_schedule_repository()
    # Due at the check that creates it (its own `now`, not a later clock read): a new or upgraded system imports
    # at beat's first check, not up to a week later at its slot.
    saved = repository.get_schedule()
    return saved or repository.create_missing_schedule(never_run | {"next_run_at": now or utc_now()})


def save_schedule(body: IntelScheduleBody, actor: str) -> dict[str, Any]:
    """Store the admin's schedule with its next run (none while disabled), audited; the switch off too."""
    before, now = read_schedule(), utc_now()
    chosen = body.model_dump(mode="json")
    next_run_at = find_next_run(chosen, now) if body.enabled else None
    saved = get_intel_schedule_repository().save_schedule(
        chosen | {"next_run_at": next_run_at, "updated_at": now, "updated_by": actor}
    )
    get_audit_repository().create_audit_record(
        AuditAction.EXTERNAL_INTELLIGENCE_SCHEDULE_CHANGED,
        admin_actor(actor),
        audit_target(AuditTarget.EXTERNAL_INTELLIGENCE_SOURCE, IntelDocId.SCHEDULE),
        before={name: before[name] for name in _DEFAULT},
        after=chosen,
    )
    log.info(LogEvent.EXTERNAL_INTELLIGENCE_SCHEDULE_SAVED, enabled=body.enabled, changed_by=actor)
    return saved


def claim_due_run(now: datetime) -> bool:
    """True for the one check that may start the scheduled import: the run is due and this check moved it on."""
    seen = read_schedule(now)
    planned = seen["next_run_at"]
    if not seen["enabled"] or (planned is not None and planned > now):
        return False
    # One compare-and-set on what was just read: a second check or pod, or an admin's edit in between, loses.
    # A missed slot runs once: the next run is counted from now, never from the slot that passed.
    changes = {"next_run_at": find_next_run(seen, now)}
    if planned is not None:  # an enabled schedule without a next run is only given one
        changes["last_run_at"] = now
    won = get_intel_schedule_repository().update_unchanged_schedule(seen, changes)
    if not won or planned is None:
        return False
    times = {"planned_at": planned.isoformat(), "next_run_at": changes["next_run_at"].isoformat()}  # text in the log
    log.info(LogEvent.EXTERNAL_INTELLIGENCE_SCHEDULE_CLAIMED, **times)
    return True


def retry_claimed_run(now: datetime) -> None:
    """The run claimed at `now` failed: due again in IntelSchedule.RETRY_SECONDS, unless its slot comes first."""
    seen, retry_at = read_schedule(), now + timedelta(seconds=IntelSchedule.RETRY_SECONDS)
    slot, saved_at = seen["next_run_at"], seen["updated_at"]
    # A schedule an admin saved while the import ran stands as saved (a disabled one has no next run).
    if slot is not None and retry_at < slot and (saved_at is None or saved_at <= now):
        get_intel_schedule_repository().update_unchanged_schedule(seen, {"next_run_at": retry_at})
