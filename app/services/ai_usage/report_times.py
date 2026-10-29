"""The times of the AI usage reports: time zones, ranges, whole hours and page cursors, each checked so a bad
one answers 422, never 500."""

import base64
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from bson.errors import InvalidId

from app.core.constants import AiUsageMessage
from app.core.exceptions import Invalid
from app.models.ai_usage.usage_report import reportable_time

HOUR = timedelta(hours=1)


def time_zone(tz: str) -> ZoneInfo:
    """The zone named `tz`; 422 for a name that is none."""
    try:
        return ZoneInfo(tz)
    except (ZoneInfoNotFoundError, ValueError, OSError) as exc:  # OSError: a folder's name ("America")
        raise Invalid(AiUsageMessage.TZ_UNKNOWN.format(tz=tz)) from exc


def check_whole_hours(tz: str, zone: ZoneInfo, since: datetime, until: datetime) -> None:
    """Totals are kept per UTC hour: a time zone whose offset is a part hour anywhere in the range would split
    them (Lord Howe is whole hours in summer, a half hour off in winter)."""
    moment = since
    while moment <= until:  # ponytail: every hour (at most 8,784, ~10 ms); an offset lasts hours at least
        offset = moment.astimezone(zone).utcoffset() or timedelta()
        if offset.total_seconds() % 3600:
            raise Invalid(AiUsageMessage.TZ_NOT_WHOLE_HOURS.format(tz=tz))
        moment += HOUR


def check_span(since: datetime, until: datetime, max_days: int, too_long: str) -> None:
    """422 for an empty range or one over `max_days`."""
    if since >= until:
        raise Invalid(AiUsageMessage.SPAN_EMPTY)
    if until - since > timedelta(days=max_days):
        raise Invalid(too_long.format(days=(until - since).days, max_days=max_days))


def as_utc(moment: datetime) -> datetime:
    """A query's time in UTC; one with no offset is read as UTC."""
    return moment.replace(tzinfo=UTC) if moment.tzinfo is None else moment.astimezone(UTC)


def floor_hour(moment: datetime) -> datetime:
    return moment.replace(minute=0, second=0, microsecond=0)


def ceil_hour(moment: datetime) -> datetime:
    floor = floor_hour(moment)
    return floor if floor == moment else floor + HOUR


def page_cursor(at: datetime, last_id: str) -> str:
    """A page's `next`: the last entry's time and id, as opaque text."""
    return base64.urlsafe_b64encode(json.dumps([at.isoformat(), last_id]).encode()).decode()


def read_cursor[Id](cursor: str | None, id_type: Callable[[str], Id]) -> tuple[datetime, Id] | None:
    """A page's `after`, checked like a report's times (a year MongoDB cannot hold would fail the read)."""
    if cursor is None:
        return None
    try:
        at, last_id = json.loads(base64.urlsafe_b64decode(cursor.encode()))
        return reportable_time(datetime.fromisoformat(at)), id_type(last_id)
    except (ValueError, TypeError, InvalidId) as exc:
        raise Invalid(AiUsageMessage.BAD_CURSOR) from exc
