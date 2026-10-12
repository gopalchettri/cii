"""What a decision on a remediation plan version changes (BLUEPRINT M11 R9; BUILD_PLAN S54; owner 2026-10-08:
any done version may be accepted or rejected, at most one accepted at a time). Pure: the service reads the
record, this works out the one update, and the store applies it fenced on `decision_seq`."""

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from app.core.constants import Decision, Status

#: (the update's $set, its array filters)
DecisionUpdate = tuple[dict[str, Any], list[dict[str, Any]]]


def version_status(read: dict[str, Any], version: dict[str, Any]) -> Status:
    """The latest version's status lives at the top of the record (R3); an older one's on its own item."""
    latest = version["version"] == read["job"]["epoch"]
    return Status(read["status"] if latest else version["status"])


def newest_done_version(read: dict[str, Any]) -> int | None:
    return max(
        (item["version"] for item in read["versions"] if version_status(read, item) == Status.DONE),
        default=None,
    )


def record_decision(
    accepted_version: int | None, decisions: Mapping[int, str], done: set[int], latest: int
) -> Decision:
    """The record's decision: accepted while a version is; pending while the latest version or a done one
    waits for a decision (a version being written or failed counts as waiting: the reviewer has something
    to do); rejected once every done version and the latest are rejected."""
    if accepted_version is not None:
        return Decision.ACCEPTED
    waiting = {latest} | done
    return Decision.PENDING if any(decisions[v] == Decision.PENDING for v in waiting) else Decision.REJECTED


def decision_update(  # noqa: PLR0913 — one decision, whole
    read: dict[str, Any],
    version: int,
    decision: Decision,
    decided_by: dict[str, str],
    comment: str | None,
    now: datetime,
) -> DecisionUpdate | None:
    """The update for `decision` on `version`, or None when it changes nothing (a repeat: the same version
    accepted again, or rejected again). Accepting moves `accepted_version` and puts a version accepted before
    back to pending; rejecting the accepted version clears it."""
    decisions = {item["version"]: item["decision"] for item in read["versions"]}
    accepted = read.get("accepted_version")
    repeat = accepted == version if decision == Decision.ACCEPTED else decisions[version] == Decision.REJECTED
    if repeat:
        return None
    stamp = {**decided_by, "decided_at": now, "review_comment": comment}
    changes: dict[str, Any] = {**_stamped("v", decision, stamp), "updated_at": now}
    filters: list[dict[str, Any]] = [{"v.version": version}]
    decisions[version] = decision
    if decision == Decision.ACCEPTED:
        if accepted is not None:  # one accepted version at a time; back to pending, with no stale stamp
            changes |= _stamped("w", Decision.PENDING, dict.fromkeys(stamp))
            filters.append({"w.version": accepted})
            decisions[accepted] = Decision.PENDING
        accepted = version
    elif accepted == version:
        accepted = None
    done = {item["version"] for item in read["versions"] if version_status(read, item) == Status.DONE}
    changes["accepted_version"] = accepted
    changes["decision"] = record_decision(accepted, decisions, done, read["job"]["epoch"])
    return changes, filters


def _stamped(slot: str, decision: Decision, stamp: dict[str, Any]) -> dict[str, Any]:
    """One version's decision and who made it, when and why, as $set paths on the version `slot` filters."""
    return {
        f"versions.$[{slot}].decision": decision,
        **{f"versions.$[{slot}].{k}": v for k, v in stamp.items()},
    }
