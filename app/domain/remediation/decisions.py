"""What a decision on a remediation plan version changes (BLUEPRINT M11 R9; BUILD_PLAN S54; owner 2026-10-08:
any done version may be accepted or rejected, at most one accepted at a time). Pure: the service reads the
record, this works out the one change as plain values, and the store writes it fenced on `decision_seq`."""

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from app.core.constants import ConflictReason, Decision, RemediationMessage, Status
from app.core.exceptions import Conflict, NotFound
from app.models.remediation_reviews import DecisionChange


def version_status(read: dict[str, Any], version: dict[str, Any]) -> Status:
    """The latest version's status lives at the top of the record (R3); an older one's on its own item."""
    latest = version["version"] == read["job"]["epoch"]
    return Status(read["status"] if latest else version["status"])


def newest_done_version(read: dict[str, Any]) -> int | None:
    return max(
        (item["version"] for item in read["versions"] if version_status(read, item) == Status.DONE),
        default=None,
    )


def decidable_version(read: dict[str, Any], asked: int | None, remediation_id: str) -> int:
    """The version to decide: the one asked for, else the newest done one; 404 when it does not exist, 409
    when it is not done (still being written, or failed)."""
    version = asked if asked is not None else newest_done_version(read)
    if version is None:
        message = RemediationMessage.NO_DONE_VERSION.format(remediation_id=remediation_id)
        raise Conflict(message, reason=ConflictReason.NOT_COMPLETE)
    item = next((item for item in read["versions"] if item["version"] == version), None)
    if item is None:
        message = RemediationMessage.VERSION_NOT_FOUND.format(remediation_id=remediation_id, version=version)
        raise NotFound(message, reason=ConflictReason.VERSION_NOT_FOUND)
    if (status := version_status(read, item)) != Status.DONE:
        message = RemediationMessage.NOT_COMPLETE.format(
            version=version, remediation_id=remediation_id, status=status
        )
        raise Conflict(message, reason=ConflictReason.NOT_COMPLETE)
    return version


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


def work_out_decision_change(  # noqa: PLR0913 — one decision, whole
    read: dict[str, Any],
    version: int,
    decision: Decision,
    decided_by: dict[str, str],
    comment: str | None,
    now: datetime,
) -> DecisionChange | None:
    """The change `decision` on `version` makes, or None when it changes nothing (a repeat: the same version
    accepted again, or rejected again). Accepting moves `accepted_version` and puts a version accepted before
    back to pending; rejecting the accepted version clears it."""
    decisions = {item["version"]: item["decision"] for item in read["versions"]}
    accepted = read.get("accepted_version")
    repeat = accepted == version if decision == Decision.ACCEPTED else decisions[version] == Decision.REJECTED
    if repeat:
        return None
    stamp = {**decided_by, "decided_at": now, "review_comment": comment}
    decisions[version] = decision
    back_to_pending = None
    if decision == Decision.ACCEPTED:
        if accepted is not None:  # one accepted version at a time
            back_to_pending = accepted
            decisions[accepted] = Decision.PENDING
        accepted = version
    elif accepted == version:
        accepted = None
    done = {item["version"] for item in read["versions"] if version_status(read, item) == Status.DONE}
    record = record_decision(accepted, decisions, done, read["job"]["epoch"])
    return DecisionChange(version, decision, stamp, back_to_pending, accepted, record)
