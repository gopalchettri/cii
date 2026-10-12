"""tsg_scenarios.controls: each written scenario's control mapping and its own small lease (Step 13,
BUILD_PLAN S33; BLUEPRINT Rules S10-S11); and tsg_sessions.controls_delivery, the run's own small lease, so
one delivery maps a run at a time (G195). A plan request's top-up may map one of its scenarios meanwhile: one
conditional update claims one scenario, and every later write is fenced on the claim's task id, so a stale
worker never overwrites a newer mapping."""

from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any

from pymongo import ReturnDocument
from pymongo.database import Database

from app.core.constants import Collection, Controls, RunKind, ScenarioStatus, Status
from app.data_access.run_counts import RunCounts
from app.data_access.scenarios import MAPPED_VERSIONS

#: Controls not mapped yet that a cancel stops (G214): waiting, being mapped, or failed (the sweep would try a
#: failed one again).
STOPPABLE_CONTROLS = [Status.QUEUED, Status.RUNNING, Status.FAILED]
#: What the controls job reads of a claimed scenario.
_CLAIMED_FIELDS = {"session_id": 1, "path_id": 1, "source": 1, "content": 1, "controls.attempts": 1}


class ControlLeases:
    def __init__(self, db: Database) -> None:
        self._scenarios = db[Collection.SCENARIOS]

    def claim(self, session_id: str, task_id: str) -> dict[str, Any] | None:
        """One written scenario of the run whose controls wait (queued, or running with an expired lease), now
        `running` for `task_id`, oldest first; None when none waits. Mapped: the newest version, or an older
        one a reviewer accepted (G139: an accepted version a regenerate replaced while its controls still
        waited kept them waiting for ever; G148: a replaced rejected one is never mapped)."""
        now = _now()
        return self._scenarios.find_one_and_update(
            _waiting(session_id, now),
            _running(task_id, now),
            projection=_CLAIMED_FIELDS,
            sort=[("created_at", 1)],
            return_document=ReturnDocument.AFTER,
        )

    def claim_scenario(self, scenario_id: str, task_id: str, remap: bool = False) -> dict[str, Any] | None:
        """One scenario's controls taken by a plan request's top-up (Rule R1T) when they are not mapped:
        waiting (queued, failed, or running with an expired lease), mapped to nothing, or never asked for.
        None when they are mapped, or a live lease holds them (a worker maps them now)."""
        now = _now()
        not_mapped = [
            # Cancelled (G214): a plan request asked for them on purpose, so they are mapped now.
            {"controls.status": {"$in": [Status.QUEUED, Status.FAILED, Status.CANCELLED]}},
            {"controls.status": Status.RUNNING, "controls.lease_until": {"$lt": now}},
            {"controls.status": Status.DONE, "controls.items": {"$size": 0}},
            {"controls": {"$exists": False}},
        ]
        if remap:  # mapped, but every control was retired since (the caller checked against the library)
            not_mapped.append({"controls.status": Status.DONE})
        return self._scenarios.find_one_and_update(
            {"_id": scenario_id, "status": ScenarioStatus.DONE, "$or": not_mapped},
            _running(task_id, now),
            projection=_CLAIMED_FIELDS,
            return_document=ReturnDocument.AFTER,
        )

    def find_mapped(self, scenario_id: str) -> list[dict[str, Any]] | None:
        """The scenario's mapped controls, or None while they are not mapped."""
        found = self._scenarios.find_one(
            {"_id": scenario_id, "controls.status": Status.DONE, "controls.items.0": {"$exists": True}},
            {"controls.items": 1},
        )
        return None if found is None else found["controls"]["items"]

    def renew(self, scenario_id: str, task_id: str) -> bool:
        lease_until = _now() + timedelta(seconds=Controls.LEASE_SECONDS)
        return self._if_owned(scenario_id, task_id, {"controls.lease_until": lease_until})

    def finish(self, scenario_id: str, task_id: str, mapped: dict[str, Any]) -> bool:
        """The mapping saved (`mapped`: items, warning, query, made_with) and the controls `done`; False when
        this worker's claim was taken over (its result is dropped)."""
        changes = {f"controls.{key}": value for key, value in mapped.items()}
        done = {"controls.status": Status.DONE, "controls.mapped_at": _now(), "controls.error": None}
        return self._if_owned(scenario_id, task_id, changes | done | {"controls.lease_until": None})

    def give_back(self, scenario_id: str, task_id: str, attempts: int, error: dict[str, str]) -> bool:
        """After an outage: queued again, or failed once Controls.MAX_ATTEMPTS were used (the sweep retries a
        failed mapping after Controls.RETRY_FAILED_AFTER_SECONDS)."""
        if attempts >= Controls.MAX_ATTEMPTS:
            return self.fail(scenario_id, task_id, error)
        queued = {"controls.status": Status.QUEUED, "controls.queued_at": _now(), "controls.error": error}
        return self._if_owned(scenario_id, task_id, queued | {"controls.lease_until": None})

    def fail(self, scenario_id: str, task_id: str, error: dict[str, str]) -> bool:
        failed = {"controls.status": Status.FAILED, "controls.error": error, "controls.lease_until": None}
        return self._if_owned(scenario_id, task_id, failed)

    def _if_owned(self, scenario_id: str, task_id: str, changes: dict[str, Any]) -> bool:
        fence = {"_id": scenario_id, "controls.task_id": task_id, "controls.status": Status.RUNNING}
        return self._scenarios.update_one(fence, {"$set": changes}).matched_count == 1


class ControlSweep:
    """The beat sweep's one write (Rule S11): every stalled mapping of every run queued again; and whether one
    of a run's scenarios waits for its controls."""

    def __init__(self, db: Database) -> None:
        self._scenarios = db[Collection.SCENARIOS]
        self._sessions = db[Collection.SESSIONS]
        self._counts = RunCounts(db)

    def requeue_stalled(self) -> list[str]:
        """The sweep (Rule S11): queued too long (its message was lost), running with an expired lease (its
        worker died) or failed long enough ago → queued now, attempts kept. The runs touched, each once; never
        a run its owner cancelled or deleted (settled first)."""
        self._settle_stopped_runs()
        now = _now()
        lost = now - timedelta(seconds=Controls.RESEND_QUEUED_AFTER_SECONDS)
        failed_long_ago = now - timedelta(seconds=Controls.RETRY_FAILED_AFTER_SECONDS)
        stalled = [
            {"controls.status": Status.QUEUED, "controls.queued_at": {"$lt": lost}},
            {"controls.status": Status.RUNNING, "controls.lease_until": {"$lt": now}},
            {"controls.status": Status.FAILED, "controls.last_attempt_at": {"$lt": failed_long_ago}},
        ]
        # A hand-written scenario's controls are mapped only inside its plan request (Rule R1T), never here.
        query = {
            "status": ScenarioStatus.DONE,
            "source": {"$ne": RunKind.MANUAL},
            "$and": [MAPPED_VERSIONS, {"$or": stalled}],
        }
        runs: list[str] = self._scenarios.distinct("session_id", query)
        self._scenarios.update_many(
            query,
            {
                "$set": {
                    "controls.status": Status.QUEUED,
                    "controls.queued_at": now,
                    "controls.lease_until": None,
                }
            },
        )
        return sorted(runs)

    def _settle_stopped_runs(self) -> None:
        """G214, whatever their age: the controls still waiting on a run its owner cancelled stop, with the
        run's counts (a scenario its writer saved as the cancel landed, or controls a resume queued as a new
        cancel landed); the scenarios of a run deleted meanwhile go with it (else queued again for ever)."""
        waiting = {
            "status": ScenarioStatus.DONE,
            "source": {"$ne": RunKind.MANUAL},
            "controls.status": {"$in": STOPPABLE_CONTROLS},
        } | MAPPED_VERSIONS
        runs = self._scenarios.distinct("session_id", waiting)
        if not runs:
            return
        found = self._sessions.find({"_id": {"$in": runs}}, {"status": 1})
        states = {record["_id"]: record.get("status") for record in found}
        if stopped := [run for run in runs if states.get(run) == Status.CANCELLED]:
            self._scenarios.update_many(
                {**waiting, "session_id": {"$in": stopped}},
                {"$set": {"controls.status": Status.CANCELLED, "controls.lease_until": None}},
            )
            for run in stopped:  # its counts stop showing controls waiting (Rule S12)
                self._counts.refresh(run)
        if gone := [run for run in runs if run not in states]:
            self._scenarios.delete_many({"session_id": {"$in": gone}})

    def has_waiting(self, session_id: str) -> bool:
        """Whether one of the run's scenarios waits for its controls, as ControlLeases.claim takes them."""
        return self._scenarios.find_one(_waiting(session_id, _now()), {"_id": 1}) is not None


class ControlDeliveries:
    """One delivery maps a run's controls at a time (G195): a small lease on the run
    (tsg_sessions.controls_delivery {task_id, until}) taken in ONE conditional update, so of ten messages for
    one run delivered at once exactly one maps and the others end at once (live test 2026-10-11: ten passed a
    look-then-claim check together and held every worker thread). A plan request's top-up never takes it: it
    claims its one scenario, atomically, as a delivery does."""

    def __init__(self, db: Database) -> None:
        self._sessions = db[Collection.SESSIONS]

    def take(self, session_id: str, task_id: str) -> bool:
        """The run's delivery lease for `task_id` when it is free, expired, a next turn in flight (no holder),
        or `task_id`'s own already (a retried message keeps its task id). False while another delivery holds
        it."""
        now = _now()
        free = [
            {"controls_delivery.until": {"$lt": now}},
            {"controls_delivery.task_id": {"$in": [None, task_id]}},  # also: no lease at all
        ]
        held = {"task_id": task_id, "until": now + timedelta(seconds=Controls.LEASE_SECONDS)}
        found = self._sessions.update_one(  # never for a run its owner cancelled (G214)
            {"_id": session_id, "status": {"$ne": Status.CANCELLED}, "$or": free},
            {"$set": {"controls_delivery": held}},
        )
        return found.matched_count == 1

    def renew(self, session_id: str, task_id: str) -> bool:
        until = _now() + timedelta(seconds=Controls.LEASE_SECONDS)
        return self._if_held(session_id, task_id, {"$set": {"controls_delivery.until": until}})

    def hand_over(self, session_id: str, task_id: str) -> None:
        """The run's next turn is queued: no holder, and the run counts as served while that message waits, so
        the sweep sends no second one (a message lost on the way: the hand-over runs out, the sweep re-sends).
        """
        until = _now() + timedelta(seconds=Controls.RESEND_QUEUED_AFTER_SECONDS)
        self._if_held(session_id, task_id, {"$set": {"controls_delivery": {"task_id": None, "until": until}}})

    def release(self, session_id: str, task_id: str) -> None:
        self._if_held(session_id, task_id, {"$unset": {"controls_delivery": ""}})

    def served(self, session_ids: Iterable[str]) -> set[str]:
        """Of `session_ids`, the runs a delivery maps now or whose next turn is on its way."""
        found = self._sessions.find(
            {"_id": {"$in": list(session_ids)}, "controls_delivery.until": {"$gte": _now()}}, {"_id": 1}
        )
        return {record["_id"] for record in found}

    def _if_held(self, session_id: str, task_id: str, update: dict[str, Any]) -> bool:
        held = {"_id": session_id, "controls_delivery.task_id": task_id}
        return self._sessions.update_one(held, update).matched_count == 1


def _waiting(session_id: str, now: datetime) -> dict[str, Any]:
    """The run's written scenarios whose controls wait: queued, or running with an expired lease; the newest
    version, or an older one a reviewer accepted (G139, G148)."""
    waiting = [
        {"controls.status": Status.QUEUED},
        {"controls.status": Status.RUNNING, "controls.lease_until": {"$lt": now}},
    ]
    return {
        "session_id": session_id,
        "status": ScenarioStatus.DONE,
        "$and": [MAPPED_VERSIONS, {"$or": waiting}],
    }


def _running(task_id: str, now: datetime) -> dict[str, Any]:
    """A claim's update: the controls `running` for `task_id` under a fresh lease, one more attempt
    counted."""
    return {
        "$set": {
            "controls.status": Status.RUNNING,
            "controls.task_id": task_id,
            "controls.lease_until": now + timedelta(seconds=Controls.LEASE_SECONDS),
            "controls.last_attempt_at": now,
        },
        "$inc": {"controls.attempts": 1},
    }


def _now() -> datetime:
    return datetime.now(UTC)
