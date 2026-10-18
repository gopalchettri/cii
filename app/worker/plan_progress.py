"""A run's plan paths as the write job settles them, each change in one fenced write with the run's counts and
plan note, then the set's next batch handed over, or the set or the regenerate ended."""

from datetime import UTC, datetime
from typing import Any

from app.core.constants import (
    RunActionKind,
    RunActionOutcome,
    ScenarioStatus,
    Status,
    TaskName,
    UnselectedReason,
)
from app.core.exceptions import LeaseLost
from app.data_access.jobs.repository import JobLease, ended_job_fields
from app.data_access.scenario.repository import scenario_sessions, scenarios
from app.domain.scenario.plan import (
    best_reserve,
    budget_left,
    next_paths_to_write,
    plan_counts,
    set_summary,
)
from app.realtime.publisher import publish_session_status
from app.worker.jobs import hand_over


class PlanProgress:
    """The plan of the run one write job holds, and the fenced writes that move it on."""

    def __init__(self, lease: JobLease, run: dict[str, Any]) -> None:
        self._lease, self._run_id = lease, run["_id"]
        self._plan, self._last_action = run["plan"], run.get("last_action") or {}
        self.paths = {path["path_id"]: path for path in self._plan["paths"]}
        # The set being written; none on a run whose job carries no set (it writes its batch, then stops).
        self._set = set(run["job"].get("set") or ())

    def hold(self) -> None:
        """Renew the job's lease right before a scenario is saved, else raise LeaseLost: a run cancelled or
        deleted during the AI call, or taken over by a later delivery, never gets the scenario."""
        if not self._lease.renew_job():
            raise LeaseLost(self._run_id)

    def abandon(
        self, path_id: str, state: dict[str, Any], reason: str, threats: dict[str, dict[str, Any]]
    ) -> str | None:
        """Give a path up for good; when the set's budget allows and a reserve exists, the reserve takes its
        place in the same fenced write. Return the reserve's id, or None."""
        states = {path_id: state | {"abandoned_reason": reason}}
        # Given up (its try counted) before the pick: it covers nothing and hides no try spent.
        self.paths[path_id].update(states[path_id])
        in_set = [path for key, path in self.paths.items() if key in self._set]
        reserve = best_reserve(self.paths.values(), threats) if budget_left(in_set) else None
        if reserve is None:
            self.record(states)
            return None
        replaced = {"selected": False, "unselected_reason": UnselectedReason.REPLACED_AFTER_FAILURE}
        states[path_id] |= replaced | {"replaced_by": reserve["path_id"]}
        states[reserve["path_id"]] = {"selected": True, "unselected_reason": None, "replaces": path_id}
        self._set.add(reserve["path_id"])
        self.record(states, {"job.set": sorted(self._set)})
        return str(reserve["path_id"])

    def record(self, states: dict[str, dict[str, Any]], also: dict[str, Any] | None = None) -> None:
        """Save attack path states, the plan's figures, the scenario counts and the plan note in one fenced
        write, then send a live update. `also`: more fields for the same write."""
        for attack_path_id, state in states.items():
            self.paths[attack_path_id].update(state)
        figures = plan_counts(self.paths.values())
        scenario_sessions.update_scenario_session_plan(self._lease, states, figures, also)
        publish_session_status(self._run_id)

    def continue_or_finish(self) -> None:
        """Hand the set's next batch to this same task, or end the set: complete, or partial when a path of
        this set was abandoned."""
        in_set = [path for path_id, path in self.paths.items() if path_id in self._set]
        batch = next_paths_to_write(in_set)
        if batch:
            hand_over(self._lease, TaskName.WRITE_SCENARIOS, {"job.batch": batch})
            return
        # A delivery that had lost its lease may still have saved a path another delivery then gave up on: the
        # written scenario wins, so the plan never calls a written path abandoned.
        given_up = [
            path["path_id"] for path in self.paths.values() if path["abandoned"] and not path["served"]
        ]
        written = (
            scenarios.list(
                fields="path_id",
                session_id=self._run_id,
                path_id_in=given_up,
                status=ScenarioStatus.DONE,
                newest=True,
            )
            if given_up
            else []
        )
        rescued = {row["path_id"]: row["_id"] for row in written}
        if rescued:
            self.record({path_id: {"served": sid, "abandoned": False} for path_id, sid in rescued.items()})
        partial = plan_counts(in_set)["abandoned"] > 0
        # This action's own writing time: from the plan's freeze, or from a later set's start.
        started = max(self._plan["frozen_at"], self._last_action.get("started_at") or self._plan["frozen_at"])
        seconds = (datetime.now(UTC) - started).total_seconds()
        outcome = RunActionOutcome.PARTIAL if partial else RunActionOutcome.COMPLETE
        changes: dict[str, Any] = {"last_action.outcome": outcome, "timings.scenarios_s": round(seconds, 1)}
        if self._last_action.get("kind") == RunActionKind.NEXT_SET:  # requested and epoch stay as queued
            summary = set_summary(in_set, list(self.paths.values()), outcome)
            changes |= {f"last_next_set.{key}": value for key, value in summary.items()}
        self._lease.update_job(changes | ended_job_fields(Status.DONE))

    def finish_regenerate(self, replaced: int, requested: int) -> None:
        """End a regenerate: complete when every target got its new version, partial when any kept its old
        one, timed from the click."""
        outcome = RunActionOutcome.COMPLETE if replaced == requested else RunActionOutcome.PARTIAL
        started = self._last_action.get("started_at") or datetime.now(UTC)
        self._lease.update_job(
            {
                "last_action.outcome": outcome,
                "last_regen.outcome": outcome,  # requested and epoch stay as queued
                "last_regen.replaced": replaced,
                "timings.scenarios_s": round((datetime.now(UTC) - started).total_seconds(), 1),
            }
            | ended_job_fields(Status.DONE)
        )
