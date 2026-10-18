"""A run's plan paths as the write job settles them, each change in one fenced write with the run's counts and
plan note, then the set's next batch handed over, or the set or the regenerate ended."""

from datetime import UTC, datetime
from typing import Any

from app.core.constants import PlanMessage, RunActionKind, RunActionOutcome, TaskName, UnselectedReason
from app.data_access.job_records import JobLease, LeaseLost
from app.data_access.scenario.scenarios import RunCounts, ScenarioRepository
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

    def __init__(
        self, lease: JobLease, run: dict[str, Any], scenarios: ScenarioRepository, counts: RunCounts
    ) -> None:
        self._lease, self._run_id, self._scenarios, self._counts = lease, run["_id"], scenarios, counts
        self._plan, self._last_action = run["plan"], run.get("last_action") or {}
        self.paths = {path["path_id"]: path for path in self._plan["paths"]}
        # The set being written; none on a run whose job carries no set (it writes its batch, then stops).
        self._set = set(run["job"].get("set") or ())

    def hold(self) -> None:
        """Renew the job's lease right before a scenario is saved, else raise LeaseLost: a run cancelled or
        deleted during the AI call, or taken over by a later delivery, never gets the scenario."""
        if not self._lease.renew():
            raise LeaseLost(self._run_id)

    def abandon(
        self,
        path_id: str,
        state: dict[str, Any],
        reason: str,
        threats: dict[str, dict[str, Any]],
        evidence: bool,
    ) -> str | None:
        """Give a path up for good; when the set's budget allows and a reserve exists, the reserve takes its
        place in the same fenced write. Return the reserve's id, or None. `evidence`: intelligence on."""
        states = {path_id: state | {"abandoned_reason": reason}}
        # Given up (its try counted) before the pick: it covers nothing and hides no try spent.
        self.paths[path_id].update(states[path_id])
        in_set = [path for key, path in self.paths.items() if key in self._set]
        reserve = best_reserve(self.paths.values(), threats, evidence) if budget_left(in_set) else None
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
        """Save paths' new states, the plan's figures and its note in one fenced write (after the run's
        scenario counts, which have their own guarded write), then send a live update. `also`: more fields
        for the same write."""
        changes: dict[str, Any] = dict(also or {})
        for number, (path_id, state) in enumerate(states.items()):
            self.paths[path_id].update(state)
            changes |= {f"plan.paths.$[p{number}].{key}": value for key, value in state.items()}
        figures = plan_counts(self.paths.values())
        written = self._counts.refresh(self._run_id)["written"]
        note = PlanMessage.PLAN_NOTE.format(
            planned=figures["planned"], written=written, remaining=figures["remaining"]
        )
        changes |= {f"counts.{key}": value for key, value in figures.items()} | {"plan_note": note}
        self._lease.write(changes, [{f"p{number}.path_id": path_id} for number, path_id in enumerate(states)])
        publish_session_status(self._run_id)

    def keep_evidence(self, found: dict[str, dict[str, Any]]) -> None:
        """Save the evidence searched for threats (key -> {evidence, intel_search}) on the plan in one fenced
        write, so every later write of the path reuses it and its evidence numbering never changes."""
        changes: dict[str, Any] = {}
        for number, fields in enumerate(found.values()):
            changes |= {f"plan.threats.$[t{number}].{name}": value for name, value in fields.items()}
        self._lease.write(changes, [{f"t{number}.key": key} for number, key in enumerate(found)])

    def continue_or_finish(self) -> None:
        """Hand the set's next batch to this same task, or end the set: complete, or partial when a path of
        this set was abandoned or a category not assessed."""
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
        rescued = self._scenarios.find_written(self._run_id, given_up) if given_up else {}
        if rescued:
            self.record({path_id: {"served": sid, "abandoned": False} for path_id, sid in rescued.items()})
        # This set's own result; an unassessed category is a gap in the whole plan, so every set carries it.
        partial = bool(self._plan["not_assessed"]) or plan_counts(in_set)["abandoned"] > 0
        # This action's own writing time: from the plan's freeze, or from a later set's start.
        started = max(self._plan["frozen_at"], self._last_action.get("started_at") or self._plan["frozen_at"])
        seconds = (datetime.now(UTC) - started).total_seconds()
        outcome = RunActionOutcome.PARTIAL if partial else RunActionOutcome.COMPLETE
        changes: dict[str, Any] = {"last_action.outcome": outcome, "timings.scenarios_s": round(seconds, 1)}
        if self._last_action.get("kind") == RunActionKind.NEXT_SET:  # requested and epoch stay as queued
            summary = set_summary(in_set, list(self.paths.values()), outcome)
            changes |= {f"last_next_set.{key}": value for key, value in summary.items()}
        self._lease.finish(changes)

    def finish_regenerate(self, replaced: int, requested: int) -> None:
        """End a regenerate: complete when every target got its new version, partial when any kept its old
        one, timed from the click."""
        outcome = RunActionOutcome.COMPLETE if replaced == requested else RunActionOutcome.PARTIAL
        started = self._last_action.get("started_at") or datetime.now(UTC)
        self._lease.finish(
            {
                "last_action.outcome": outcome,
                "last_regen.outcome": outcome,  # requested and epoch stay as queued
                "last_regen.replaced": replaced,
                "timings.scenarios_s": round((datetime.now(UTC) - started).total_seconds(), 1),
            }
        )
