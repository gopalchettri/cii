"""A run's plan paths as the scenario write job settles them (Step 12, BUILD_PLAN S25-S26): every change in
ONE fenced write with the run's counts and plan note, then a live update; then the set's next batch, handed to
the same task, or the end of the set (job.set: the paths the plan job or a next-set call asked for)."""

from datetime import UTC, datetime
from typing import Any

from app.core.constants import PlanMessage, RunActionKind, RunActionOutcome, TaskName
from app.data_access.job_records import JobLease, LeaseLost
from app.data_access.run_counts import RunCounts
from app.data_access.scenarios import ScenarioRepository
from app.engine.scenarios.attack_paths.path_progress import (
    is_still_to_write,
    next_paths_to_write,
    plan_counts,
)
from app.realtime.publisher import publish_session_status
from app.worker.jobs import hand_over


class PlanProgress:
    def __init__(
        self, lease: JobLease, run: dict[str, Any], scenarios: ScenarioRepository, counts: RunCounts
    ) -> None:
        self._lease, self._run_id, self._scenarios, self._counts = lease, run["_id"], scenarios, counts
        self._plan, self._last_action = run["plan"], run.get("last_action") or {}
        self.paths = {path["path_id"]: path for path in self._plan["paths"]}
        # The set being written; none on a run whose job carries no set (it writes its batch, then stops).
        self._set = set(run["job"].get("set") or ())

    def hold(self) -> None:
        """Right before a scenario is saved: the job still owns the run (its lease renewed), else LeaseLost.
        Its AI answers come back seconds after the call, so a run its owner cancelled or deleted meanwhile
        never gets a scenario saved after the cancel (G214), nor one a later delivery already owns."""
        if not self._lease.renew():
            raise LeaseLost(self._run_id)

    def is_still_to_write(self, path_id: str) -> bool:
        return is_still_to_write(self.paths[path_id])

    def record(self, states: dict[str, dict[str, Any]]) -> None:
        """Paths' new states, the plan's figures and its note in ONE fenced write, after the run's scenario
        counts (their own guarded write: the controls job refreshes them too); then a live update."""
        changes: dict[str, Any] = {}
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

    def continue_or_finish(self) -> None:
        """The set's next batch, handed to this same task (never-tried paths first, best rank first), or the
        end of the set, which ends this action: complete, or partial when a path of this set was abandoned or
        a category not assessed. The paths no one asked for yet wait for the next set."""
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
        # This set's own result: a path set 1 abandoned does not make set 2 partial; an unassessed category
        # is a gap in the whole plan, so every set carries it (G113).
        partial = bool(self._plan["not_assessed"]) or plan_counts(in_set)["abandoned"] > 0
        # This action's own writing time: from the plan's freeze for a run's first writing, from the next
        # set's start for a later one (never the days a reviewer took in between).
        started = max(self._plan["frozen_at"], self._last_action.get("started_at") or self._plan["frozen_at"])
        seconds = (datetime.now(UTC) - started).total_seconds()
        outcome = RunActionOutcome.PARTIAL if partial else RunActionOutcome.COMPLETE
        changes: dict[str, Any] = {"last_action.outcome": outcome, "timings.scenarios_s": round(seconds, 1)}
        if self._last_action.get("kind") == RunActionKind.NEXT_SET:  # what the status shows of it
            delivered = sum(bool(path["served"]) for path in in_set)
            changes["last_next_set"] = {"outcome": outcome, "requested": len(in_set), "delivered": delivered}
        self._lease.finish(changes)
