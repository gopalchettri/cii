"""A run's plan paths as the write job settles them, each change in one fenced write."""

from datetime import datetime
from typing import Any

import structlog

from app.core import constants as c
from app.core import metrics
from app.core.clock import utc_now
from app.crud.jobs import JobLease, ended_job_fields
from app.crud.scenarios import get_threat_scenario_repository, get_threat_scenario_session_repository
from app.domain.scenario import session
from app.realtime.publisher import publish_session_status
from app.worker.jobs import hand_over

log = structlog.get_logger(__name__)


class PlanProgress:
    """The plan of the run one write job holds, and the fenced writes that move it on."""

    def __init__(self, lease: JobLease, run: dict[str, Any]) -> None:
        self._lease, self._run_id = lease, run["_id"]
        self._sessions, self._scenarios = get_threat_scenario_session_repository(), get_threat_scenario_repository()
        self._plan, self._last_action = run["plan"], run.get("last_action") or {}
        self._planning_s = (run.get("timings") or {}).get("threats_s", 0.0)  # a start's plan job; else none
        self.paths = {path["path_id"]: path for path in self._plan["paths"]}
        self._set = set(run["job"].get("set") or ())

    def abandon(
        self,
        path_id: str,
        state: dict[str, Any],
        reason: str,
        threats: dict[str, dict[str, Any]],
        card: c.ScenarioOutcome | None = None,
    ) -> None:
        """Give a path up for good, logged and counted with its last `card`."""
        log.warning(c.LogEvent.WRITER_PATH_ABANDONED, path_id=path_id, path_attempts=state["attempts"], reason=reason)
        counted = (c.ScenarioOutcome.ABANDONED,) if card is None else (card, c.ScenarioOutcome.ABANDONED)
        states = {path_id: state | {"abandoned_reason": reason, "settled_epoch": self._lease.epoch}}
        self.paths[path_id].update(states[path_id])
        reserve = session.pick_replacement_path(self.paths.values(), threats, self._set)
        if reserve is None:
            self.record(states, counted=counted)
            return
        replaced = {"selected": False, "unselected_reason": c.UnselectedReason.REPLACED_AFTER_FAILURE}
        states[path_id] |= replaced | {"replaced_by": reserve["path_id"]}
        states[reserve["path_id"]] = {"selected": True, "unselected_reason": None, "replaces": path_id}
        self._set.add(reserve["path_id"])
        self.record(states, {"job.set": sorted(self._set)}, counted)

    def leave_for_next_set(self, path_id: str, state: dict[str, Any], card: c.ScenarioOutcome) -> None:
        """Keep a path open but out of the set being written, so only a later set writes it; its `card`"""
        # ponytail: pick_replacement_path may still pick it as this set's spare; flag it if spares must be new
        self._set.discard(path_id)
        settled = state | {"abandoned": False, "settled_epoch": self._lease.epoch}
        self.record({path_id: settled}, {"job.set": sorted(self._set)}, (card,))

    def serve_written(self, path_ids: list[str]) -> None:
        """Serve each of the paths that already has a finished scenario, with no AI call."""
        if not path_ids:
            return
        done = c.ScenarioStatus.DONE
        written = self._scenarios.list(
            fields="path_id", session_id=self._run_id, path_id_in=path_ids, status=done, newest=True
        )
        if written:
            self.record({row["path_id"]: {"served": row["_id"], "abandoned": False} for row in written})

    def record(
        self,
        states: dict[str, dict[str, Any]],
        also: dict[str, Any] | None = None,
        counted: tuple[c.ScenarioOutcome, ...] = (),
    ) -> None:
        """Save attack path states, the plan's figures and the scenario counts in one fenced write."""
        for attack_path_id, state in states.items():
            self.paths[attack_path_id].update(state)
        figures = session.count_plan_paths(self.paths.values())
        self._sessions.update_scenario_session_plan(self._lease, states, figures, also)
        for outcome in counted:
            metrics.SCENARIOS.labels(outcome).inc()
        publish_session_status(self._run_id)

    def continue_or_finish(self) -> None:
        """Hand the set's next batch to this same task, or end the set."""
        in_set = [path for path_id, path in self.paths.items() if path_id in self._set]
        _, batch = session.pick_next_paths_to_write(in_set)
        if batch:
            hand_over(self._lease, c.TaskName.WRITE_SCENARIOS, {"job.batch": batch})
            return
        self.serve_written(
            [path["path_id"] for path in self.paths.values() if path["abandoned"] and not path["served"]]
        )
        partial = session.count_plan_paths(in_set)["abandoned"] > 0
        started = max(self._plan["frozen_at"], self._last_action.get("started_at") or self._plan["frozen_at"])
        outcome = c.RunActionOutcome.PARTIAL if partial else c.RunActionOutcome.COMPLETE
        changes: dict[str, Any] = {"last_action.outcome": outcome, **self._action_times(started)}
        if self._last_action.get("kind") == c.RunActionKind.NEXT_SET:  # requested and epoch stay as queued
            summary = session.summarise_finished_set(in_set, list(self.paths.values()), outcome)
            changes |= {f"last_next_set.{key}": value for key, value in summary.items()}
        self._lease.update_job(changes | ended_job_fields(c.Status.DONE))

    def finish_regenerate(self, replaced: int, requested: int) -> None:
        """End a regenerate: complete when every target was written, else partial."""
        outcome = c.RunActionOutcome.COMPLETE if replaced == requested else c.RunActionOutcome.PARTIAL
        started = self._last_action.get("started_at") or utc_now()
        self._lease.update_job(
            {
                "last_action.outcome": outcome,
                "last_regen.outcome": outcome,  # requested and epoch stay as queued
                "last_regen.replaced": replaced,
                **self._action_times(started),
            }
            | ended_job_fields(c.Status.DONE)
        )

    def _action_times(self, started: datetime) -> dict[str, float]:
        now = utc_now()
        writing_from = self._last_action.get("writing_started_at") or started
        return {
            "timings.threats_s": round(self._planning_s + (writing_from - started).total_seconds(), 1),
            "timings.scenarios_s": round((now - writing_from).total_seconds(), 1),
        }
