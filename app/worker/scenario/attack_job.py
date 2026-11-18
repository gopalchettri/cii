"""An attack run's write job: one checked AI call writes a batch's slots and lists the risks that grow its plan."""

from collections.abc import Callable, Iterator, Sequence
from typing import Any

import structlog

from app.ai import ChatModel
from app.core import constants as c
from app.core.clock import utc_now
from app.crud.jobs import JobLease
from app.crud.scenarios import get_threat_scenario_repository
from app.domain.scenario import attack, session
from app.domain.scenario.attack_prompt import build_attack_facts, build_attack_prompt, find_attack_sources_of_asset
from app.domain.shared.ask_ai import ChatPrompt, call_tokens, within_call_limit
from app.domain.shared.names import as_json
from app.schemas.library import ThreatLibrary
from app.schemas.scenario_internal import PathFailure, WriterBrief, WrittenScenario
from app.worker.scenario.plan_progress import PlanProgress
from app.worker.scenario.write_job import BatchWriter, PathOutcome, PathWriter

log = structlog.get_logger(__name__)


class AttackPathWriter(PathWriter):
    """Writes an attack run's slots: one checked AI call a set, the plan grown and filled before any card."""

    def __init__(
        self,
        lease: JobLease,
        run: dict[str, Any],
        chat: ChatModel,
        library: ThreatLibrary,
        progress: PlanProgress,
        replaces: dict[str, str],
        regenerate: bool,
    ) -> None:
        super().__init__(run, chat, library, c.WriterStyle.ORIGINAL)
        self._lease, self._plan, self._library, self._progress = lease, run["plan"], library, progress
        self._replaces = replaces  # by path id: the version a regenerate writes again
        self._lists_risks = attack.is_listing_risks(self._plan, regenerate)  # this job's first call asks for them
        self._sides = find_attack_sources_of_asset(self._context)
        # the facts every prompt of the run shows: what an answer may take a label or a word of another script from
        self._given = as_json(build_attack_facts(self._context, self._budget)).casefold()
        self._titles: list[str] = []  # of the run's written scenarios: no new one repeats them
        self._checked: attack.CheckedSet = {}  # by path id: what each card is built from

    def build_card(
        self,
        run: dict[str, Any],
        path: dict[str, Any],
        threat: dict[str, Any],
        brief: WriterBrief,
        written: WrittenScenario,
        replaces: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """The path's card with what MITRE ATT&CK confirmed of its scenario."""
        found = self._checked[path["path_id"]]
        return attack.build_attack_card(run, path, threat, brief, written, found, replaces)

    def write_scenario_set(
        self, slots: Sequence[tuple[str, dict[str, Any]]], last_try: bool, epoch: int = 0
    ) -> Iterator[tuple[str, PathOutcome | Exception]]:
        """Yields each slot's outcome by its path id once its call's answer is checked; a slot with no card, none."""
        paths = dict(slots)
        left = dict.fromkeys(paths)  # the slots not settled yet
        try:
            yield from self._write_slots(paths, left)
        except Exception as error:  # the paths not settled yet follow the writer's own rules
            open_ids = [paths[label]["path_id"] for label in left if not attack.is_without_risk(paths[label])]
            yield from self._fail_paths_left(error, open_ids, last_try)

    def _write_slots(
        self, paths: dict[str, dict[str, Any]], left: dict[str, None]
    ) -> Iterator[tuple[str, PathOutcome]]:
        if not paths:
            return
        held = get_threat_scenario_repository().list(
            fields=("content.title", "content.risk_statement"), session_id=self._run_id, status=c.ScenarioStatus.DONE
        )
        self._titles = [doc["content"]["title"] for doc in held]
        earlier = {doc["_id"]: doc["content"] for doc in held}

        def build_prompt(labels: Sequence[str], lists: bool = self._lists_risks) -> ChatPrompt:
            """The prompt of these slots as their paths are now: a listed risk reaches a later call's slot."""
            slots = [self._build_slot(label, paths[label], earlier) for label in labels]
            return build_attack_prompt(self._context, slots, self._titles, lists, self._library, self._budget)

        for number, part in enumerate(self._split_within_call_limit(list(paths), build_prompt)):
            lists = self._lists_risks and number == 0
            first = lists and self._plan.get("risks_listed_at") is None  # the run's first call may leave a slot out
            asked = [label for label in part if not attack.is_without_risk(paths[label])]
            if not asked:
                continue
            other_risks, checked = attack.ask_for_confirmed_set(
                self._chat, build_prompt(asked, lists), set(asked), self._sides, self._library, first, self._given
            )
            self._record_plan({label: paths[label] for label in asked}, other_risks, checked, lists)
            for label in asked:
                outcome = self._settle_slot(paths[label], checked[label], first)
                del left[label]
                if outcome is not None:
                    yield paths[label]["path_id"], outcome

    def _split_within_call_limit(
        self, labels: list[str], build_prompt: Callable[[Sequence[str]], ChatPrompt]
    ) -> list[Sequence[str]]:
        task = c.AiTask.WRITE_SCENARIO
        if call_tokens(build_prompt(labels[:1]), self._chat, task) > c.AiLimits.CALL_TOKENS_LIMIT:
            return [labels]  # the shared facts alone are over the limit: fewer slots a call would not fit it
        return within_call_limit(labels, build_prompt, self._chat, task)

    def _build_slot(self, label: str, path: dict[str, Any], earlier: dict[str, dict[str, Any]]) -> dict[str, Any]:
        old = earlier.get(self._replaces.get(path["path_id"], ""))
        if old is not None:  # the scenario to tell another way: it carries its risk
            return {"slot": label, "rewrite_of": {"title": old["title"], "risk_statement": old.get("risk_statement")}}
        return {"slot": label} | ({"risk": path["risk"]} if path.get("risk") else {})

    def _record_plan(
        self,
        written: dict[str, dict[str, Any]],
        other_risks: list[dict[str, str]],
        checked: attack.CheckedSet,
        lists: bool,
    ) -> None:
        paths, changes = self._progress.paths, {}
        if lists:
            answered = {path["path_id"] for label, path in written.items() if not checked[label].is_left_out}
            held, target = list(paths.values()), self._plan.get("target") or 0  # the plan before this call's risks
            added, threats = attack.extend_attack_plan(held, answered, other_risks, self._titles, target)
            paths.update({path["path_id"]: path for path in added})
            self.threats.update({threat["key"]: threat for threat in threats})
            counts = attack.count_attack_plan(paths.values())
            if self._plan.get("risks_listed_at") is None:  # the first call: a slot no risk reached leaves the count
                counts["first_set"] = sum(not attack.is_without_risk(path) for path in held)
                self._plan["risks_listed_at"] = utc_now()
            self._plan["risks_complete"] = not other_risks  # none listed, new or told again: no later call asks
            changes = {f"plan.{name}": self._plan[name] for name in ("risks_listed_at", "risks_complete")}
            changes |= {f"plan_trace.counts.{name}": count for name, count in counts.items()}
        for label, path in written.items():
            told = checked[label].answer
            if not checked[label].refusal:
                key = path["steps"][0]
                self.threats[key], filled = attack.build_slot_threat(
                    self.threats[key], path, checked[label], self._library
                )
                path.update(filled)
            elif told is not None and not path.get("risk"):  # not confirmed: a retried job asks for its own risk
                path["risk"] = {"title": told.scenario_title, "risk": told.risk_statement}
        figures = session.count_plan_paths(paths.values())
        changes |= {f"counts.{name}": count for name, count in figures.items()}
        # ponytail: both lists whole in one fenced write (a plan is tens of paths); positional sets if it grows
        self._lease.update_job(
            changes | {"plan.paths": list(paths.values()), "plan.threats": list(self.threats.values())}
        )

    def _settle_slot(self, path: dict[str, Any], found: attack.CheckedScenario, first: bool) -> PathOutcome | None:
        path_id = path["path_id"]
        if found.refusal and (path_id in self._replaces or path["abandoned"]):  # the card it has says why
            return PathFailure(c.ErrorCode.GENERATION_FAILED, found.refusal)
        if first and found.is_left_out:  # no card: the plan write gave it a listed risk, or no further risk
            return None
        if found.refusal:
            log.warning(c.LogEvent.ATTACK_SCENARIO_NOT_CONFIRMED, path_id=path_id, message=found.refusal)
            state = {"attempts": path["attempts"] + 1, "abandoned": True}
            self._progress.abandon(path_id, state, found.refusal, self.threats)
            return None
        if found.problems:
            log.info(c.LogEvent.ATTACK_NAME_NOT_CONFIRMED, path_id=path_id, message="; ".join(found.problems))
        assert found.answer is not None
        self._checked[path_id] = found
        self._titles.append(found.answer.scenario_title)
        return attack.draft_attack_scenario(self._context, path, self.threats[path["steps"][0]], found, self._given)


class AttackBatchWriter(BatchWriter):
    """One delivery's batch of an attack run: the batch writer's rules, its slots written by AttackPathWriter."""

    _maps_each_card = False  # the saved set's controls are picked in one AI call

    def _build_path_writer(self, chat: ChatModel, library: ThreatLibrary, style: c.WriterStyle) -> PathWriter:
        return AttackPathWriter(self._lease, self._run, chat, library, self._progress, self._replaces, self._regenerate)
