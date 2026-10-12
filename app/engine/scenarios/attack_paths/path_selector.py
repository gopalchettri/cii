"""Attack-path selection: one path per kind of attack on each system (path_grouping.py, owner 2026-10-12;
the AI never joins threats into chains), paths that are one attack through several systems merged into one
(same_scenario.py, G213), every path ranked (path_ranking.py), TOTAL_SCENARIO_COUNT applied, and the plan the
run freezes."""

from collections import Counter
from typing import Any

from app.ai import get_chat_model
from app.core.config import get_settings
from app.core.constants import GapFillOutcome, UnselectedReason
from app.core.singletons import singleton
from app.core.tracing import record_detail, step_detail_enabled, traced
from app.engine.scenarios.attack_paths.best_threat import BestThreatPicker
from app.engine.scenarios.attack_paths.path_grouping import group_by_attack_and_system
from app.engine.scenarios.attack_paths.path_ranking import rank_paths
from app.engine.scenarios.attack_paths.same_scenario import SameScenarioCheck
from app.engine.scenarios.finding.threat_prompts import PLANNER_PROMPT_VERSION
from app.models.threats import AttackPath, FoldedThreat, ThreatFindings


@traced("paths.apply_target")
def select_up_to_target(paths: list[dict[str, Any]], max_scenarios: int) -> list[dict[str, Any]]:
    """`paths` = every valid attack path found (the total count), each with its `rank` (1 = most relevant)
    and its `choice` (the last step's category). The plan keeps every path,
    They are sorted most relevant first, then:
    - max_scenarios 0 → no target: every path is selected;
    - max_scenarios N > 0 → the N most relevant are selected; the rest are kept in the plan, not selected,
      with reason target_reached;
    - fewer than N found → every path found is selected and nothing is added: the target never invents a
      scenario to reach N."""
    ranked = sorted(paths, key=lambda path: path["rank"])
    keep = len(ranked) if max_scenarios == 0 else max_scenarios
    return [
        {**path, "selected": True}
        if position < keep
        else {**path, "selected": False, "unselected_reason": UnselectedReason.TARGET_REACHED}
        for position, path in enumerate(ranked)
    ]


class AttackPathSelector:
    def __init__(
        self,
        target: int,
        picker: BestThreatPicker | None = None,
        same_scenarios: SameScenarioCheck | None = None,
    ) -> None:
        """`target`: TOTAL_SCENARIO_COUNT (0 = no cap). `picker`: chooses each path's threat by meaning
        (G209); None = the strongest by impact and confidence, with no AI call (the same threats, the same
        plan). `same_scenarios`: merges paths that are one attack through several systems (G213); None =
        none merged."""
        self._target, self._picker, self._same_scenarios = target, picker, same_scenarios

    @traced("paths.plan")
    def build_plan(self, findings: ThreatFindings) -> dict[str, Any]:
        """The plan: every threat once, one path per kind of attack on each system (its other threats
        kept with it), ranked and selected or not, the categories' records and every note. The worker stamps
        it frozen and saves it with the hand-over."""
        grouped, notes, merges = self._scenarios(findings)
        paths = [path for path, _ in grouped]
        also_applies = {path.path_id: others for path, others in grouped}
        ranked = [
            _path_record(path, rank, choice, findings.category_ids)
            | {"also_applies": also_applies[path.path_id]}
            for rank, (path, choice) in enumerate(rank_paths(paths), 1)
        ]
        covered = {category for path in paths for category in path.categories}
        uncovered = [audit for audit in findings.audits if audit.category not in covered]
        selected = select_up_to_target(ranked, self._target)
        if step_detail_enabled():
            _trace_selection(selected, self._target)
        return {
            "prompt_version": PLANNER_PROMPT_VERSION,
            "threats": [threat.to_record() for threat in findings.threats],
            "paths": selected,
            "target": self._target,
            "notes": [*findings.notes, *notes],
            # Not fully assessed (a technical gap, so the run is partial): no path because never assessed, or
            # threats left not judged though its others gave it a path (G210). Else no path: nothing valid.
            "not_assessed": [
                a.category
                for a in findings.audits
                if a.not_judged or (a.category not in covered and a.gap_fill == GapFillOutcome.NOT_ASSESSED)
            ],
            "no_valid_threat": [a.category for a in uncovered if a.gap_fill != GapFillOutcome.NOT_ASSESSED],
            "categories": [audit.to_record() for audit in findings.audits],
            "folded": [_folded_record(fold) for fold in findings.folded],
            "merged": merges,  # G213: each scenario merged from one attack through several systems, and why
        }

    def _scenarios(
        self, findings: ThreatFindings
    ) -> tuple[list[tuple[AttackPath, list[str]]], list[str], list[dict[str, Any]]]:
        """(each scenario's path and its other threats' names, the notes, the merges): one per kind of attack
        on each system around its best threat (G208, G209), those that are one attack through several systems
        merged (G213)."""
        preferred, notes = (
            self._picker.pick(findings.threats, findings.landscape) if self._picker else ({}, [])
        )
        grouped = group_by_attack_and_system(findings.threats, preferred)
        if not self._same_scenarios:
            return grouped, notes, []
        grouped, merge_notes, merges = self._same_scenarios.merge(
            grouped, findings.threats, findings.landscape
        )
        return grouped, [*notes, *merge_notes], merges


def _trace_selection(paths: list[dict[str, Any]], target: int) -> None:
    """How many paths the target selected, and why the rest were not."""
    reasons = Counter(str(path["unselected_reason"]) for path in paths if not path["selected"])
    record_detail(
        "selected",
        given={"paths": len(paths), "target": target},
        produced={
            "selected": len(paths) - reasons.total(),
            "not_selected": reasons.total(),
            "reasons": dict(reasons) or "none",
        },
    )


def _path_record(path: AttackPath, rank: int, choice: str, category_ids: dict[str, int]) -> dict[str, Any]:
    """A path as the plan holds it: its threats by key (plan.threats has each once), the card's category from
    its LAST step (with its library id: `category_ids` by lower-case name), the rest of its categories after
    the first step's."""
    category = path.steps[-1].categories[0]
    return {
        "path_id": path.path_id,
        "rank": rank,
        "choice": choice,
        "served": None,
        "attempts": 0,
        "abandoned": False,
        "steps": [step.key for step in path.steps],
        "category": category,
        "category_id": category_ids.get(category.lower()),
        "categories": list(path.categories),
        "systems": list(path.systems),
        "impact": path.impact,
        "confidence": path.confidence,
    }


def _folded_record(fold: FoldedThreat) -> dict[str, Any]:
    return {
        "key": fold.threat.key,
        "name": fold.threat.name,
        "kept": fold.kept_key,
        "reason": fold.reason,
        "score": fold.score,
        "why": fold.why,
    }


@singleton
def get_attack_path_selector() -> AttackPathSelector:
    chat = get_chat_model()
    return AttackPathSelector(
        get_settings().total_scenario_count, BestThreatPicker(chat), SameScenarioCheck(chat)
    )
