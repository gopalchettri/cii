"""Which of a scenario's reranked candidate controls it keeps (owner 2026-10-13, G225: "maximize control
relevance and risk mitigation effectiveness, not to achieve a fixed control count at the expense of
quality"; G227: "controls cannot be zero. if there are no match, control which is near possible match will be
used").

Best first, twins folded (the same id, or the same text: an IT and an OT copy). Every control at or above the
threshold is "strong", at most MAX_CONTROLS of them (how many more there were is recorded). Fewer than
MIN_CONTROLS strong: the nearest below the threshold are added as "fallback" to reach it, so a scenario with
any compatible candidate is never left without a control; fewer compatible candidates than MIN_CONTROLS is
recorded as a shortfall. Every score is the reranker's 0-100 relevance (the models give 0-1, multiplied once
in app/ai/rerank.py), so one threshold reads the same for every reranker."""

from dataclasses import replace

from app.core.config import get_settings
from app.core.constants import ControlMatch, ControlMessage
from app.engine.shared.names import name_match_key
from app.models.controls import ControlMapping, ControlRule, MappedControl
from app.models.library import LibraryControl
from app.search.texts import describe_control

Scored = list[tuple[LibraryControl, float]]


def control_rule() -> ControlRule:
    """The rule the settings give: CONTROL_SIMILARITY_THRESHOLD, CONTROL_CANDIDATES, MIN_/MAX_CONTROLS."""
    settings = get_settings()
    return ControlRule(
        settings.control_similarity_threshold,
        settings.control_candidates,
        settings.min_controls,
        settings.max_controls,
    )


def select_controls(scored: Scored, rule: ControlRule, query: str) -> tuple[ControlMapping, list[str]]:
    """(the mapping, the twins' codes folded away). `scored`: each compatible candidate with its 0-100 score
    (at least one: no compatible candidate at all is the caller's no_compatible_control)."""
    unique, twins = _without_twins(sorted(scored, key=lambda pair: (-pair[1], pair[0].control_id)))
    strong = [(control, score) for control, score in unique if score >= rule.cutoff]
    kept = strong[: rule.most]
    room = max(min(rule.least, rule.most) - len(kept), 0)
    fallback = [(control, score) for control, score in unique if score < rule.cutoff][:room]
    chosen = [_mapped(c, s, ControlMatch.EXACT, rule) for c, s in kept]
    chosen += [_mapped(c, s, ControlMatch.NEAREST, rule) for c, s in fallback]
    items = tuple(replace(item, rank=rank) for rank, item in enumerate(chosen, 1))
    warning = None if kept else ControlMessage.NEAREST_ONLY.format(cutoff=rule.cutoff, least=rule.least)
    short = (
        ControlMessage.SHORTFALL.format(kept=len(items), least=rule.least)
        if len(items) < rule.least
        else None
    )
    return ControlMapping(items, query, warning, short, len(strong) - len(kept)), twins


def _without_twins(ordered: Scored) -> tuple[Scored, list[str]]:
    """The best of each control: the same id, then the same text (an IT and an OT copy), once."""
    seen: set[object] = set()
    unique: Scored = []
    twins: list[str] = []
    for control, score in ordered:
        keys = {control.control_id, name_match_key(describe_control(control))}
        if keys & seen:
            twins.append(control.code)
            continue
        seen |= keys
        unique.append((control, score))
    return unique, twins


def _mapped(control: LibraryControl, score: float, match: ControlMatch, rule: ControlRule) -> MappedControl:
    reason = (
        ControlMessage.STRONG_REASON.format(score=score, cutoff=rule.cutoff)
        if match is ControlMatch.EXACT
        else ControlMessage.FALLBACK_REASON.format(score=score, cutoff=rule.cutoff, least=rule.least)
    )
    fields = (control.control_id, control.code, control.name, control.domain, control.asset_type)
    return MappedControl(*fields, 0, score, match, control.description, reason)
