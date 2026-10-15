"""What tsg_scenarios stores for one path (tsg_scenarios), built by code from the
frozen plan, the brief and the draft the writer kept: the written (or blocked) scenario, or its failure card.
No database call here."""

import itertools
import uuid
from collections import Counter
from collections.abc import Iterator, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from app.core.constants import (
    ActorRole,
    Decision,
    EvidenceMode,
    KnownGroupMatch,
    KnownGroups,
    RunKind,
    ScenarioStatus,
    Status,
    StoryLimits,
    WriterStyle,
)
from app.engine.scenarios.writing.evidence_citations import renumber_citations
from app.engine.scenarios.writing.writing_prompts import WRITER_PROMPT_VERSION
from app.engine.shared.names import name_match_key, threat_name_without_code
from app.models.writing import PathFailure, ScenarioDraft, WriterBrief, WrittenScenario

#: A path's first scenario is version 1; a regenerated one (#6) is the next version of its path.
FIRST_VERSION = 1


def scenario_id(session_id: str, path_id: str, version: int) -> str:
    """The same run, path and version always give the same id: a repeated delivery saves once, and a path's
    later success replaces its failure card."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"tsg:{session_id}:{path_id}:{version}"))


def title_candidates(title: str, qualifier: str) -> Iterator[str]:
    """`title`, then `title (qualifier)` (the threat's name, owner 2026-10-06), then `title (2)`, `(3)` ...
    for when another scenario of the run already took each."""
    yield title
    if qualifier and name_match_key(qualifier) not in name_match_key(title):
        yield f"{title} ({qualifier})"
    for number in itertools.count(2):
        yield f"{title} ({number})"


def written_record(
    run: dict[str, Any],
    path: dict[str, Any],
    threat: dict[str, Any],
    brief: WriterBrief,
    written: WrittenScenario,
    replaces: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """A written scenario (status done), or one kept for audit only (status blocked: never served, counted or
    mapped to controls). Its controls wait for the controls job (Step 13). `replaces`: the version a
    regenerate (#6) writes the next version of ({_id, version}); None for a path's first write."""
    draft, now = written.draft, datetime.now(UTC)
    statement, risk, evidence = _cited(brief, draft)
    # G229: an evidence story with no source at all is never finished; one citing none of its sources shows
    # the closest instead (G250, G254), so only a threat whose search kept nothing is unproven (the gate stops
    # it before writing).
    unproven = brief.style is WriterStyle.EVIDENCE_STORY and not evidence and not _related(brief, threat)[0]
    status = ScenarioStatus.BLOCKED if written.blocked or unproven else ScenarioStatus.DONE
    content = {
        "title": draft.title,
        "statement": statement,
        "risk_statement": risk,
        "why_applies": brief.why_it_applies,
        "assumptions": list(draft.assumptions),
        "anatomy": draft.anatomy.as_doc() if draft.anatomy else None,  # G229: its parts, as written
        **_threat_content(path, threat),
        **_systems_content(run, path, brief, draft),
        "route": {"status": written.route, "note": None},
        "prompt_version": prompt_version_of(brief.style),
    } | _evidence_content(brief, threat, evidence)
    record = _record_fields(run, path, status, now, replaces) | {
        "title_key": name_match_key(draft.title),
        "content": content,
        "findings": [finding.to_record() for finding in written.findings],
        "plan_check": written.plan_check.to_record(),
        "rewritten": written.rewritten,
    }
    if status == ScenarioStatus.DONE:
        record["controls"] = {"status": Status.QUEUED, "attempts": 0, "queued_at": now}
    return record


def prompt_version_of(style: WriterStyle) -> str:
    """Which prompts wrote a scenario: a regenerate reads it back to keep the scenario's style."""
    return StoryLimits.PROMPT_VERSION if style is WriterStyle.EVIDENCE_STORY else WRITER_PROMPT_VERSION


def style_of_version(prompt_version: str | None) -> WriterStyle:
    """The style a stored scenario was written in (a scenario with no version, or an older one: original)."""
    return (
        WriterStyle.EVIDENCE_STORY if prompt_version == StoryLimits.PROMPT_VERSION else WriterStyle.ORIGINAL
    )


def _cited(brief: WriterBrief, draft: ScenarioDraft) -> tuple[str, str, list[dict[str, Any]]]:
    """An evidence story's statement and risk with its citations renumbered from [1], and the evidence they
    cite (G224); a scenario written in the original style cites none."""
    if brief.style is not WriterStyle.EVIDENCE_STORY:
        return draft.statement, draft.risk, []
    evidence = [dict(item) for item in brief.evidence]
    return renumber_citations(draft.statement, draft.risk, evidence, dict(draft.evidence_links))


def _evidence_content(
    brief: WriterBrief, threat: dict[str, Any], cited: list[dict[str, Any]]
) -> dict[str, Any]:
    """The proof an evidence story carries: each entry its text cites, under the number its markers use
    (G224); citing none, the closest source as related intelligence, never numbered (G250, owner
    2026-10-15: "if no citation is found suggest the nearest possible one"); how the story rests on it, how
    many vulnerabilities apply, and the audit of the search. Nothing is added to an original-style
    scenario."""
    if brief.style is not WriterStyle.EVIDENCE_STORY:
        return {}
    applies = Counter(str(item["applicability"]) for item in cited if item.get("applicability"))
    related, mode = ([], brief.evidence_mode) if cited else _related(brief, threat)
    return {
        "evidence": cited,
        "related_evidence": related,
        "evidence_mode": mode,
        "applicability": dict(applies),
        "intel_search": threat.get("intel_search"),
        "known_groups": _known_groups(threat, cited),
    }


def _related(brief: WriterBrief, threat: dict[str, Any]) -> tuple[list[dict[str, Any]], EvidenceMode]:
    """What a story citing none of its sources shows instead: its best source (G250, "related"); when no
    source passed the relevance check, the closest match its search kept (G254, "nearest"); else nothing."""
    if brief.evidence:
        return [_closest(brief.evidence)], EvidenceMode.RELATED
    nearest = threat.get("nearest_evidence") or []
    return ([dict(nearest[0])], EvidenceMode.NEAREST) if nearest else ([], EvidenceMode.INFERRED)


def _closest(evidence: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """The source the search scored highest (G250), as searched: no number, no claim (none cites it)."""
    best = max(evidence, key=lambda item: float(item.get("score") or 0.0))
    return dict(best)


def _known_groups(threat: dict[str, Any], cited: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """G230: the real named groups behind the threat's evidence, each with the number its technique is cited
    under (None: the story did not cite it). G235: picked for what the story cites, now that it is written:
    groups behind a cited technique first ("used this attack [n]"); a group behind a technique the card does
    not show used a related attack, never "this" one; the search order (UAE, region, sector) kept within."""
    numbers = {item.get("ref"): item["n"] for item in cited}
    groups = []
    for group in threat.get("known_groups") or []:
        number = numbers.get(group.get("technique"))
        match = group.get("match")
        if number is None and match == KnownGroupMatch.USED_THIS_TECHNIQUE:
            match = KnownGroupMatch.USED_RELATED_TECHNIQUE
        groups.append(group | {"cited": number, "match": match})
    return sorted(groups, key=lambda group: group["cited"] is None)[: KnownGroups.SHOWN]


def _card_systems(
    run: dict[str, Any], path: dict[str, Any], brief: WriterBrief, entry_point: str
) -> list[dict[str, Any]]:
    """Each system by its recorded name, never the prompt's redacted one ("scada01.plant.local" reaches the
    AI as [REDACTED]); the entry point by its place in the brief, so two systems redacted alike are never
    both marked ("" = the asset itself: none is)."""
    names = {system["id"]: system["name"] for system in run["context"]["systems"]}
    entry = brief.entry_point_options.index(entry_point) if entry_point else -1
    return [
        {"id": system_id, "name": names[system_id], "entry_point": place == entry}
        for place, system_id in enumerate(path["systems"])  # in the brief's order: the path's systems
    ]


def _systems_content(
    run: dict[str, Any], path: dict[str, Any], brief: WriterBrief, draft: ScenarioDraft
) -> dict[str, Any]:
    """The card's own systems with the entry point (`systems`, as before), and every supporting system of the
    run (`system_applicability`, G216): applicable when the scenario's route goes through it (code), the
    entry point among them, and the writer's one-sentence reason; by its recorded name."""
    card = _card_systems(run, path, brief, draft.entry_point)
    names = {system["id"]: system["name"] for system in run["context"]["systems"]}
    entry = {system["id"] for system in card if system["entry_point"]}
    reasons = dict(draft.system_reasons)  # by the brief's spelling of each name
    every = [
        {
            "id": system.id,
            "name": names.get(system.id, system.name),
            "applicable": system.applicable,
            "entry_point": system.id in entry,
            "reason": reasons.get(system.name, ""),
        }
        for system in brief.supporting_systems
    ]
    return {"systems": card, "system_applicability": every}


def failure_record(
    run: dict[str, Any], path: dict[str, Any], threat: dict[str, Any] | None, failure: PathFailure
) -> dict[str, Any]:
    """A visible failure card: what was to be written and why it could not be."""
    content = _threat_content(path, threat) if threat is not None else _category(path)
    return _record_fields(run, path, ScenarioStatus.FAILED, datetime.now(UTC)) | {
        "content": content,
        "findings": [],
        "failure": {"code": failure.code, "message": failure.message},
    }


def _record_fields(
    run: dict[str, Any],
    path: dict[str, Any],
    status: ScenarioStatus,
    now: datetime,
    replaces: dict[str, Any] | None = None,
) -> dict[str, Any]:
    version = FIRST_VERSION if replaces is None else replaces["version"] + 1
    return {
        "_id": scenario_id(run["_id"], path["path_id"], version),
        "session_id": run["_id"],
        "entity_id": run["entity_id"],
        "asset_id": run["asset_id"],
        "path_id": path["path_id"],
        "version": version,
        "source": RunKind.GENERATED,
        "status": status,
        "decision": Decision.PENDING,
        "decided_by": None,
        "decided_at": None,
        "replaces": None if replaces is None else replaces["_id"],
        "superseded_by": None,
        "created_at": now,
        "updated_at": now,
    }


def _category(path: dict[str, Any]) -> dict[str, Any]:
    """The card's category and its library id, as the plan froze them."""
    return {"category": path.get("category"), "category_id": path.get("category_id")}


def _threat_content(path: dict[str, Any], threat: dict[str, Any]) -> dict[str, Any]:
    """The path's category and threat, and the threat's attackers (the acting one first). Read with care: a
    failure card is written for a path whose threat may lack a name, a type or an attacker."""
    threat_type = threat.get("type") or {}
    return _category(path) | {
        "contributing_categories": (path.get("categories") or [])[1:],
        "threat": {
            "key": threat.get("key"),
            "type": threat_name_without_code(threat_type.get("name") or ""),
            "name": threat_name_without_code(threat.get("name") or ""),
            "library_id": threat.get("library_id"),
            "ai_generated": threat.get("ai_generated"),
            # Tracked for the results (owner 2026-10-12): the library type's id, the relevance check's
            # confidence (0-100) and the path's rank in the plan (1 = most relevant).
            "type_id": threat_type.get("id"),
            "confidence": threat.get("confidence"),
            "rank": path.get("rank"),
        },
        # The other threats of the same kind of attack on the same system (owner 2026-10-12): not lost.
        "also_applies": list(path.get("also_applies") or []),
        "actors": [
            {key: actor.get(key) for key in ("id", "name", "role", "closest", "below_threshold")}
            | (_why_acting(threat) if actor.get("role") == ActorRole.ACTING else {})
            for actor in threat.get("actors") or []
        ],
    }


def _why_acting(threat: dict[str, Any]) -> dict[str, Any]:
    """How the acting attacker was decided and why (G229): the card shows it, the audit keeps it."""
    return {"selection": threat.get("attacker_check"), "reason": threat.get("attacker_check_reason")}
