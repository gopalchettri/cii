"""What tsg_scenarios stores for one path (tsg_scenarios), built by code from the
frozen plan, the brief and the draft the writer kept: the written (or blocked) scenario, or its failure card.
No database call here."""

import itertools
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

from app.core.constants import Decision, RunKind, ScenarioStatus, Status
from app.engine.scenarios.writing.writing_prompts import WRITER_PROMPT_VERSION
from app.engine.shared.names import name_match_key, threat_name_without_code
from app.models.writing import PathFailure, WriterBrief, WrittenScenario

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
    status = ScenarioStatus.BLOCKED if written.blocked else ScenarioStatus.DONE
    content = {
        "title": draft.title,
        "statement": draft.statement,
        "risk_statement": draft.risk,
        "why_applies": brief.why_it_applies,
        "assumptions": list(draft.assumptions),
        **_threat_content(path, threat),
        "systems": _card_systems(run, path, brief, draft.entry_point),
        "route": {"status": written.route, "note": None},
        "prompt_version": WRITER_PROMPT_VERSION,
    }
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
            for actor in threat.get("actors") or []
        ],
    }
