"""The owner's check of every card a run serves (2026-10-18): an acting attacker the plan listed for its
threat, the reviewer's verdicts that the scenario tells its threat and the risk its impact, the evidence
(cited with external intelligence on, none with it off) and no duplicate. Blocked records are listed with
why, for review. Read-only: no AI call, nothing written.

From the project folder: .venv\\Scripts\\python scripts\\scorecard.py [run id]   (default: TSG_RUN_ID in
debug/.env). Exit 1 when any served card fails."""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from debug_tools import debug_value  # noqa: E402  (scripts/ is on the path: this script's own folder)


def actor(card: dict[str, Any], threats: dict[str, dict[str, Any]]) -> str:
    """An acting attacker, named, that the run's plan listed for the card's threat (`threats`: by key)."""
    content = card["content"]
    acting = next((a for a in content.get("actors") or [] if a.get("role") == "acting"), None)
    if not (acting and acting.get("name")):
        return "no acting threat actor"
    listed = (threats.get((content.get("threat") or {}).get("key")) or {}).get("actors") or []
    if acting.get("id") not in {listed_actor.get("id") for listed_actor in listed}:
        return f"{acting['name']} is not an attacker the plan listed for its threat"
    return ""


def threat(card: dict[str, Any]) -> str:
    return _verdict(card, "same_threat", "the statement tells another threat")


def risk(card: dict[str, Any]) -> str:
    return _verdict(card, "same_impact", "the risk tells another impact")


def _verdict(card: dict[str, Any], verdict: str, wrong: str) -> str:
    """The reviewer's verdict; a check not made stores none, so correctness is not established."""
    value = (card.get("plan_check") or {}).get(verdict)
    if value is None:
        return "no reviewer verdict recorded: correctness not established"
    return "" if value else wrong


def evidence(card: dict[str, Any]) -> str:
    """With intelligence on (an evidence story), one or more markers, each naming a stored entry; with it
    off, no marker and no entry."""
    from app.core.constants import StoryLimits
    from app.models.external_intelligence.evidence_view import markers_of

    content = card["content"]
    cited = set(markers_of(f"{content.get('statement', '')}\n{content.get('risk_statement', '')}"))
    entries = content.get("evidence") or []
    if content.get("prompt_version") != StoryLimits.PROMPT_VERSION:
        return f"cites {sorted(cited)} with intelligence off" if cited or entries else ""
    if not cited:
        return "cites no evidence"
    unknown = sorted(n for n in cited if not 1 <= n <= len(entries))
    return f"markers {unknown} name no stored source" if unknown else ""


CHECKS: dict[str, Callable[[dict[str, Any]], str]] = {
    "threat": threat, "risk": risk, "evidence": evidence,
}  # fmt: skip


def served_cards(cards: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The written cards the run's results serve (list_for_run, CURRENT_VERSIONS): each path's newest version
    and any older one a reviewer decided (an accepted one stays listed after its path was regenerated)."""
    from app.core.constants import Decision

    return [
        c
        for c in cards
        if c.get("status") == "done"
        and (c.get("superseded_by") is None or c.get("decision") != Decision.PENDING)
    ]


def duplicates(served: list[dict[str, Any]]) -> dict[str, str]:
    """Each served card that copies an earlier one of another path the run still holds: the same threat key,
    kind and systems, or the same statement (the app's own duplicate_of). The run holds find_finished's
    register (MAPPED_VERSIONS): a replaced rejected version is served but has left it."""
    from app.core.constants import Decision
    from app.domain.scenario.write import duplicate_of

    found: dict[str, str] = {}
    for index, card in enumerate(served):
        held = [
            c
            for c in served[:index]
            if c.get("superseded_by") is None or c.get("decision") == Decision.ACCEPTED
        ]
        if copy := duplicate_of(card["content"], card["path_id"], held, ()):
            found[card["_id"]] = copy.message
    return found


def main() -> int:
    from app.core.constants import Collection
    from app.core.database import get_mongodb

    run_id = (sys.argv[1] if len(sys.argv) > 1 else "") or debug_value("TSG_RUN_ID")
    db = get_mongodb()
    run = db[Collection.SESSIONS].find_one({"_id": run_id}, {"plan.threats.key": 1, "plan.threats.actors": 1})
    if not run:
        raise SystemExit(f"  No run '{run_id}'.")
    threats = {threat["key"]: threat for threat in (run.get("plan") or {}).get("threats") or []}
    cards = list(db[Collection.SCENARIOS].find({"session_id": run_id}).sort("created_at", 1))
    served = served_cards(cards)
    copies = duplicates(served)
    failed = 0
    print(f"  run {run_id}: {len(served)} served cards\n")
    for card in served:
        faults = {"actor": why} if (why := actor(card, threats)) else {}
        faults |= {name: why for name, check in CHECKS.items() if (why := check(card))}
        faults |= {"duplicate": copies[card["_id"]]} if card["_id"] in copies else {}
        failed += bool(faults)
        name = (card["content"].get("threat") or {}).get("name", "")[:48]
        print(
            f"  {'FAIL' if faults else 'pass'}  {name:48}  "
            + "; ".join(f"{k}: {v}" for k, v in faults.items())
        )
    review = [c for c in cards if c.get("status") != "done"]
    print(f"\n  {len(served) - failed} of {len(served)} served cards pass every check")
    print(f"  {len(review)} record(s) held back for review:")
    for card in review:
        blockers = [f["code"] for f in card.get("findings") or [] if f.get("severity") == "blocker"]
        reason = ", ".join(blockers) or ((card.get("failure") or {}).get("message") or card.get("status"))
        name = (card["content"].get("threat") or {}).get("name", "")[:45]
        print(f"    {card.get('status'):8} {name:45}  {reason}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
