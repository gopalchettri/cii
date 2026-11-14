"""Gate A/B check: the relevance gate's categories with the old and the new rules, on the same questions sent
at the same moment (owner rule: the model drifts within the hour), so a prompt change is kept only when it
helps.

For a stored run's frozen asset it rebuilds the gate's own questions (landscape, candidates, batches as the
app cuts them), then `--runs` times sends every question with both rules at once. It saves each raw verdict
and what each arm keeps: the new rules a category only when its "by" points to one of its acts; the old rules
every listed own category, and also those cut to the first 3 (the trim of 30 Oct, D69). `--facts` gives every
system production-style facts. The AI is asked with the scenario module's model outside any job, so no
earlier answer is reused. An independent reviewer then marks the categories (see `--out`).

From the project folder:
  .venv\\Scripts\\python scripts\\gate_ab_check.py --session <id> --old-rules old_gate.txt --out ab.json
      [--runs 3] [--facts]"""

import argparse
import json
import math
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pymongo import MongoClient  # noqa: E402

from app.ai import TruncatedAiAnswer  # noqa: E402
from app.container import get_library_search, get_scenario_chat_model  # noqa: E402
from app.core.asset_types import compatible_asset_types  # noqa: E402
from app.core.config import get_settings  # noqa: E402
from app.core.constants import AiTask, StrideCategory, ThreatFinding  # noqa: E402
from app.domain.scenario import plan  # noqa: E402
from app.domain.shared.names import threat_name_without_code  # noqa: E402
from app.models.scenario.asset_context import FrozenContext  # noqa: E402

#: Production-style facts for every system (`--facts`): what UAT and production record.
FACTS = {
    "description": "Platform operators use to monitor and control city traffic and coordinate incidents.",
    "technology_used": "Microsoft, SAP, Siemens",
    "vendor_name": "Siemens Mobility",
    "database_platforms": "Microsoft SQL Server",
    "saas_platform_list": "Microsoft 365",
    "public_cloud_platforms": "Microsoft Azure",
    "accessability_channel": "Web portal, VPN",
    "hosting_location": "On-premises data centre",
    "managed_by": "Third-party vendor",
    "backup_multi_site": "Yes",
    "offsite_air_gapped_backup": "No",
}


def load_context(session_id: str, with_facts: bool) -> FrozenContext:
    """The run's frozen asset, its systems given production-style facts when asked."""
    settings = get_settings()
    db: Any = MongoClient(settings.mongo_url)[settings.mongo_db]
    found = db.tsg_sessions.find_one({"_id": session_id}, {"context": 1})
    if found is None:
        raise SystemExit(f"no stored run {session_id}")
    record = found["context"]
    if with_facts:
        record["systems"] = [system | FACTS for system in record["systems"]]
    return FrozenContext.from_record(record)


def build_questions(context: FrozenContext, chat: Any) -> tuple[Any, list[list[dict[str, Any]]]]:
    """The landscape and the gate's batches of candidates, as the app builds them."""
    library = get_library_search().snapshot(wait=True).library.threat_library
    allowed = compatible_asset_types(
        context.asset.get("category_code"), (system.get("category_code") for system in context.systems)
    )
    fitting = plan._list_threats_to_check(library.threats, allowed, [])
    landscape = plan.describe_asset_for_ai(
        context, chat.max_prompt_chars // 2, get_settings().context_country
    )
    items = [
        {
            "slot": f"{ThreatFinding.RECORD_SLOT}{number}",
            "threat_type": threat_name_without_code(threat.type_name),
            "threat": threat_name_without_code(threat.name),
            "categories": [str(category) for category in threat.categories],
            "attackers": [actor.name for actor in threat.linked_actors],
        }
        for number, threat in enumerate(fitting, start=1)
    ]
    size = math.ceil(len(items) / math.ceil(len(items) / ThreatFinding.THREATS_PER_QUESTION))
    return landscape, [items[start : start + size] for start in range(0, len(items), size)]


def keep_kinds(verdict: dict[str, Any], candidate: dict[str, Any]) -> dict[str, list[str]]:
    """What each arm keeps of one verdict: proved (new), every listed own one (old), the old cut to 3."""
    listed = [entry for entry in verdict.get("categories") or [] if isinstance(entry, dict)]
    own = candidate["categories"]
    named, _ = plan._read_answer_categories(verdict["slot"], listed, own, verdict.get("actions"))
    old = [str(entry.get("name")) for entry in listed if str(entry.get("name")) in own]
    return {"new": [str(kind) for kind in named if kind in own], "old": old, "old_cut_to_3": old[:3]}


def ask(chat: Any, landscape: Any, rules: str, batch: list[dict[str, Any]]) -> dict[str, Any]:
    """One gate question with `rules`: its verdicts, seconds and answer size; a cut-off one as two halves, as
    the app asks it."""
    system, user = plan._build_threat_finding_prompt(
        landscape.text, StrideCategory, rules, "CANDIDATES", batch
    )
    started = time.perf_counter()
    try:
        answer = chat.ask_for_checked_json(AiTask.RELEVANCE_GATE, system, user, lambda _answer: [])
    except TruncatedAiAnswer:
        middle = len(batch) // 2
        halves = [ask(chat, landscape, rules, part) for part in (batch[:middle], batch[middle:])]
        verdicts = [verdict for half in halves for verdict in half["verdicts"]]
        chars = sum(half["answer_chars"] for half in halves)
        seconds = round(time.perf_counter() - started, 1)
        return {"seconds": seconds, "answer_chars": chars, "cut_off": True, "verdicts": verdicts}
    seconds = time.perf_counter() - started
    by_slot = {candidate["slot"]: candidate for candidate in batch}
    verdicts = []
    for verdict in answer.get("verdicts") or []:
        candidate = by_slot.get(verdict.get("slot"))
        if candidate is None:
            continue
        accepted = verdict.get("relevant") is True and not verdict.get("needs")
        verdicts.append(
            {
                "threat": candidate["threat"],
                "own": candidate["categories"],
                "accepted": accepted,
                "raw": verdict,
            }
            | ({"kept": keep_kinds(verdict, candidate)} if accepted else {})
        )
    return {"seconds": round(seconds, 1), "answer_chars": len(json.dumps(answer)), "verdicts": verdicts}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--session", required=True, help="a stored run whose frozen asset is asked about")
    parser.add_argument("--old-rules", required=True, help="a file holding the old [scenario.gate] text")
    parser.add_argument("--out", required=True)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--facts", action="store_true", help="give every system production-style facts")
    args = parser.parse_args(argv)
    rules = {"old": Path(args.old_rules).read_text(encoding="utf-8"), "new": plan._GATE_RULES}
    chat = get_scenario_chat_model()
    landscape, batches = build_questions(load_context(args.session, args.facts), chat)
    asks = [(run, arm, number) for run in range(args.runs) for arm in rules for number in range(len(batches))]
    with ThreadPoolExecutor(2 * len(batches)) as pool:  # each run's old and new questions at the same moment
        answers = list(pool.map(lambda ask_: ask(chat, landscape, rules[ask_[1]], batches[ask_[2]]), asks))
    rows = [
        {"run": run, "arm": arm, "batch": number} | answer
        for (run, arm, number), answer in zip(asks, answers, strict=True)
    ]
    Path(args.out).write_text(json.dumps({"facts": args.facts, "rows": rows}, indent=1), encoding="utf-8")
    print(f"{len(rows)} questions answered, saved to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
