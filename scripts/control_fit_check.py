"""Control fit check: whether a threat scenario's controls reduce its risk, today and in two other ways, on
the same fixed scenarios, so the owner can pick a way (plan of 2026-10-31).

For the newest scenarios of each STRIDE category (one per threat, each with a full candidate shortlist) it
builds four control lists:
  today        the controls the scenario got, as stored
  no_category  today's search text without its "Category:" line, re-scored on the stored candidates
  way_a        the AI chooses 3-5 codes from the library's codes and names (10 scenarios per call)
  way_b        the AI writes 3-5 "what would stop it" lines (10 per call); each line searches the library on
               its own and keeps its best control
ONE AI reviewer (10 scenarios per call) then marks every control of every list, mixed so it cannot tell the
lists apart: fits, partly or no. It prints each list's fit, overall and per category, how many way_a and
way_b controls score below the threshold on the whole scenario (they would show as "nearest"), and the AI
calls and tokens used: about 9 calls for 30 scenarios.

Reads the scenarios (MongoDB) and the control library (SQL Server) and writes nothing to them. The AI is
called directly with the scenario module's settings, so no usage row or call text is stored.
ponytail: the local reranker only, and way_b scores every library control of the scenario's asset types per
line (the app first narrows to the CONTROL_CANDIDATES closest by meaning); add the proxy reranker and that
first step to run it on UAT.

From the project folder:
  .venv\\Scripts\\python scripts\\control_fit_check.py [--per-category 5] [--out control_fit.json]"""

import argparse
import json
import sys
from collections import Counter, defaultdict
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

import litellm  # noqa: E402
from pymongo import MongoClient  # noqa: E402

from app.ai.chat_messages import build_request_options  # noqa: E402
from app.ai.common import build_api_key_header  # noqa: E402
from app.ai.module_chat import module_chat  # noqa: E402
from app.ai.profiles import CHAT_MODEL_PROFILES, find_model_profile  # noqa: E402
from app.core.asset_types import asset_type_fits, asset_type_label  # noqa: E402
from app.core.config import get_settings  # noqa: E402
from app.core.constants import AiTask  # noqa: E402
from app.core.constants.ai_limits import ChatModule  # noqa: E402
from app.domain.scenario.controls import select_controls  # noqa: E402
from app.domain.shared.names import name_match_key  # noqa: E402
from app.models.library.library import LibraryControl  # noqa: E402
from app.models.scenario.controls import ControlRule  # noqa: E402
from app.search.texts import describe_control  # noqa: E402

CATEGORIES = (
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
)
LISTS = ("today", "no_category", "way_a", "way_b")
MARKS = ("fits", "partly", "no")
BATCH = 10
DESCRIPTION_CHARS = 220
Scorer = Callable[[str, list[str]], list[float]]

WAY_A_PROMPT = """You choose security controls from a control LIBRARY for threat scenarios. For each scenario,
choose 3 to 5 LIBRARY controls that most directly prevent, detect or recover from its attack steps or the harm
in its risk statement, on its systems. Prefer a specific technical or operational control to generic
governance (risk assessment, threat intelligence, awareness) unless the scenario is about that. Codes only
from LIBRARY, verbatim; never invent one.
Return ONLY JSON: {"scenarios": [{"id": <id>, "controls": ["<code>", ...]}]}"""

DEFENCES_PROMPT = """For each threat scenario, write "defences": 3 to 5 lines, each ONE common security
measure that would prevent, detect or recover from a step of its attack or the harm in its risk statement, on
its systems. Each line 4 to 10 plain words, the measure as a security control library names it (e.g. "lock
accounts after repeated failed log-ins", "require MFA for operator log-ins", "block malware on workstations",
"back up controller configurations"). No new or unusual technology, product, vendor, tool or control code;
never the same idea twice.
Return ONLY JSON: {"scenarios": [{"id": <id>, "defences": ["<line>", ...]}]}"""

REVIEW_PROMPT = """You are a CII security reviewer. For each threat scenario, mark EVERY listed control on its
own: "fits" = it directly prevents, detects or recovers from this scenario's attack steps or the harm in its
risk statement; "partly" = it helps, but indirectly or for only a small part; "no" = generic, unrelated or
about something else. The list order means nothing.
Return ONLY JSON: {"scenarios": [{"id": <id>, "marks": {"<code>": "fits" | "partly" | "no"}}]}"""


def load_scenarios(per_category: int, most: int) -> list[dict[str, Any]]:
    """The newest scenarios of each category, one per threat, mapped with today's MAX_CONTROLS and a full
    shortlist (read only)."""
    settings = get_settings()
    db = MongoClient(settings.mongo_url)[settings.mongo_db]
    query = {
        "controls.status": "done",
        f"controls.shortlist.{settings.control_candidates - 1}": {"$exists": True},
        "controls.made_with.max_controls": most,
        "content.title": {"$ne": None},
    }
    fields = ("content.title", "content.category", "content.statement", "content.risk_statement")
    projection = dict.fromkeys((*fields, "content.threat", "controls"), 1)
    picked: list[dict[str, Any]] = []
    for category in CATEGORIES:
        threats: set[str] = set()
        cursor = db.tsg_scenarios.find(query | {"content.category": category}, projection)
        for doc in cursor.sort("created_at", -1):
            threat = str((doc["content"].get("threat") or {}).get("name"))
            if threat not in threats:
                threats.add(threat)
                picked.append(doc)
            if len(threats) == per_category:
                break
    return picked


def control_rule() -> ControlRule:
    """The rule the settings give (the app's own: CONTROL_SIMILARITY_THRESHOLD, MIN_, MAX_ and so on)."""
    s = get_settings()
    return ControlRule(
        s.control_similarity_threshold,
        s.control_candidates,
        s.min_controls,
        s.max_controls,
        s.nearest_controls,
    )


def local_scorer() -> Scorer:
    """The local reranker (CII_RERANK_MODEL, a folder) as 0-100 scores, as the app scores."""
    settings = get_settings()
    if settings.rerank_base_url:
        raise SystemExit("This check runs the local reranker only: CII_RERANK_BASE_URL is set.")
    from sentence_transformers import CrossEncoder

    model = CrossEncoder(settings.rerank_model)

    def score(query: str, documents: list[str]) -> list[float]:
        pairs = [(query, document) for document in documents]
        return [100.0 * float(p) for p in model.predict(pairs, batch_size=64, show_progress_bar=False)]

    return score


def ask_ai(system: str, user: str, usage: Counter[str]) -> dict[str, Any]:
    """The scenario module's chat model's JSON answer, called directly (no usage row, no call text); one
    retry when the answer is not JSON."""
    settings = get_settings()
    chat = module_chat(settings, ChatModule.SCENARIO)
    key = chat.api_key.get_secret_value()
    profile = find_model_profile(CHAT_MODEL_PROFILES, chat.model)
    options = build_request_options(profile, AiTask.REMEDIATION_PLAN, chat.model, chat.model_thinking)
    messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
    for attempt in (1, 2):
        response = litellm.completion(
            model=chat.model,
            messages=messages,
            api_base=chat.base_url,
            api_key=key,
            **build_api_key_header(settings.ai_key_header, key),
            **options,
        )
        usage["calls"] += 1
        usage["tokens_in"] += response.usage.prompt_tokens
        usage["tokens_out"] += response.usage.completion_tokens
        text = response.choices[0].message.content or ""
        try:
            return json.loads(text[text.index("{") : text.rindex("}") + 1])
        except ValueError:
            if attempt == 2:
                raise
    return {}


def answers_by_id(answer: dict[str, Any], field: str, count: int) -> list[list[str]]:
    """Each scenario's list in `field` of the AI's {"scenarios": [{"id", field}]}, in batch order."""
    by_id = {
        str(entry.get("id")): [str(value) for value in entry.get(field) or []]
        for entry in answer.get("scenarios") or []
    }
    return [by_id.get(str(index), []) for index in range(1, count + 1)]


def scenario_text(doc: dict[str, Any], index: int) -> str:
    """One scenario as the AI reads it: its batch id (never a database id), title, story and risk."""
    content = doc["content"]
    return (
        f"id {index}\nTitle: {content.get('title')}\nScenario: {content.get('statement')}\n"
        f"Risk statement: {content.get('risk_statement')}"
    )


def search_text_without_category(doc: dict[str, Any]) -> str:
    """The scenario's stored search text without its "Category:" line."""
    lines = doc["controls"]["query"].split("\n")
    return "\n".join(line for line in lines if not line.startswith("Category:"))


def shortlist(doc: dict[str, Any], by_id: dict[int, LibraryControl]) -> list[LibraryControl]:
    """The scenario's stored candidates still in the library."""
    return [by_id[e["control_id"]] for e in doc["controls"]["shortlist"] if e["control_id"] in by_id]


def asset_pool(doc: dict[str, Any], by_id: dict[int, LibraryControl], library: Sequence[LibraryControl]):
    """The library controls of the scenario's asset types, read off its stored (type-filtered) candidates."""
    allowed = {asset_type_label(control.asset_type) for control in shortlist(doc, by_id)} - {None}
    return [control for control in library if asset_type_fits(control.asset_type, allowed)]


def no_category(doc, by_id, score: Scorer, rule: ControlRule) -> list[LibraryControl]:
    """Today's selection on the stored candidates, scored by the search text without its category line."""
    query, candidates = search_text_without_category(doc), shortlist(doc, by_id)
    scores = score(query, [describe_control(control) for control in candidates])
    mapping = select_controls(list(zip(candidates, scores, strict=True)), rule, query)
    return [by_id[item.control_id] for item in mapping.items]


def best_per_line(
    lines: Sequence[str], pool: Sequence[LibraryControl], score: Scorer, most: int
) -> list[LibraryControl]:
    """Each line's best-scored control of `pool`, in line order, no control (or IT/OT twin) twice, at most
    `most`."""
    texts = [describe_control(control) for control in pool]
    kept: list[LibraryControl] = []
    taken: set[str] = set()
    for line in lines:
        ranked = sorted(zip(pool, score(line, texts), strict=True), key=lambda pair: -pair[1])
        best = next((c for c, _ in ranked if name_match_key(describe_control(c)) not in taken), None)
        if best is not None:
            kept.append(best)
            taken.add(name_match_key(describe_control(best)))
        if len(kept) == most:
            break
    return kept


def chosen_codes(codes: Sequence[str], pool: Sequence[LibraryControl], most: int) -> list[LibraryControl]:
    """The AI's codes that name a control of `pool`, once each, in its order, at most `most`; an answer may
    carry the name after its code ("CID-0242 Multi-Factor Authentication (MFA)")."""
    by_code = {control.code.casefold(): control for control in pool}
    heads = [answer.split()[0].casefold() for answer in codes if answer.split()]
    return list(dict.fromkeys(by_code[head] for head in heads if head in by_code))[:most]


def review(batch: Sequence[dict[str, Any]], lists: Sequence[dict[str, list]], usage) -> list[dict[str, str]]:
    """The reviewer's mark per code for each scenario, every list's controls mixed and sorted by code."""
    parts = []
    for index, (doc, named) in enumerate(zip(batch, lists, strict=True), 1):
        controls = {control.code: control for listed in named.values() for control in listed}
        shown = "\n".join(
            f"{code} {control.name}: {(control.description or '')[:DESCRIPTION_CHARS]}"
            for code, control in sorted(controls.items())
        )
        parts.append(f"{scenario_text(doc, index)}\nControls:\n{shown}")
    answer = ask_ai(REVIEW_PROMPT, "\n\n".join(parts), usage)
    marks: dict[str, dict[str, str]] = {
        str(entry.get("id")): {str(k): str(v).strip().lower() for k, v in (entry.get("marks") or {}).items()}
        for entry in answer.get("scenarios") or []
    }
    return [marks.get(str(index), {}) for index in range(1, len(batch) + 1)]


def below_threshold(doc: dict[str, Any], controls: Sequence[LibraryControl], score: Scorer, cutoff: float):
    """How many of `controls` score below the threshold on the whole scenario (they would show "nearest")."""
    if not controls:
        return 0
    scores = score(search_text_without_category(doc), [describe_control(control) for control in controls])
    return sum(value < cutoff for value in scores)


def check_batch(batch, library, by_id, score: Scorer, rule: ControlRule, usage) -> list[dict[str, Any]]:
    """The four lists of each scenario of one batch, the reviewer's marks and the "nearest" counts."""
    pools = [asset_pool(doc, by_id, library) for doc in batch]
    offered = sorted({control.code: control for pool in pools for control in pool}.items())
    stories = "\n\n".join(scenario_text(doc, index) for index, doc in enumerate(batch, 1))
    library_text = "\n".join(f"{code} {control.name}" for code, control in offered)
    picks = answers_by_id(
        ask_ai(WAY_A_PROMPT, f"LIBRARY:\n{library_text}\n\nSCENARIOS:\n{stories}", usage),
        "controls",
        len(batch),
    )
    defences = answers_by_id(ask_ai(DEFENCES_PROMPT, stories, usage), "defences", len(batch))
    rows = []
    for doc, pool, codes, lines in zip(batch, pools, picks, defences, strict=True):
        named = {
            "today": [by_id[i["control_id"]] for i in doc["controls"]["items"] if i["control_id"] in by_id],
            "no_category": no_category(doc, by_id, score, rule),
            "way_a": chosen_codes(codes, pool, rule.most),
            "way_b": best_per_line(lines, pool, score, rule.most),
        }
        below = {way: below_threshold(doc, named[way], score, rule.cutoff) for way in ("way_a", "way_b")}
        rows.append({"doc": doc, "lists": named, "defences": lines, "below_threshold": below})
    for row, marks in zip(rows, review(batch, [row["lists"] for row in rows], usage), strict=True):
        row["marks"] = marks
    return rows


def fit_of(rows: Sequence[dict[str, Any]], name: str) -> dict[str, float]:
    """One list's marks over `rows`: the share of fits, partly and no, and its fit (fits + half the partly),
    over the controls the reviewer marked; `count` is every control of the list."""
    counts: Counter[str] = Counter()
    for row in rows:
        counts.update(row["marks"].get(control.code, "unmarked") for control in row["lists"][name])
    marked = sum(counts[mark] for mark in MARKS) or 1
    shares = {mark: counts[mark] / marked for mark in MARKS}
    return shares | {"fit": shares["fits"] + shares["partly"] / 2, "count": sum(counts.values())}


def report(rows: Sequence[dict[str, Any]], usage: Counter[str]) -> list[str]:
    """The summary lines: each list overall, the fit per category, the "nearest" counts and the AI used."""
    lines = [
        f"{len(rows)} scenarios",
        f"{'list':12} {'controls':>8} {'fits':>6} {'partly':>7} {'no':>5} {'fit':>5}",
    ]
    for name in LISTS:
        f = fit_of(rows, name)
        lines.append(
            f"{name:12} {f['count']:8.0f} {f['fits']:6.0%} {f['partly']:7.0%} {f['no']:5.0%} {f['fit']:5.0%}"
        )
    lines += ["", "fit per category:", f"{'':24}" + "".join(f"{name:>12}" for name in LISTS)]
    by_category: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_category[row["doc"]["content"]["category"]].append(row)
    for category, group in by_category.items():
        lines.append(f"{category:24}" + "".join(f"{fit_of(group, name)['fit']:12.0%}" for name in LISTS))
    for way in ("way_a", "way_b"):
        below = sum(row["below_threshold"][way] for row in rows)
        total = sum(len(row["lists"][way]) for row in rows)
        lines.append(f"{way}: {below} of {total} controls below the threshold (would show 'nearest')")
    lines.append(f"AI: {usage['calls']} calls, {usage['tokens_in']:,} tokens in, {usage['tokens_out']:,} out")
    return lines


def detail(rows: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """Each scenario's lists with the reviewer's marks, for --out."""
    return [
        {
            "title": row["doc"]["content"]["title"],
            "category": row["doc"]["content"]["category"],
            "defences": row["defences"],
            "lists": {
                name: [
                    f"{c.code} {c.name}: {row['marks'].get(c.code, 'unmarked')}" for c in row["lists"][name]
                ]
                for name in LISTS
            },
        }
        for row in rows
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Whether scenarios' controls reduce their risk, four ways.")
    parser.add_argument("--per-category", type=int, default=5, help="scenarios per STRIDE category (5)")
    parser.add_argument("--out", help="also write each scenario's lists and marks to this JSON file")
    args = parser.parse_args(argv)
    from app.container import apply_proxy_once, get_control_repository

    apply_proxy_once()
    library, _ = get_control_repository().get_control_library()
    by_id = {control.control_id: control for control in library}
    rule, score, usage = control_rule(), local_scorer(), Counter()
    scenarios = load_scenarios(args.per_category, rule.most)
    rows: list[dict[str, Any]] = []
    for start in range(0, len(scenarios), BATCH):
        rows += check_batch(scenarios[start : start + BATCH], library, by_id, score, rule, usage)
        print(f"checked {len(rows)} of {len(scenarios)} scenarios", flush=True)
    print("\n".join(report(rows, usage)))
    if args.out:
        Path(args.out).write_bytes(json.dumps(detail(rows), indent=2, ensure_ascii=False).encode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
