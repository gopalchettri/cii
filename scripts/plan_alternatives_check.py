"""Plan alternatives check: whether a remediation plan keeps controls that fit its risk better when it is
shown every control its scenario's search found and the register's controls that search missed (plan of
2026-10-31), on the same saved plans, both ways asked at the same time:
  today  the identified controls and the next ALTERNATIVES of the search, as the job builds them now
  all    the same identified controls, the register's controls the search missed, then every other control
         the search found
Each version is written by the app's own write_plan with the remediation module's chat model. ONE AI
reviewer then marks each plan's kept controls (retained, or chosen to replace one), both ways mixed: fits,
partly or no. It prints the fit, the uncovered risks per plan (those about systems outside the request's scope
left out), the replaced and flagged controls, the re-asks and the tokens, generated and hand-written apart.

Reads MongoDB and the control library and writes nothing to them: the chat model's call texts and usage rows
are kept in memory.

From the project folder:
  .venv\\Scripts\\python scripts\\plan_alternatives_check.py [--plans 24] [--out plan_alternatives.json]"""

import argparse
import json
import re
import sys
import threading
from collections import Counter
from collections.abc import Collection, Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts"))

import control_fit_check as check  # noqa: E402
from pymongo import MongoClient  # noqa: E402

import app.ai.attempts  # noqa: E402
from app.ai.chat import chat_model_from  # noqa: E402
from app.ai.module_chat import module_chat  # noqa: E402
from app.ai.slots import UNLIMITED_AI_REQUEST_RATE, UNLIMITED_AI_SLOTS  # noqa: E402
from app.core.config import get_settings  # noqa: E402
from app.core.constants import ControlValidation, GapKind, Remediation, RunKind  # noqa: E402
from app.core.constants.ai_limits import ChatModule  # noqa: E402
from app.core.exceptions import JobFailed  # noqa: E402
from app.domain.remediation.plan import assess_alternatives, resolve_control_refs, write_plan  # noqa: E402
from app.domain.scenario.write import ControlMapper  # noqa: E402
from app.domain.shared.names import name_match_key  # noqa: E402
from app.models.library.library import LibraryControl  # noqa: E402
from app.models.remediation.requests import SYSTEM_LISTS, ControlRef  # noqa: E402
from app.models.scenario.asset_context import FrozenContext  # noqa: E402
from app.search.texts import describe_control  # noqa: E402

WAYS = ("today", "all")
SET = 6
#: An uncovered risk about systems the request left out of the risk's scope: no missing control.
_OUT_OF_SCOPE = re.compile(
    r"outside|not (?:in|among|part of) (?:the )?affected|beyond the affected|scope", re.I
)
_REF_FIELDS = ("control_id", "control_code", "control_name")
_USAGE = threading.local()  # each worker thread's usage rows: one plan written at a time


class _CallsInMemory:
    """The chat model's call texts, kept here instead of tsg_ai_call_texts."""

    def create(self, record: dict[str, Any]) -> None:
        pass

    def find_ok_response(self, job: dict[str, Any], prompt_hash: str) -> None:
        return None


def _keep_usage_rows(rows: list[dict[str, Any]]) -> None:
    _USAGE.rows.extend(rows)


def register_controls_not_found(
    register: dict[str, Any], controls: Sequence[LibraryControl], taken_ids: Collection[int]
) -> list[tuple[LibraryControl, None]]:
    """The register's existing controls not among `taken_ids` nor a twin of one, once each, unscored."""
    refs = [ControlRef.model_validate(entry) for entry in register.get("existing_controls") or []]
    named, _ = resolve_control_refs(refs, controls)
    taken = {name_match_key(describe_control(c)) for c in controls if c.control_id in taken_ids}
    return [(control, None) for control in named if name_match_key(describe_control(control)) not in taken]


def _register_of_today(register: dict[str, Any]) -> bool:
    """Whether a stored register has today's shape (older ones the app no longer reads)."""
    entries = register.get("existing_controls") or []
    return SYSTEM_LISTS[1] in register and all(set(entry) <= set(_REF_FIELDS) for entry in entries)


def load_plans(db: Any, most: int, by_id: dict[int, LibraryControl]) -> list[dict[str, Any]]:
    """The newest done version of each distinct scenario statement whose scenario still holds the plan's
    identified controls and whose register has today's shape: every hand-written one, then generated ones one
    threat type at a time."""
    newest: dict[tuple[str, str], dict[str, Any]] = {}
    for record in db.tsg_remediations.find({}, {"versions": 1, "register": 1, "source": 1, "scenario_id": 1}):
        for version in record.get("versions") or []:
            snapshot = version.get("snapshot") or {}
            if version.get("status") != "done" or "library_alternatives" not in snapshot.get(
                "existing_controls", {}
            ):
                continue
            key = (record["source"], (snapshot["scenario"]["statement"] or "")[:80])
            if key not in newest or version["completed_at"] > newest[key]["version"]["completed_at"]:
                newest[key] = {"record": record, "version": version}
    usable = []
    for plan in newest.values():
        scenario = db.tsg_scenarios.find_one({"_id": plan["record"]["scenario_id"]})
        identified = [
            row["control_id"] for row in plan["version"]["snapshot"]["existing_controls"]["library_mapped"]
        ]
        stored = [item["control_id"] for item in ((scenario or {}).get("controls") or {}).get("items") or []]
        fits_today = _register_of_today(plan["record"]["register"]) and all(i in by_id for i in identified)
        if scenario and identified == stored and fits_today:
            usable.append(plan | {"scenario": scenario})
    usable.sort(key=lambda plan: plan["version"]["completed_at"], reverse=True)
    manual = [plan for plan in usable if plan["record"]["source"] == RunKind.MANUAL]
    by_type: dict[str, list[dict[str, Any]]] = {}
    for plan in usable:
        if plan["record"]["source"] != RunKind.MANUAL:
            by_type.setdefault(str(plan["scenario"]["content"]["threat"].get("type")), []).append(plan)
    generated = []
    while len(manual) + len(generated) < most and any(by_type.values()):
        for plans in by_type.values():
            if plans and len(manual) + len(generated) < most:
                generated.append(plans.pop(0))
    return (manual + generated)[:most]


def snapshots(plan: dict[str, Any], mapper: ControlMapper, search: Any, controls: Sequence[LibraryControl]):
    """Today's snapshot and the one showing every searched control and the register's missed ones."""
    saved, scenario, register = plan["version"]["snapshot"], plan["scenario"], plan["record"]["register"]
    context = FrozenContext.from_record(plan["context"])
    identified = [row["control_id"] for row in saved["existing_controls"]["library_mapped"]]
    affected, categories = saved["risk_scope"]["affected_systems"], context.system_categories()

    def offering(count: int, with_register: bool) -> dict[str, Any]:
        found = mapper.find_alternative_controls(
            scenario, context, search, identified, count, scenario["controls"]
        )
        if with_register:
            taken = [*identified, *(control.control_id for control, _ in found)]
            found = [*register_controls_not_found(register, controls, taken), *found]
        offered = assess_alternatives(found, register, controls, affected, categories)
        existing = saved["existing_controls"] | {"library_alternatives": offered}
        return saved | {"existing_controls": existing}

    return {
        "today": offering(Remediation.ALTERNATIVES, False),
        "all": offering(get_settings().control_candidates, True),
    }


def write(chat: Any, snapshot: dict[str, Any]) -> dict[str, Any]:
    """The plan write_plan makes of `snapshot`, with the usage rows of its ask; a failure's code."""
    _USAGE.rows = []
    try:
        plan, warnings = write_plan(chat, snapshot)
    except JobFailed as exc:
        return {"failed": exc.code, "usage": _USAGE.rows}
    return {"plan": plan, "warnings": warnings, "usage": _USAGE.rows}


def kept(plan: dict[str, Any], by_code: dict[str, LibraryControl]) -> list[LibraryControl]:
    """The controls a plan keeps against the risk: identified ones retained, alternatives chosen."""
    rows = plan["control_assessment"]
    codes = [
        r["control_code"] for r in rows if r["validation"] == ControlValidation.RETAINED or r["replaces"]
    ]
    return [by_code[code] for code in codes if code in by_code]


def measures(written: dict[str, Any]) -> Counter[str]:
    """One written version's counts: uncovered risks in scope, replaced, flagged, re-asks, tokens."""
    counts: Counter[str] = Counter(plans=1)
    for row in written["usage"]:
        counts["calls"] += 1
        counts["tokens_in"] += row.get("tokens_in") or 0
        counts["reasks"] += bool(row.get("reask"))
    if "failed" in written:
        return counts + Counter(failed=1)
    plan = written["plan"]
    gaps = [g["detail"] for g in plan["unresolved_gaps"] if g["kind"] == GapKind.UNCOVERED_RISK]
    counts["uncovered"] += sum(1 for detail in gaps if not _OUT_OF_SCOPE.search(detail))
    for row in plan["control_assessment"]:
        counts[str(row["validation"])] += 1
    counts["recommended"] += len(plan["controls_to_be_implemented"]["controls"])
    return counts


def report(rows: Sequence[dict[str, Any]]) -> list[str]:
    """Each way's fit and counts, all plans then generated and hand-written apart."""
    lines = []
    for label, group in (("all plans", rows), *((s, [r for r in rows if r["source"] == s]) for s in RunKind)):
        if not group:
            continue
        lines += [
            f"\n{label}: {len(group)} plans",
            f"{'way':6} {'kept':>5} {'fits':>5} {'partly':>6} {'no':>4} "
            f"{'fit':>5} {'uncovered/plan':>15} {'replaced':>8} {'flagged':>7} {'reasks':>6} {'failed':>6} "
            f"{'tokens in/call':>14}",
        ]
        for way in WAYS:
            f = check.fit_of(group, way)
            c = sum((r["measures"][way] for r in group), Counter())
            lines.append(
                f"{way:6} {f['count']:5.0f} {f['fits']:5.0%} {f['partly']:6.0%} {f['no']:4.0%} "
                f"{f['fit']:5.0%} {c['uncovered'] / len(group):15.1f} {c[ControlValidation.REPLACED]:8} "
                f"{c[ControlValidation.FLAGGED_FOR_REVIEW]:7} {c['reasks']:6} {c['failed']:6} "
                f"{c['tokens_in'] // max(c['calls'], 1):14,}"
            )
    return lines


def detail(rows: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """Each plan's kept controls with the reviewer's marks and its uncovered risks, for --out."""
    return [
        {
            "statement": row["doc"]["content"]["statement"],
            "source": row["source"],
            "ways": {
                way: {
                    "kept": [
                        f"{c.code} {c.name}: {row['marks'].get(c.code, 'unmarked')}"
                        for c in row["lists"][way]
                    ],
                    "uncovered": [
                        g["detail"]
                        for g in (row["written"][way].get("plan") or {}).get("unresolved_gaps") or []
                        if g["kind"] == GapKind.UNCOVERED_RISK
                    ],
                }
                for way in WAYS
            },
        }
        for row in rows
    ]


def build_remediation_chat(settings: Any) -> Any:
    """Remediation's chat model, its calls kept in memory and no slot or rate limit."""
    return chat_model_from(
        module_chat(settings, ChatModule.REMEDIATION),
        settings.ai_key_header,
        _CallsInMemory(),  # type: ignore[arg-type]
        UNLIMITED_AI_SLOTS,
        UNLIMITED_AI_REQUEST_RATE,
    )


def build_rows(
    plans: Sequence[dict[str, Any]], written: Sequence[dict[str, Any]], by_code: dict[str, Any]
) -> list[dict[str, Any]]:
    """Each plan with both ways' written versions, kept controls and measures."""
    return [
        {
            "doc": plan["scenario"],
            "source": plan["record"]["source"],
            "written": versions,
            "lists": {
                way: kept(versions[way]["plan"], by_code) if "plan" in versions[way] else [] for way in WAYS
            },
            "measures": {way: measures(versions[way]) for way in WAYS},
        }
        for plan, versions in zip(plans, written, strict=True)
    ]


def mark_kept_controls(rows: list[dict[str, Any]]) -> Counter[str]:
    """The reviewer's marks on each row's kept controls, SET plans a call; returns the reviewer's usage."""
    usage: Counter[str] = Counter()
    for start in range(0, len(rows), SET):
        batch = rows[start : start + SET]
        marks = check.review([r["doc"] for r in batch], [r["lists"] for r in batch], usage)
        for row, marked in zip(batch, marks, strict=True):
            row["marks"] = marked
        print(f"reviewed {min(start + SET, len(rows))} of {len(rows)} plans", flush=True)
    return usage


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Whether plans keep better controls when shown all found ones."
    )
    parser.add_argument("--plans", type=int, default=24, help="distinct saved plans (24)")
    parser.add_argument("--out", help="also write each plan's kept controls, marks and uncovered risks here")
    args = parser.parse_args(argv)
    from app.container import apply_proxy_once, get_control_repository, get_library_search, get_rerank_model

    apply_proxy_once()
    app.ai.attempts.write_usage_rows = _keep_usage_rows  # ponytail: the check's usage rows stay in memory
    settings = get_settings()
    library, _ = get_control_repository().get_control_library()
    by_id = {control.control_id: control for control in library}
    by_code = {control.code: control for control in library}
    search, mapper = get_library_search().snapshot(wait=True), ControlMapper(get_rerank_model())
    chat = build_remediation_chat(settings)
    db = MongoClient(settings.mongo_url)[settings.mongo_db]
    plans = load_plans(db, args.plans, by_id)
    for plan in plans:
        plan["context"] = db.tsg_sessions.find_one({"_id": plan["scenario"]["session_id"]})["context"]
    inputs = [snapshots(plan, mapper, search, library) for plan in plans]
    with ThreadPoolExecutor(max_workers=4) as pool:  # each plan's two ways side by side
        futures = [{way: pool.submit(write, chat, shots[way]) for way in WAYS} for shots in inputs]
        written = [{way: future.result() for way, future in pair.items()} for pair in futures]
    rows = build_rows(plans, written, by_code)
    usage = mark_kept_controls(rows)
    print("\n".join(report(rows)))
    print(f"\nreviewer: {usage['calls']} calls, {usage['tokens_in']:,} tokens in")
    if args.out:
        Path(args.out).write_bytes(json.dumps(detail(rows), indent=2, ensure_ascii=False).encode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
