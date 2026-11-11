"""The AI budget report's section on each session (scripts/ai_budget_report.py): its actions, their stages and
its minutes against the limit; and the Markdown and limit wording the whole report shares."""

from __future__ import annotations

import statistics
from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime

from ai_budget_measures import (
    ACTIONS,
    APP_TIMES,
    MODULES,
    STAGES,
    Evidence,
    Run,
    Session,
    Work,
    gateway_counter,
    logged_429s,
)
from ai_limits_check import amount as cell

#: Our own causes of delay a pod's log names, and what each means.
OWN_DELAYS = {
    "job.not_claimed": "a job delivery our own checks dropped (a clock gap: docs/UAT_CLOCK_SKEW_RUNBOOK.md)",
    "ai.slots_busy": "no call slot was free within its wait",
    "ai.request_rate_busy": "TSG's own pacing had no turn free within its wait",
    "ai.limit_cut": "a 429 lowered how many calls TSG makes at once",
}


STAGE_HEADER = ["Module", "Stage", "Time (s)", "Requests", "Tokens", "Model response, median / longest (s)",
                "No request in flight, est. (s)", "No response: 429 / other", "Unusable answers", "Retries",
                "Waited before retrying (s)"]  # fmt: skip


def when(epoch: float, form: str = "%Y-%m-%d %H:%M") -> str:
    """'2026-10-31 10:02' (UTC)."""
    return f"{datetime.fromtimestamp(epoch, UTC):{form}}"


def median(values: list[float]) -> float | None:
    """The median, None for no values."""
    return statistics.median(values) if values else None


def shown(value: float | None, form: str = "{:,.0f}") -> str:
    """A number as text; '-' for none."""
    return "-" if value is None else form.format(value)


def table(header: list[str], rows: list[list[str]], left: int | str = 1) -> list[str]:
    """A Markdown table: its first `left` columns left-aligned and the rest (numbers) right, or as `left`
    spells it, an 'l' or 'r' a column."""
    align = left if isinstance(left, str) else "l" * left + "r" * (len(header) - left)
    rule = "|" + "".join("---|" if side == "l" else "---:|" for side in align)
    return ["| " + " | ".join(header) + " |", rule, *("| " + " | ".join(row) + " |" for row in rows), ""]


def many(count: int, word: str) -> str:
    """'1 action', '3 actions'."""
    return f"{count:,} {word}{'s' * (count != 1)}"


def counted_text(counts: Counter) -> str:
    """'Timeout x3, APIError x1'; 'none' for none."""
    return ", ".join(f"{value} x{n}" for value, n in counts.most_common()) or "none"


def scenario_limits(e: Evidence) -> list:
    """The limits of the model threat scenario sessions use (all models' when none is named for them)."""
    named = [found for model, found in e.limits.items() if "scenario" in model.rsplit("(", 1)[-1]]
    return named[0] if named else [limit for found in e.limits.values() for limit in found]


def logged_line(entry: dict, counted: Callable[[float], tuple[int, int]]) -> str:
    """A logged 429 in the gateway's own numbers, and what the gateway and TSG had counted then."""
    names = ("limit_type", "limit_scope", "limit", "limit_remaining", "retry_after")
    limit_type, scope, limit, remaining, retry = (entry.get(name, "not given") for name in names)
    line = (
        f"{entry.get('timestamp')}  HTTP 429 (worker log): limit type {limit_type}, scope {scope}, "
        f"limit {limit}, remaining {remaining}, Retry-After {retry}"
    )
    if isinstance(limit, int) and isinstance(remaining, int):
        ours = counted(datetime.fromisoformat(str(entry["timestamp"])).timestamp())[0]
        line += f": the gateway had counted {limit - remaining:,}, TSG's own calls {ours:,} (est.)"
    return line


def no_response(attempts: list) -> str:
    """'21 of 723: 19 refused by the limit (429); others: Timeout x2'."""
    refused = sum(a.refused for a in attempts)
    others = Counter(a.error or a.outcome for a in attempts if not a.answered and not a.refused)
    return (
        f"{refused + sum(others.values()):,} of {len(attempts):,}: {refused:,} refused by the limit (429); "
        f"others: {counted_text(others)}"
    )


def stage_row(module: str, stage: str, work: Work) -> list[str]:
    """One stage of an action."""
    response = (
        f"{statistics.median(work.responses):,.0f} / {max(work.responses):,.0f}" if work.responses else "-"
    )
    return [module, stage, f"{work.seconds:,.0f}", str(work.requests), f"{work.tokens:,}", response,
            f"{work.idle:,.0f}", f"{work.refused} / {work.unanswered}", str(work.unusable), str(work.retries),
            f"{work.retry_wait:,.0f}"]  # fmt: skip


def run_block(run: Run) -> list[str]:
    """One action of a session: its time, the app's own stage times and each stage."""
    module = MODULES.get(run.first.module, run.first.module)
    head = (
        f"**{ACTIONS.get(run.first.api, run.first.api)}** at {when(run.first.start, '%H:%M:%S')} UTC: "
        f"{run.work.seconds:,.0f} s from its first AI request to its last answer"
    )
    if run.app_times:
        times = [
            f"{STAGES[stage]} {run.app_times[k]:,.0f} s"
            for k, stage in APP_TIMES.items()
            if k in run.app_times
        ]
        head += "; the app's own stage times: " + ", ".join(times)
    rows = [
        stage_row(module, STAGES.get(stage, stage or "(no stage)"), work)
        for stage, work in run.stages.items()
    ]
    return [f"{head}.", "", *table(STAGE_HEADER, [*rows, stage_row("**All stages**", "", run.work)], left=2)]


def timeline(e: Evidence, session: Session) -> list[str]:
    """Each minute of a session: its tokens and TSG's, the estimated peak against the limit, the 429s."""
    own, own_refused = Counter[int](), Counter[int]()
    for attempt in (a for run in session.runs for a in run.attempts):
        if attempt.refused:
            own_refused[int(attempt.start // 60)] += 1
        else:
            own[int(attempt.start // 60)] += attempt.tokens
    spans = {m for run in session.runs for m in range(int(run.first.start // 60), int(run.end // 60) + 1)}
    rows = []
    for at in sorted(spans):
        minute = e.minutes.get(at)
        peak_tokens, tokens, refused = (
            (minute.peak_tokens, minute.tokens, minute.refused) if minute else (0, 0, 0)
        )
        rows.append([when(at * 60, "%H:%M"), f"{own[at]:,}", f"{tokens:,}", f"{peak_tokens:,}",
                     f"{peak_tokens / e.budget:.0%}", f"{own_refused[at]} / {refused}"])  # fmt: skip
    header = ["Minute (UTC)", "This session's tokens", "All TSG tokens", "Peak estimated demand (est.)",
              "Of the limit (est.)", "429s: this session / all TSG"]  # fmt: skip
    return [f"Timeline (the limit is {e.budget:,} tokens per minute):", "", *table(header, rows)]


def session_429s(e: Evidence, session: Session) -> list[str]:
    """The 429s the worker logs recorded while the session ran, word for word."""
    counted, found = gateway_counter(e.attempts), []
    for entry in logged_429s(e.logs or []):
        moment = datetime.fromisoformat(str(entry["timestamp"])).timestamp()
        if any(run.first.start <= moment <= run.end + 1 and entry.get("request_id") in (None, run.request)
               for run in session.runs):  # fmt: skip
            found.append(logged_line(entry, counted))
    return ["Gateway 429s logged during this session:", "", "```", *found, "```", ""] if found else []


def session_block(e: Evidence, number: int, session: Session) -> list[str]:
    """One session: when, its total time, the limits for it, each action and its minutes."""
    start, end = session.runs[0].first.start, max(run.end for run in session.runs)
    after = round(e.checked.timestamp() - end) // 60
    checked = f"{after // 60} h {after % 60} min after this session ended" if after > 0 else "while it ran"
    limits = scenario_limits(e)
    model, key = ([limit for limit in limits if limit.scope == scope] for scope in ("model", "key"))
    lines = [
        f"### Session {number}: {when(start)} UTC ({session.id[:8]}), {session.seconds / 60:.1f} minutes in "
        "all",
        "",
        f"Limits per minute (checked {e.checked:%Y-%m-%d %H:%M} UTC, {checked}): model capacity: tokens "
        f"{cell(model, 'tokens')}, requests {cell(model, 'requests')}; TSG's key: tokens "
        f"{cell(key, 'tokens')}, requests {cell(key, 'requests')}; **applies to TSG: {e.budget:,} tokens** "
        "(the lowest, section 1).",
        "",
    ]
    for run in session.runs:
        lines += run_block(run)
    return [*lines, *timeline(e, session), *session_429s(e, session)]


def sessions_section(e: Evidence) -> list[str]:
    """Section 5: each session."""
    lines = [
        "## 5. Each session",
        "",
        "Per stage: its time from its first AI request to its last answer; requests (a retry is the same "
        "request again); the model's own time per answer; **no request in flight (est.)**: how long each "
        "request waited before it was sent is *not measured* (section 6), this is the nearest the records "
        "give; requests the model did not respond to (refused by the limit with 429 / for another reason: a "
        "timeout, an unreachable or failing model); answers that could not be used; retries and the time "
        "from each failed try to its retry.",
        "",
    ]
    for number, session in enumerate(e.sessions, 1):
        lines += session_block(e, number, session)
    return lines


def app_side_section(e: Evidence) -> list[str]:
    """Section 4: the app's own waits and other errors that may have added delay."""
    runs = [run for s in e.sessions for run in s.runs]
    idle, total = sum(r.work.idle for r in runs), sum(r.work.seconds for r in runs)
    outside = [sum(r.app_times.values()) - r.work.seconds for r in runs if r.app_times]
    unusable = Counter(a.outcome for r in runs for a in r.attempts if a.answered and a.outcome != "ok")
    lines = [
        "## 4. Application-side waits and other errors",
        "",
        f"- **No request in flight (est.): {idle:,.0f} of the actions' {total:,.0f} s.** TSG waiting to send "
        "(its own pacing turn, CII_SCENARIO_CHAT_TOKENS_PER_MINUTE, or a free call slot) or its own work "
        "between requests; the records cannot split these.",
        "- Outside the AI requests (the app's own stage times less the AI time; known for "
        f"{many(len(outside), 'action')}, a session's latest only): median {shown(median(outside))} s.",
        "- Requests the model did not respond to, in the sessions: "
        f"{no_response([a for r in runs for a in r.attempts])}.",
        f"- Answers that could not be used (asked again): {counted_text(unusable)}.",
        "",
    ]  # fmt: skip
    if e.logs is None:
        return [
            *lines,
            "Worker logs not given (--logs): TSG's own limiter and job lines are not counted.",
            "",
        ]
    counts = Counter(entry["event"] for entry in e.logs)
    rows = [[event, meaning, f"{counts[event]:,}"] for event, meaning in OWN_DELAYS.items()]
    return [*lines, *table(["Worker log line", "What it means", "Count"], rows, left=2)]


def gaps_section(e: Evidence) -> list[str]:
    """Section 6: what is estimated and what is not measured, so no gap is hidden."""
    unowned = sum(not a.session for a in e.attempts)
    return [
        "## 6. Estimated and not measured",
        "",
        "- **Not measured: how long each request waited before it was sent.** The app records each request's "
        "own time with the model, not its wait for TSG's pacing turn or a free call slot. *No request in "
        "flight (est.)* is the nearest measure: it also holds the app's own work, and misses a wait while "
        "another request was in flight. Recording that wait on each usage row would measure it.",
        "- **Estimated: peak demand.** Counted as the gateway counts, over the 60 s before each request: a "
        "running request at its prompt and whole answer cap, a finished one at its prompt and answer "
        "(scripts/ai_capacity_report.py). The gateway's own count may differ; a logged 429 shows both.",
        f"- **Estimated: the capacity for {e.users} users** assumes they all start the heaviest action at "
        "the same moment, each as heavy as the heaviest one measured.",
        "- **Not visible: others' use of a shared limit** (a team or organisation budget): only TSG's own "
        "requests are counted; a logged 429's count against TSG's shows the rest.",
        f"- **Limits checked {e.checked:%Y-%m-%d %H:%M} UTC**, not when each session ran; a logged 429 "
        "states the limit at its time.",
        "- Clocks: each request is timed by its pod's clock; pods a few seconds apart shift a timeline that "
        "much (scripts/uat_clock_check.py).",
        f"- Requests of no session (shared work, other modules' own runs): {unowned:,}; in the minutes' "
        "'All TSG tokens' only.",
        "- The app's own stage times: a session keeps them for its latest action only.",
        "",
    ]
