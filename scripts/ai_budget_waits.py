"""The AI budget report's section on how long users waited today, and why (scripts/ai_budget_report.py): each
click's wait and what it was spent on, the runs by how many users worked at once, the shortest time the
key's limit allows N users, and who used the limit in today's busiest minutes."""

from __future__ import annotations

from collections import Counter, defaultdict

from ai_budget_measures import (
    ACTIONS,
    ANSWERING,
    FAILING,
    IDLE,
    REFUSED,
    SCENARIO_ACTIONS,
    SCENARIO_MODULE,
    Evidence,
    Run,
    split,
)
from ai_budget_sessions import many, median, shown, table, when

AT_ONCE = (1, 2, 3, 5, 10)  # users who click at once, for the shortest wait the limit allows them
BUSIEST_SHOWN = 10  # today's busiest minutes shown
#: A request's column in the busiest minutes: its module's, or search for an embedding or rerank call.
COLUMNS = {"threat_scenarios": "Scenarios", "remediation": "Remediation", "service_mapper": "Service mapper"}
MINUTE_COLUMNS = (*COLUMNS.values(), "Search", "Other")
PARTS = (ANSWERING, REFUSED, FAILING, IDLE)  # how a wait splits; split() adds them up to it


def scenario_runs(e: Evidence) -> list[Run]:
    """The threat scenario actions of every session."""
    return [run for s in e.sessions for run in s.runs if run.first.module == SCENARIO_MODULE]


def runs_of(e: Evidence, api: str) -> list[Run]:
    """Today's runs of one threat scenario action."""
    return [run for run in scenario_runs(e) if run.first.api == api]


def minutes(seconds: float | None) -> str:
    """'6.2 min'; '-' for none."""
    return shown(None if seconds is None else seconds / 60, "{:.1f} min")


def parts_of(runs: list[Run]) -> dict[str, float]:
    """The runs' time in each part of a wait, in seconds: it adds up to their time."""
    totals = dict.fromkeys(PARTS, 0.0)
    for run in runs:
        for part, seconds in split(run.attempts).items():
            totals[part] += seconds
    return totals


def floor_minutes(tokens: float, limit: int, users: int = 1) -> float:
    """The shortest time `users` runs of `tokens` each take through a limit of `limit` tokens a minute."""
    return users * tokens / limit


def users_at_once(run: Run, e: Evidence) -> int:
    """How many sessions had AI requests running while this run did: its own and every other one."""
    start, end = run.first.start, run.end
    others = {a.session for a in e.attempts if a.session and a.session != run.first.session
              and a.start < end and a.end > start}  # fmt: skip
    return 1 + len(others)


def one_user_rows(e: Evidence, limit: int) -> list[list[str]]:
    """Table a: each action's runs today, their median wait, what it was spent on and the limit's floor."""
    rows = []
    for api in SCENARIO_ACTIONS:
        runs = runs_of(e, api)
        if not runs:
            continue
        parts, total = parts_of(runs), sum(run.work.seconds for run in runs) or 1.0
        tokens = median([run.work.tokens for run in runs]) or 0
        rows.append([ACTIONS[api], str(len(runs)), minutes(median([run.work.seconds for run in runs])),
                     *(f"{parts[part] / total:.0%}" for part in PARTS), f"{tokens:,.0f}",
                     minutes(floor_minutes(tokens, limit) * 60)])  # fmt: skip
    return rows


def together_rows(e: Evidence) -> list[list[str]]:
    """Table b: each action's runs by how many users worked at once, as measured today."""
    rows = []
    for api in SCENARIO_ACTIONS:
        grouped = defaultdict(list)
        for run in runs_of(e, api):
            grouped[min(users_at_once(run, e), 3)].append(run)
        for count, runs in sorted(grouped.items()):
            rows.append([ACTIONS[api], "3 or more" if count == 3 else str(count), str(len(runs)),
                         minutes(median([run.work.seconds for run in runs])),
                         f"{sum(run.work.refused for run in runs) / len(runs):.1f}",
                         shown(median([run.demand for run in runs]), "{:.0%}")])  # fmt: skip
    return rows


def heaviest(e: Evidence) -> str:
    """The threat scenario action whose runs used the most tokens today (median)."""
    return max(SCENARIO_ACTIONS, key=lambda api: median([run.work.tokens for run in runs_of(e, api)]) or 0)


def floor_rows(e: Evidence, limit: int) -> list[list[str]]:
    """Table c: the shortest wait the limit allows N users clicking the heaviest action at once."""
    tokens = median([run.work.tokens for run in runs_of(e, heaviest(e))]) or 0
    return [
        [str(users), f"{users * tokens:,.0f}", minutes(floor_minutes(tokens, limit, users) * 60)]
        for users in AT_ONCE
    ]


def minute_tokens(e: Evidence) -> dict[int, Counter]:
    """Each minute's tokens used, by the column of who used them; they add up to the minute's tokens."""
    used: dict[int, Counter] = defaultdict(Counter)
    for attempt in e.attempts:
        if not attempt.refused:
            column = COLUMNS.get(attempt.module, "Other") if attempt.chat else "Search"
            used[int(attempt.start // 60)][column] += attempt.tokens
    return used


def busiest_rows(e: Evidence, limit: int) -> list[list[str]]:
    """Table d: today's busiest minutes, as the gateway counted them: who used the tokens, how many
    sessions were active, the share of the limit and the 429s."""
    used = minute_tokens(e)
    rows = []
    for at, minute in sorted(e.minutes.items(), key=lambda item: -item[1].peak_tokens)[:BUSIEST_SHOWN]:
        start, end = at * 60, at * 60 + 60
        active = {a.session for a in e.attempts if a.session and a.start < end and a.end > start}
        rows.append([when(start, "%H:%M"), *(f"{used[at][column]:,}" for column in MINUTE_COLUMNS),
                     f"{minute.tokens:,}", f"{minute.peak_tokens:,}", f"{minute.peak_tokens / limit:.0%}",
                     str(len(active)), str(minute.refused)])  # fmt: skip
    return rows


def wait_sentence(e: Evidence, limit: int) -> str:
    """The answer's first sentence: what one click took today, and the least N users at once wait."""
    api = heaviest(e)
    runs = runs_of(e, api)
    if not runs:
        return ""
    answering = median([split(run.attempts)[ANSWERING] for run in runs]) or 0.0
    floor = floor_minutes(median([run.work.tokens for run in runs]) or 0, limit, e.users)
    return (
        f"Today one {ACTIONS[api]} took a median {minutes(median([r.work.seconds for r in runs]))}, "
        f"{answering / 60:.1f} of it the model answering; {e.users} users at once wait at least "
        f"{floor:.1f} min for the last result from the limit alone."
    )


ONE_CLICK = ["Threat scenario action", "Runs today", "Wait, median", "Of it: model answering",
             "Refused by the limit (429)", "Other failures", "No request in flight", "Tokens used, median",
             "Shortest the limit allows"]  # fmt: skip
TOGETHER = ["Threat scenario action", "Users at once", "Runs", "Wait, median", "429s per run",
            "Share of the limit, median (est.)"]  # fmt: skip
FLOORS = ["Users who click at once", "Tokens needed", "Earliest the last user gets results"]
BUSIEST = ["Minute (UTC)", *MINUTE_COLUMNS, "Tokens used", "Peak counted (est.)", "Of the limit",
           "Sessions active", "429s"]  # fmt: skip
NO_OVERLAP = [
    "Nothing overlapped today: every run had the limit to itself. To measure it, have 2-3 people click "
    "Create scenario within the same minute, then run this report again.",
    "",
]


def one_click_lines(e: Evidence, limit: int) -> list[str]:
    """Table a, with what its columns mean."""
    return [
        "**a. One click.** The wait is from a run's first AI request to its last answer. Its parts add up to "
        "100%: the model answering; refused by the limit (each 429 and the wait before its retry); other "
        "failures; and no request in flight (TSG holding requests back to stay under the limit, or its own "
        f"work). The shortest the limit allows is the run's tokens ÷ {limit:,} a minute.",
        "",
        *table(ONE_CLICK, one_user_rows(e, limit)),
    ]


def together_lines(e: Evidence) -> list[str]:
    """Table b, and the test to run when nothing overlapped today."""
    rows = together_rows(e)
    return [
        "**b. Users at once, as measured today.** Each run counts the sessions that had AI requests running "
        "at the same time, its own too.",
        "",
        *table(TOGETHER, rows, left=2),
        *([] if any(row[1] != "1" for row in rows) else NO_OVERLAP),
    ]


def floor_lines(e: Evidence, limit: int) -> list[str]:
    """Table c, and why its waits are floors."""
    return [
        f"**c. Users at once, from the limit alone.** N users clicking {ACTIONS[heaviest(e)]} at once need N "
        f"times its median tokens; at {limit:,} tokens a minute the last of them gets results no sooner than "
        "this. These are floors: the model's own answer time, the 429 waits and the gateway holding each "
        "running request's whole answer cap all come on top.",
        "",
        *table(FLOORS, floor_rows(e, limit)),
    ]


def busiest_lines(e: Evidence, limit: int) -> list[str]:
    """Table d: who used the limit."""
    return [
        f"**d. Who used the {limit:,} tokens a minute: today's {many(len(e.minutes), 'minute')} with AI "
        f"requests, the {BUSIEST_SHOWN} busiest.** The limit is shared by every model the key uses: the "
        "columns are each module's tokens used (search: embedding and rerank calls).",
        "",
        *table(BUSIEST, busiest_rows(e, limit)),
    ]


def waits_section(e: Evidence, limit: int) -> list[str]:
    """The section 'How long users waited today, and why', for the page before the detail."""
    title = ["## How long users waited today, and why", ""]
    if not scenario_runs(e):
        return [*title, "No threat scenario action ran today.", ""]
    return [*title, *one_click_lines(e, limit), *together_lines(e), *floor_lines(e, limit),
            *busiest_lines(e, limit)]  # fmt: skip
