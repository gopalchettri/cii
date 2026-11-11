"""The AI budget evidence report (scripts/ai_budget_evidence.py), in Markdown for the gateway's support team:
first, in plain words, whether the API key's token limit is the bottleneck, with what the key may use in one
minute, what threat scenario generation needs in one minute and the proof from the runs; then the detail
(scripts/ai_budget_sessions.py writes each session, the app's own waits and what is not measured)."""

from __future__ import annotations

import statistics
from collections.abc import Callable

from ai_budget_measures import (
    ACTIONS,
    SCENARIO_ACTIONS,
    SCENARIO_MODULE,
    Evidence,
    Need,
    Run,
    gateway_counter,
    logged_429s,
    needs_of,
)
from ai_budget_sessions import (
    app_side_section,
    cell,
    gaps_section,
    logged_line,
    many,
    median,
    no_response,
    scenario_limits,
    sessions_section,
    shown,
    table,
    when,
)
from ai_budget_waits import scenario_runs, wait_sentence, waits_section
from ai_limits_check import HEADER as KEY_HEADER
from ai_limits_check import key_table

LOGGED_SHOWN = 20  # logged 429s quoted word for word in section 1
PACE_SETTING = "CII_SCENARIO_CHAT_TOKENS_PER_MINUTE"  # TSG's own pacing of threat scenario requests


def peak(e: Evidence, kind: str) -> tuple[int, float]:
    """The busiest minute's estimated count of `kind` (tokens or requests) and when it was."""
    return max(((getattr(m, f"peak_{kind}"), at * 60.0) for at, m in e.minutes.items()), default=(0, 0.0))


def lowest(e: Evidence, kind: str):
    """The lowest tokens- or requests-a-minute limit the gateway states, of any model and scope; None."""
    stated = [limit for found in e.limits.values() for limit in found if limit.kind == kind and limit.value]
    return min(stated, key=lambda limit: limit.value, default=None)


def short(model: str) -> str:
    """'kimi-k2.5 (scenario)' of 'kimi-k2.5 @ gw.test (scenario)'."""
    return f"{model.split(' @ ')[0]} ({model.rsplit('(', 1)[-1]}"


def pace(e: Evidence) -> int:
    """TSG's own pacing of threat scenario requests, tokens a minute; 0 for none."""
    values = [line.split("=", 1)[1] for line in e.settings if line.startswith(f"{PACE_SETTING}=")]
    return int(values[0]) if values and values[0].isdigit() else 0


def key_limit(e: Evidence) -> int:
    """The tokens a minute the key may use for threat scenarios: the lowest its model's gateway states."""
    stated = [limit.value for limit in scenario_limits(e) if limit.kind == "tokens" and limit.value]
    return min(stated) if stated and e.budget_read else e.budget


def scenario_needs(e: Evidence) -> list[Need]:
    """Each threat scenario action's need in one minute, in the order a session runs them."""
    needs = {need.api: need for need in needs_of(e.attempts) if need.module == SCENARIO_MODULE}
    return [needs[api] for api in SCENARIO_ACTIONS if api in needs]


def need_rows(e: Evidence, limit: int) -> list[list[str]]:
    """Table 2: each threat scenario action's need in one minute against the key's limit."""
    rows = []
    for need in scenario_needs(e):
        runs = [run for run in scenario_runs(e) if run.first.api == need.api]
        together = e.users * need.tokens
        rows.append([ACTIONS[need.api], str(need.actions),
                     shown(median([run.work.seconds / 60 for run in runs]), "{:.1f} min"),
                     shown(median([run.work.tokens for run in runs])), f"{need.tokens:,} / {need.requests:,}",
                     f"{need.tokens / limit:.0%}", f"{together:,} / {e.users * need.requests:,}",
                     f"{together / limit:.0%}", str(limit // need.tokens)])  # fmt: skip
    return rows


def bottleneck(e: Evidence, limit: int) -> str:
    """The answer in plain words: how long users waited today, then whether the key's limit is why."""
    return " ".join(part for part in (wait_sentence(e, limit), token_answer(e, limit)) if part)


def covers(e: Evidence) -> str:
    """'Today, 2026-10-30, 00:00 to 14:21 UTC', or the range given."""
    if e.since.date() == e.until.date() and (e.since.hour, e.since.minute) == (0, 0):
        return f"Today, {e.since:%Y-%m-%d}, 00:00 to {e.until:%H:%M} UTC"
    return f"From {e.since:%Y-%m-%d %H:%M} to {e.until:%Y-%m-%d %H:%M} UTC"


def token_answer(e: Evidence, limit: int) -> str:
    """Whether the key's limit is the bottleneck for threat scenario generation, in plain words."""
    needs = scenario_needs(e)
    if not needs:
        return "No threat scenario action made AI calls in this range: run a few, then this report again."
    heavy = max(needs, key=lambda need: need.tokens)
    action, together, allows = ACTIONS[heavy.api], e.users * heavy.tokens, limit // heavy.tokens
    if heavy.tokens > limit:
        return (
            f"**The API key's token limit is the bottleneck.** One {action} needs up to {heavy.tokens:,} "
            f"tokens in a minute, but the key may use only {limit:,} tokens a minute: even one user has to "
            f"wait. {e.users} users at once would need {together:,} tokens a minute, {together / limit:.1f} "
            "times the limit."
        )
    if together > limit:
        return (
            f"**The API key's token limit is the bottleneck as soon as {many(allows + 1, 'user')} use it at "
            f"once.** One {action} needs up to {heavy.tokens:,} tokens in a minute, "
            f"{heavy.tokens / limit:.0%} of the key's {limit:,}, so only {allows} can run at full speed "
            f"together. {e.users} users at once would need {together:,} tokens a minute, "
            f"{together / limit:.1f} times the limit."
        )
    return (
        f"**The API key's token limit is not the bottleneck at {e.users} users at once:** they would need "
        f"{together:,} tokens a minute, {together / limit:.0%} of the key's {limit:,}."
    )


def pace_note(e: Evidence, limit: int) -> list[str]:
    """When TSG paces its own requests below the limit, what that does to the measured minutes."""
    if not pace(e):
        return []
    return [
        f"TSG holds its own threat scenario requests to {pace(e):,} tokens a minute ({PACE_SETTING}) to stay "
        f"under the key's {limit:,}, so no measured minute can show more than that: the real need is at "
        "least what this table shows, and the requests held back wait (proof 5).",
        "",
    ]


def proof_lines(e: Evidence, limit: int) -> list[str]:
    """The proof from the runs, in plain words, each with the section that shows it in full."""
    refused, in_sessions = sum(a.refused for a in e.attempts), sum(s.refused for s in e.sessions)
    (tokens, at), runs = peak(e, "tokens"), scenario_runs(e)
    idle, total = sum(r.work.idle for r in runs), sum(r.work.seconds for r in runs) or 1.0
    binding, logged = lowest(e, "tokens"), len(logged_429s(e.logs or []))
    said = (
        f"`{binding.source}`"
        if binding and e.budget_read
        else "none stated; the limit was given with --budget"
    )
    quoted = (
        f"; {many(logged, 'refusal')} quoted from the worker logs with the limit and what was left"
        if logged
        else ""
    )
    paced = f" (TSG paces itself at {pace(e):,} tokens a minute to stay under the limit)" if pace(e) else ""
    return [
        f"1. **The limit, in the gateway's own words:** {said}, checked {e.checked:%Y-%m-%d %H:%M} UTC "
        "(section 1).",
        f"2. **The gateway refused {many(refused, 'request')} because of the limit (HTTP 429)**, "
        f"{in_sessions:,} of them in threat scenario sessions{quoted} (sections 1 and 2).",
        f"3. **TSG's demand peaked at {tokens:,} tokens in one minute** ({when(at)} UTC): "
        f"{tokens / limit:.0%} of the key's limit (est.; each session's minutes are in section 5).",
        f"4. {verdict(e)} (section 3)",
        f"5. **For {idle / total:.0%} of the threat scenario actions' time no request was in flight** "
        f"(est.): requests waiting to be sent{paced}, or the app's own work (section 4).",
    ]  # fmt: skip


def key_sentence(e: Evidence) -> str:
    """What TSG's key may use, in words."""
    own = cell([limit for found in e.limits.values() for limit in found if limit.scope == "key"], "tokens")
    binding = lowest(e, "tokens")
    if binding is None or not e.budget_read:
        return (
            f"**TSG's key:** the gateway states no tokens-per-minute limit; {e.budget:,} was given with "
            "--budget."
        )
    if binding.scope == "key":
        return f"**TSG's key** has its own limit, **{binding.value:,} tokens per minute**, the lowest one."
    said = (
        f"has its own limit of {own} tokens per minute, above the {binding.scope}'s"
        if own[0].isdigit()
        else "has no token limit of its own: the gateway says none is set"
        if own == "none set"
        else "has no token limit of its own that the gateway states"
        if own == "not stated"
        else f"has no token limit of its own that the gateway states: its own settings are {own}"
    )
    if binding.scope == "model":
        return (
            f"**TSG's key** {said}; the limit is the model's own capacity, **{binding.value:,} tokens per "
            "minute**."
        )
    return (
        f"**TSG's key** {said}. It shares the {binding.scope}'s **{binding.value:,} tokens per minute** with "
        f"every other key of that {binding.scope}. That is the most TSG can use, and less while other keys "
        "use it."
    )


def need_lines(e: Evidence, limit: int) -> list[str]:
    """Table 2: what each threat scenario action needs in one minute, against the key's limit."""
    header = ["Threat scenario action", "Runs measured", "Takes, median", "Tokens used, median",
              "Busiest minute: tokens / requests (est.)", "Of the key's limit",
              f"{e.users} users at once: tokens / requests (est.)", "Of the key's limit",
              "Runs at once the limit allows"]  # fmt: skip
    return [
        "## Table 2. What threat scenario generation needs in one minute",
        "",
        "Measured from the UAT runs as the gateway counts a minute: a running request holds its prompt and "
        "its whole answer cap, a finished one what it used (est.). 'Takes' is from an action's first AI "
        "request to its last answer.",
        "",
        *table(header, need_rows(e, limit)),
        *pace_note(e, limit),
    ]


def stated(limits: list, kind: str):
    """The lowest limit of `kind` the gateway states in `limits`; None for none."""
    found = [limit for limit in limits if limit.kind == kind and limit.value]
    return min(found, key=lambda limit: limit.value, default=None)


def source_sentence(e: Evidence) -> str:
    """Where the limit comes from: the gateway, when it was asked, its own words, the models sharing it."""
    model = next((m for m in e.limits if "scenario" in m.rsplit("(", 1)[-1]), next(iter(e.limits), ""))
    where = model.split(" @ ", 1)[-1].rsplit(" (", 1)[0] if model else "the gateway"
    tokens, requests = stated(scenario_limits(e), "tokens"), stated(scenario_limits(e), "requests")
    if tokens is None or not e.budget_read:
        return (
            f"**The gateway at {where} states no tokens-a-minute limit** (its answers: section 1); "
            f"{e.budget:,} was given with --budget."
        )
    per_minute = f"{tokens.value:,} tokens" + (f" and {requests.value:,} requests" if requests else "")
    sharing = [m.split(" @ ")[0] for m, found in e.limits.items()
               if any(lim.kind == "tokens" and lim.scope == tokens.scope and lim.value == tokens.value
                      for lim in found)]  # fmt: skip
    shared = (
        "the model's own capacity, its alone"
        if tokens.scope == "model"
        else f"set at the {tokens.scope} level, so every model this key uses shares it: {', '.join(sharing)}"
    )
    others = [m.split(" @ ")[0] for m in e.limits if m.split(" @ ")[0] not in sharing]
    rest = f" Other models state other limits: {', '.join(others)} (section 1)." if others else ""
    return (
        f"**Limit read from {where}** at {e.checked:%Y-%m-%d %H:%M} UTC: **{per_minute} a minute**, "
        f"{shared}. The gateway's own words: `{tokens.source}`.{rest}"
    )


def head_lines(e: Evidence) -> list[str]:
    """The page for the support team: the answer, the two tables, the proof and the request."""
    limit, models = key_limit(e), [model for model in e.limits if "scenario" in model.rsplit("(", 1)[-1]]
    actions = sum(len(s.runs) for s in e.sessions)
    return [
        "# UAT threat scenario generation: the API key's token limit",
        "",
        f"{covers(e)}, UAT: {many(len(e.sessions), 'threat scenario session')}, {many(actions, 'action')}.",
        "",
        source_sentence(e),
        "",
        bottleneck(e, limit),
        "",
        *waits_section(e, limit),
        "## Table 1. What the API key can use in one minute",
        "",
        f"As the gateway states it for {short(models[0]) if models else 'the models'}, checked "
        f"{e.checked:%Y-%m-%d %H:%M} UTC (every model: section 1).",
        "",
        *table(KEY_HEADER, key_table(scenario_limits(e)), left="lrrl"),
        key_sentence(e),
        "",
        *need_lines(e, limit),
        "## The proof from the UAT runs",
        "",
        *proof_lines(e, limit),
        "",
        f"**Request to support:** users wait on the limit. {wait_sentence(e, limit)} Please raise the key's "
        f"**{limit:,} tokens per minute**, or advise how it can be raised for a controlled UAT test; Table 2 "
        "shows what the threat scenarios need.",
        "",
        "Values marked **(est.)** are estimated; waiting time the records cannot measure is marked *not "
        "measured* (section 6).",
        "",
        "---",
        "",
        "# The detail",
        "",
    ]


def gateway_evidence(e: Evidence) -> list[str]:
    """The gateway's own words with their times: its answers when checked, and the logged 429s."""
    logged, counted = logged_429s(e.logs or []), gateway_counter(e.attempts)
    quoted = [logged_line(entry, counted) for entry in logged[:LOGGED_SHOWN]]
    more = [f"... and {len(logged) - LOGGED_SHOWN} more logged 429s"] if len(logged) > LOGGED_SHOWN else []
    refused = sorted(a.end for a in e.attempts if a.refused)
    records = (
        f"TSG's own records: {many(len(refused), 'token-limit error')} (429), the first at "
        f"{when(refused[0], '%Y-%m-%d %H:%M:%S')} and the last at {when(refused[-1], '%H:%M:%S')} UTC."
        if refused
        else "TSG's own records: no token-limit error (429) in this range."
    )
    if e.logs is None:
        note = (
            "429 messages (limit, remaining, limit type): not given; run with --logs (the worker pods' logs)."
        )
    else:
        note = (
            f"Worker logs given: {many(len(logged), 'logged 429')} (one is logged when a request gives up)."
        )
    return ["**Gateway evidence**, word for word:", "", "```", *e.gateway, *quoted, *more, "```", "",
            records, note, ""]  # fmt: skip


def limits_section(e: Evidence) -> list[str]:
    """Section 1: every model's limits, the one that applies, and the gateway's own words."""
    ended = max((run.end for s in e.sessions for run in s.runs), default=0.0)
    after = ", after every session below" if e.sessions and e.checked.timestamp() > ended else ""
    binding = lowest(e, "tokens")
    whose = (
        f"the {binding.scope}'s, the lowest the gateway states: `{binding.source}`"
        if e.budget_read and binding
        else "given with --budget: the gateway states no tokens-a-minute limit"
    )
    tables = [
        line
        for model, found in e.limits.items()
        for line in (f"**{short(model)}**", "", *table(KEY_HEADER, key_table(found), left="lrrl"))
    ]
    return [
        f"## 1. Every model's limits (checked {e.checked:%Y-%m-%d %H:%M} UTC{after})",
        "",
        *tables,
        f"**Applicable limit: {e.budget:,} tokens per minute** ({whose}).",
        "",
        *gateway_evidence(e),
    ]


def compared(runs: list[Run]) -> tuple[float, float] | None:
    """(median minutes, median model seconds per chat request) of some actions; None for none."""
    if not runs:
        return None
    responses = [seconds for run in runs for seconds in run.work.chat_responses]
    return statistics.median(run.work.seconds / 60 for run in runs), median(responses) or 0.0


def similar_findings(e: Evidence) -> list[tuple[str, tuple[float, float], tuple[float, float]]]:
    """(action, with 429s, without) for each scenario action that ran both with a 429 and without."""
    found = []
    for api in SCENARIO_ACTIONS:
        runs = [run for run in scenario_runs(e) if run.first.api == api]
        slow, fast = (
            compared([r for r in runs if r.work.refused]),
            compared([r for r in runs if not r.work.refused]),
        )
        if slow and fast:
            found.append((ACTIONS[api], slow, fast))
    return found


def verdict(e: Evidence) -> str:
    """Whether token-limit errors added delay, from the numbers."""
    refused, (tokens, _) = sum(a.refused for a in e.attempts), peak(e, "tokens")
    if not refused:
        return (
            "The evidence does not show the token limit as the cause in this range: the gateway refused no "
            f"request, and TSG's estimated demand peaked at {tokens / e.budget:.0%} of the limit."
        )
    if not any(run.work.refused for run in scenario_runs(e)):
        return (
            f"The gateway refused {refused} requests with 429, none of them in a threat scenario session: in "
            "this range the refusals did not slow the sessions."
        )
    found = similar_findings(e)
    slower = [(action, slow, fast) for action, slow, fast in found if slow[0] > fast[0]]
    if not slower:
        return (
            f"The gateway refused {refused} requests with 429, but similar actions with them are not slower "
            "than without (or none ran both ways): further investigation is needed."
        )
    said = [
        f"{action} took a median {slow[0]:.1f} minutes with a 429 against {fast[0]:.1f} without, the model "
        f"answering each chat request in {slow[1]:,.0f} s against {fast[1]:,.0f} s ("
        + ("so the extra time is waiting, not a slower model)" if slow[1] <= 1.2 * fast[1] else
           "so part of the extra time is the model answering slower)")
        for action, slow, fast in slower
    ]  # fmt: skip
    return "The evidence confirms that token-limit errors added delay: " + "; ".join(said) + "."


def summary_section(e: Evidence) -> list[str]:
    """Section 2: the counts and the conclusion."""
    (tokens, at), (requests, requests_at) = peak(e, "tokens"), peak(e, "requests")
    refused, in_sessions = sum(a.refused for a in e.attempts), sum(s.refused for s in e.sessions)
    used, runs = sum(a.tokens for a in e.attempts if not a.refused), scenario_runs(e)
    idle, total = sum(r.work.idle for r in runs), sum(r.work.seconds for r in runs) or 1.0
    actions = sum(len(s.runs) for s in e.sessions)
    rows = [
        ["Threat scenario sessions", f"{len(e.sessions)} ({many(actions, 'action')})"],
        ["Sessions with token-limit errors (429)", str(sum(bool(s.refused) for s in e.sessions))],
        ["Token-limit errors (429)", f"{refused:,} ({in_sessions:,} of them in these sessions)"],
        ["AI requests sent and tokens used", f"{len(e.attempts):,} requests, {used:,} tokens"],
        ["Requests the model did not respond to", no_response(e.attempts)],
        ["Peak estimated demand (est.)", f"{tokens:,} tokens per minute at {when(at)} UTC: "
                                          f"{tokens / e.budget:.0%} of the limit"],
        ["Peak requests (est.)", f"{requests:,} requests per minute at {when(requests_at)} UTC"],
    ]  # fmt: skip
    found = [verdict(e)] if e.sessions else ["No threat scenario session made AI calls in this range."]
    return [
        "## 2. Summary",
        "",
        *table(["Measure", "Result"], rows, left=2),
        *found,
        "",
        f"Not attributed: {idle / total:.0%} of the scenario actions' time ({idle:,.0f} of {total:,.0f} s) "
        "had no request in flight (est., section 4): TSG waiting to send, or its own work.",
        "",
    ]


def compare_row(label: str, runs: list[Run]) -> list[str]:
    """One group of similar actions: their medians."""

    def middle(value: Callable[[Run], float]) -> str:
        return shown(median([value(run) for run in runs]))

    responses = median([seconds for run in runs for seconds in run.work.chat_responses])
    no_answer = f"{sum(r.work.refused for r in runs)} / {sum(r.work.unanswered for r in runs)}"
    return [label, str(len(runs)), middle(lambda r: r.work.seconds), shown(responses),
            middle(lambda r: r.work.idle), middle(lambda r: r.work.retry_wait), no_answer,
            str(sum(r.work.unusable for r in runs)),
            shown(median([r.demand for r in runs]), "{:.0%}")]  # fmt: skip


def compare_section(e: Evidence) -> list[str]:
    """Section 3: similar actions (the same API) with and without 429s."""
    rows = []
    for api in SCENARIO_ACTIONS:
        runs = [run for run in scenario_runs(e) if run.first.api == api]
        if runs:
            rows.append(compare_row(f"{ACTIONS[api]}, with 429s", [r for r in runs if r.work.refused]))
            rows.append(compare_row(f"{ACTIONS[api]}, without", [r for r in runs if not r.work.refused]))
    header = ["Similar actions", "Count", "Time, median (s)", "Model response per chat request, median (s)",
              "No request in flight, est., median (s)", "Waited before retrying, median (s)",
              "No response: 429 / other", "Unusable answers",
              "Estimated demand, median % of the limit"]  # fmt: skip
    return [
        "## 3. Similar sessions with and without token-limit errors",
        "",
        "Each action of a session (an API request) against the same action elsewhere; times are from its "
        "first AI request to its last answer.",
        "",
        *table(header, rows),
    ]


def report_lines(e: Evidence) -> list[str]:
    """The whole report: the page for the support team, then the detail."""
    return [
        *head_lines(e),
        *limits_section(e),
        *summary_section(e),
        *compare_section(e),
        *app_side_section(e),
        *sessions_section(e),
        *gaps_section(e),
        "## 7. TSG's own settings",
        "",
        "```",
        *e.settings,
        "```",
        "",
    ]
