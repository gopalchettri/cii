"""The AI budget evidence (scripts/ai_budget_evidence.py, its measures and its report) on hand-made usage
rows, saved pod logs and a fake gateway: every second of an action in one bucket, each stage's times, the
gateway's count each minute, the limits by whose they are, and a verdict that can also say "not the limit".
Each test names the mutation it catches."""

import importlib
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
try:
    measures = importlib.import_module("ai_budget_measures")
    report = importlib.import_module("ai_budget_report")
    evidence = importlib.import_module("ai_budget_evidence")
    limits_check = importlib.import_module("ai_limits_check")  # imported by the script as it asks the gateway
    waits = importlib.import_module("ai_budget_waits")
finally:
    sys.path.remove(str(REPO / "scripts"))

CAPS = {"relevance_gate": 10_240, "write_scenario": 6_144, "plan_check": 3_072}
T0 = datetime(2026, 10, 30, 9, 0, tzinfo=UTC)
BUDGET = 25_000
KEY = "sk-secret-key"
FIND, WRITE = "tsg_find_threats", "tsg_write_scenarios"


def _row(task: str, start: float, seconds: float, tokens=(0, 0), **row) -> dict:
    """A tsg_ai_usage row of request r1's Create scenario, noted as its attempt ends."""
    return {"created_at": T0 + timedelta(seconds=start + seconds), "seconds": seconds, "task": task,
            "model": "litellm_proxy/kimi-k2.5", "outcome": "ok", "tokens_in": tokens[0],
            "tokens_out": tokens[1], "module": "threat_scenarios", "api": "create_scenario",
            "request_id": "r1", "session_id": "s1", "ask_id": f"{task}-{start}", "job_task": WRITE,
            "attempt": 1, **row}  # fmt: skip


def _refused(task: str, start: float, ask: str, **row) -> dict:
    return _row(task, start, 0.5, outcome="unavailable", error_type="RateLimitError", ask_id=ask, **row)


#: One Create scenario, 96 s. Finding threats: the embed (0-1), the gate refused (1-1.5) and asked again after
#: 20 s (21.5-41.5). Then 8.5 s with no request in flight. Writing: the writer (50-80), the plan check timed
#: out (80-90) and asked again 1 s later (91-96). Answering 56 s, refused 20.5, other failures 11, idle 8.5.
R1 = [
    _row("embed", 0, 1, (100, 0), job_task=FIND),
    _refused("relevance_gate", 1, "gate", job_task=FIND),
    _row("relevance_gate", 21.5, 20, (5_000, 2_000), ask_id="gate", job_task=FIND),
    _row("write_scenario", 50, 30, (3_000, 1_500)),
    _row("plan_check", 80, 10, outcome="unavailable", error_type="Timeout", ask_id="check"),
    _row("plan_check", 91, 5, (1_000, 200), ask_id="check"),
]
#: A Create scenario ten minutes later, in another session, with no 429: the gate alone, 50 s.
R4 = [_row("relevance_gate", 600, 50, (5_000, 2_000), request_id="r4", session_id="s4", job_task=FIND)]
#: UAT 2026-10-29: the key's own settings refused, the team's 2,000,000 tokens and the organisation's 25,000.
REFUSED_KEY = "/key/info HTTP 403: this key may not read it"
LIMITS = {
    "kimi-k2.5 @ https://gw.test (scenario)": [
        limits_check.Limit("key", "tokens", None, REFUSED_KEY),
        limits_check.Limit("key", "requests", None, REFUSED_KEY),
        limits_check.Limit("team", "tokens", 2_000_000, "x-ratelimit-team-limit-tokens 2000000"),
        limits_check.Limit("organisation", "tokens", 25_000, "x-ratelimit-organization-limit-tokens 25000"),
        limits_check.Limit("organisation", "requests", 3_780, "x-ratelimit-organization-limit-requests 3780"),
        limits_check.Limit("model", "requests", 600, "/model/info litellm_params.rpm 600"),
    ]
}


def _evidence(rows: list[dict], logs: list[dict] | None = None, limits: dict = LIMITS) -> object:
    attempts = measures.attempts_of(rows, CAPS)
    minutes = measures.minutes_of(attempts)
    app_times = {"r1": {"threats_s": 61.0, "scenarios_s": 40.0}}
    sessions = measures.sessions_of(attempts, minutes, BUDGET, app_times)
    gateway = ["2026-10-30 11:00:00 UTC  limits check, the gateway's answers:", "  headers x-ratelimit-..."]
    return measures.Evidence(
        T0, T0 + timedelta(hours=1), attempts, minutes, sessions, BUDGET, True, T0 + timedelta(hours=2),
        limits, gateway, logs, ["CII_SCENARIO_CHAT_TOKENS_PER_MINUTE=24000"],
    )  # fmt: skip


def _text(rows: list[dict], logs: list[dict] | None = None) -> str:
    return "\n".join(report.report_lines(_evidence(rows, logs)))


def test_every_second_of_an_action_is_in_one_bucket_and_they_add_up_to_its_span() -> None:
    """Mutation: the gap after a 429 left out (refused 0.5), the gap after a timeout put with the 429s, or a
    reused answer counted as an attempt."""
    rows = [*R1, {**R1[3], "outcome": "reused", "seconds": None}]
    attempts = measures.attempts_of(rows, CAPS)
    buckets = measures.split(attempts)
    assert buckets == {
        measures.ANSWERING: 56.0,
        measures.FAILING: 11.0,
        measures.REFUSED: 20.5,
        measures.IDLE: 8.5,
    }
    assert sum(buckets.values()) == pytest.approx(96.0) and len(attempts) == len(R1)


def test_an_answering_call_wins_over_another_calls_429_wait() -> None:
    """While one call answers, a second call's wait after its 429 is not counted as refused time (waiting is
    never over-counted). Mutation: the refused bucket ahead of answering (20 s refused)."""
    rows = [
        _row("write_scenario", 0, 30),
        _refused("plan_check", 5, "p"),
        _row("plan_check", 25, 10, ask_id="p"),
    ]
    buckets = measures.split(measures.attempts_of(rows, CAPS))
    assert buckets[measures.ANSWERING] == 35.0 and buckets[measures.REFUSED] == 0.0


def test_a_job_retried_later_after_its_ask_gave_up_on_a_429_is_refused_time() -> None:
    """Mutation: the wait between a job's deliveries not counted (119.5 s idle)."""
    rows = [_refused("write_scenario", 0, "a"), _row("write_scenario", 120, 10, ask_id="b", attempt=2)]
    attempts = measures.attempts_of(rows, CAPS)
    buckets, work = measures.split(attempts), measures.work_of(attempts)
    assert buckets[measures.REFUSED] == 120.0 and buckets[measures.IDLE] == 0.0
    assert (work.retries, work.retry_wait) == (1, 119.5)


def test_each_minute_counts_tokens_and_the_peak_the_gateway_counts() -> None:
    """As the writer starts (50 s) the embed (100) and the gate (7,000) have finished and the writer holds
    3,000 + its 6,144 cap: 16,244; the refused try is a request but no tokens. Mutation: a finished call kept
    at its hold, the cap not held, or a refused try counted as tokens or not as a request."""
    minutes = measures.minutes_of(measures.attempts_of(R1, CAPS))
    first, second = minutes[int(T0.timestamp() // 60)], minutes[int(T0.timestamp() // 60) + 1]
    assert (first.refused, first.tokens, first.peak_tokens, first.peak_requests) == (1, 11_600, 16_244, 4)
    assert (second.tokens, second.peak_tokens) == (1_200, 11_500)


def test_each_stage_shows_its_time_requests_model_time_429s_and_retry_waits() -> None:
    """Finding threats: 41.5 s, 2 requests, the model 1 and 20 s, one 429 retried 20 s later. Writing: 46 s,
    a timeout retried 1 s later. The action: 96 s with 8.5 s idle between the stages. Mutation: idle taken
    from the whole action into each stage, the retry wait measured from the failed try's start, a 429
    counted as no response for another reason, or a retry counted as a request of its own."""
    text = _text(R1 + R4)
    assert "| Threat Identification | 42 | 2 | 7,100 | 10 / 20 | 0 | 1 / 0 | 0 | 1 | 20 |" in text
    assert "| Scenario Writing | 46 | 2 | 5,700 | 18 / 30 | 0 | 0 / 1 | 0 | 1 | 1 |" in text
    assert "| **All stages** |  | 96 | 4 | 12,800 | 12 / 30 | 8 | 1 / 1 | 0 | 2 | 21 |" in text


def test_section_1_has_each_models_table_and_the_limit_that_applies() -> None:
    """The model's 600 requests, the key refused, the team's 2,000,000 tokens and the organisation's 25,000
    tokens and 3,780 requests. Mutation: the highest limit applying, a team limit shown as the key's own, or
    a refused key shown as having no limit."""
    text = _text(R1 + R4)
    section = text[
        text.index("## 1. Every model's limits (checked 2026-10-30 11:00 UTC, after every session") :
    ]
    rows = [
        "**kimi-k2.5 (scenario)**",
        "",
        "| Per minute, unless said | Tokens | Requests | Notes |",
        "|---|---:|---:|---|",
        "| The model's own capacity | not stated | 600 | shared by every caller of the model |",
        "| This key's own limit | not readable (HTTP 403) | not readable (HTTP 403) | for this key alone |",
        "| The key's team | 2,000,000 | not stated | shared by every key of that team |",
        "| The key's organisation | 25,000 | 3,780 | shared by every key of that organisation |",
    ]
    assert "\n".join(rows) in section
    assert (
        "**Applicable limit: 25,000 tokens per minute** (the organisation's, the lowest the gateway states: "
        "`x-ratelimit-organization-limit-tokens 25000`)."
    ) in section
    assert (
        "TSG's key: tokens not readable (HTTP 403), requests not readable (HTTP 403); **applies to TSG: "
        "25,000 tokens** (the lowest, section 1)."
    ) in text


def test_the_summary_counts_sessions_429s_requests_and_the_peak() -> None:
    """Mutation: the peak taken from tokens used, a refused try's tokens counted, a session with a 429
    counted as clear, or a 429 left out of the requests the model did not respond to."""
    text = _text(R1 + R4)
    assert "| Threat scenario sessions | 2 (2 actions) |" in text
    assert "| Sessions with token-limit errors (429) | 1 |" in text
    assert "| Token-limit errors (429) | 1 (1 of them in these sessions) |" in text
    assert "| AI requests sent and tokens used | 7 requests, 19,800 tokens |" in text
    assert (
        "| Requests the model did not respond to | 2 of 7: 1 refused by the limit (429); others: Timeout x1 |"
    ) in text
    assert (
        "| Peak estimated demand (est.) | 16,244 tokens per minute at 2026-10-30 09:00 UTC: 65% of the "
        "limit |" in text
    )
    assert "Please raise the key's **25,000 tokens per minute**" in text


def test_the_verdict_confirms_the_limit_only_when_the_numbers_do() -> None:
    """With a 429 and a slower action at the same model time: confirmed. A slower model: said so. With no
    429: not the limit. With no session: says so. Mutation: the verdict always confirming, comparing the
    search calls' time, or blaming the limit for a slower model."""
    assert (
        "The evidence confirms that token-limit errors added delay: Create scenario took a median 1.6 "
        "minutes with a 429 against 0.8 without, the model answering each chat request in 20 s against 50 s "
        "(so the extra time is waiting, not a slower model)."
    ) in _text(R1 + R4)
    quick = [{**R4[0], "seconds": 10, "created_at": T0 + timedelta(seconds=610)}]
    assert "the model answering slower" in _text(R1 + quick)
    assert "does not show the token limit as the cause" in _text(R4)
    assert "No threat scenario session made AI calls in this range." in _text([])


def test_the_page_for_support_answers_in_plain_words_with_both_tables_and_the_proof() -> None:
    """Before the detail: the answer, Table 1 (the key's limits a minute), Table 2 (what a Create scenario
    needs a minute: 16,244 tokens in 3 requests at its busiest, 5 users 81,220, the limit allows 1 at once),
    the proof and the request. Mutation: the key's limit not the lowest, the need not set against it, or
    the users' need not their count times one action's."""
    text = _text(R1 + R4)
    page = text[: text.index("# The detail")]
    assert (
        "**The API key's token limit is the bottleneck as soon as 2 users use it at once.** One Create "
        "scenario needs up to 16,244 tokens in a minute, 65% of the key's 25,000, so only 1 can run at full "
        "speed together. 5 users at once would need 81,220 tokens a minute, 3.2 times the limit."
    ) in page
    assert (
        page.index("## Table 1.") < page.index("## Table 2.") < page.index("## The proof from the UAT runs")
    )
    assert "| **Most this key can use in one minute** | **25,000** | **600** |" in page
    assert "| Create scenario | 2 | 1.2 min | 9,900 | 16,244 / 3 | 65% | 81,220 / 15 | 325% | 1 |" in page
    assert "TSG holds its own threat scenario requests to 24,000 tokens a minute" in page
    assert (
        "1. **The limit, in the gateway's own words:** `x-ratelimit-organization-limit-tokens 25000`" in page
    )
    assert "2. **The gateway refused 1 request because of the limit (HTTP 429)**, 1 of them in" in page
    assert "3. **TSG's demand peaked at 16,244 tokens in one minute** (2026-10-30 09:00 UTC): 65% of" in page
    assert "4. The evidence confirms that token-limit errors added delay" in page
    assert "Please raise the key's **25,000 tokens per minute**" in page
    assert (
        "**TSG's key** has no token limit of its own that the gateway states: its own settings are not "
        "readable (HTTP 403). It shares the organisation's **25,000 tokens per minute** with every other key "
        "of that organisation. That is the most TSG can use, and less while other keys use it."
    ) in page


def test_the_key_sentence_says_whether_the_key_has_a_limit_of_its_own() -> None:
    """A key whose limit is none: said so. A key with its own limit, the lowest: it applies. Mutation: a
    key set to none read as refused, or the key's own limit left out."""
    model = "kimi-k2.5 @ https://gw.test (scenario)"
    org = limits_check.Limit("organisation", "tokens", 25_000, "x-ratelimit-organization-limit-tokens 25000")
    none_set = limits_check.Limit("key", "tokens", None, "/key/info tpm_limit none set")
    own = limits_check.Limit("key", "tokens", 10_000, "x-ratelimit-api_key-limit-tokens 10000")
    assert "the gateway says none is set. It shares the organisation's" in report.key_sentence(
        _evidence(R4, limits={model: [none_set, org]})
    )
    assert "has its own limit, **10,000 tokens per minute**, the lowest one." in report.key_sentence(
        _evidence(R4, limits={model: [own, org]})
    )


def test_the_answer_says_when_the_limit_is_and_is_not_the_bottleneck() -> None:
    """Request r1's busiest minute as the gateway counts it is as the writer starts: the embed's 100 and the
    gate's 7,000 used, the writer's 9,144 held: 16,244; the refused try and the timeout would not be sent.
    A key of 10,000 holds even one back; one of 100,000 fits 5 users. Mutation: one user's need, a refused
    try counted, or the limit called the bottleneck when it is not."""
    model = "kimi-k2.5 @ https://gw.test (scenario)"

    def key(tokens: int) -> dict:
        return {model: [limits_check.Limit("organisation", "tokens", tokens, f"org {tokens}")]}

    assert (
        "**The API key's token limit is the bottleneck.** One Create scenario needs up to 16,244 tokens in a "
        "minute, but the key may use only 10,000 tokens a minute: even one user has to wait."
    ) in "\n".join(report.report_lines(_evidence(R1 + R4, limits=key(10_000))))
    assert (
        "**The API key's token limit is not the bottleneck at 5 users at once:** they would need 81,220 "
        "tokens a minute, 81% of the key's 100,000."
    ) in "\n".join(report.report_lines(_evidence(R1 + R4, limits=key(100_000))))


def test_the_answer_leads_with_todays_wait_and_the_page_says_today() -> None:
    """Create scenario r1 96 s and r4 50 s: a median 1.2 min, 0.9 of it answering (56 and 50 s); 5 users need
    5 x 9,900 tokens, 2.0 min at 25,000 a minute. Mutation: the wait left out of the answer, or the floor
    taken for one user."""
    text = _text(R1 + R4)
    assert (
        "Today one Create scenario took a median 1.2 min, 0.9 of it the model answering; 5 users at once "
        "wait at least 2.0 min for the last result from the limit alone. **The API key's token limit is"
    ) in text
    assert "**Request to support:** users wait on the limit. Today one Create scenario took a median" in text
    assert text.index("## How long users waited today, and why") < text.index("## Table 1.")
    today = _evidence(R1 + R4)
    today.since, today.until = T0.replace(hour=0), T0.replace(hour=14, minute=21)
    assert report.covers(today) == "Today, 2026-10-30, 00:00 to 14:21 UTC"
    assert report.covers(_evidence(R4)) == "From 2026-10-30 09:00 to 2026-10-30 10:00 UTC"


def test_the_floor_is_n_times_the_tokens_over_the_limit() -> None:
    """The plan's worked example: 3 users of 36,000 tokens at 25,000 a minute wait at least 4.3 min; here the
    median Create scenario used 9,900. Mutation: N not multiplied in, or the floor flipped."""
    assert waits.floor_minutes(36_000, 25_000, 3) == pytest.approx(4.32)
    text = _text(R1 + R4)
    assert "| 1 | 9,900 | 0.4 min |" in text and "| 5 | 49,500 | 2.0 min |" in text
    assert "| 10 | 99,000 | 4.0 min |" in text


def test_two_overlapping_sessions_count_as_two_users_at_once() -> None:
    """Session s5 writes at 30-35 s while s1's Create scenario runs (0-96 s); s4's runs alone at 600 s. With
    nothing overlapping, the report says how to measure it. Mutation: the other sessions not counted."""
    other = _row("write_scenario", 30, 5, (2_000, 500), request_id="r5", session_id="s5")
    together = _evidence([*R1, other, *R4])
    counts = {run.request: waits.users_at_once(run, together) for run in waits.scenario_runs(together)}
    assert counts == {"r1": 2, "r5": 2, "r4": 1}
    rows = [row[:3] for row in waits.together_rows(together)]
    assert rows == [["Create scenario", "1", "1"], ["Create scenario", "2", "2"]]
    assert "Nothing overlapped today" in _text(R1 + R4) and "Nothing overlapped today" not in _text(
        [*R1, other, *R4]
    )


def test_one_clicks_wait_splits_into_parts_that_add_up_to_it() -> None:
    """R1, 96 s: answering 56, refused 20.5, other failures 11, no request in flight 8.5. Mutation: a part
    left out, or the shares taken of another run's time."""
    (run,) = waits.scenario_runs(_evidence(R1))
    assert sum(waits.parts_of([run]).values()) == pytest.approx(run.work.seconds) == 96.0
    assert "| Create scenario | 1 | 1.6 min | 58% | 21% | 11% | 9% | 12,800 | 0.5 min |" in _text(R1)


def test_the_busiest_minutes_tokens_by_module_add_up_to_the_minutes_tokens() -> None:
    """Minute 09:00: the scenarios' gate and writer 11,500, a remediation check 1,500, the embed's 100 as
    search. Mutation: a search call put under its module, or a column dropped."""
    plan = _row("plan_check", 40, 5, (1_000, 500), module="remediation", api="create_plan", request_id="p1")
    e = _evidence([*R1, plan])
    (minute,) = [m for at, m in e.minutes.items() if at == int(T0.timestamp() // 60)]
    used = waits.minute_tokens(e)[int(T0.timestamp() // 60)]
    assert sum(used.values()) == minute.tokens == 13_100
    assert "| 09:00 | 11,500 | 1,500 | 0 | 100 | 0 | 13,100 |" in _text([*R1, plan])


def test_the_page_names_the_gateway_the_limit_was_read_from_and_its_words() -> None:
    """The limit is read from the gateway, never assumed: its address, when, its stated tokens and requests a
    minute, the level it is set at and every model sharing it. Mutation: the source left out, a model of
    another limit listed as sharing it, or a limit given with --budget shown as read."""
    shared = {**LIMITS, "qwen3-embedding-8b @ https://gw.test (embedding)": [
        limits_check.Limit("organisation", "tokens", 25_000, "x-ratelimit-organization-limit-tokens 25000")],
        "glm-5.3 @ https://gw.test (remediation)": [
        limits_check.Limit("model", "tokens", 300_000, "x-ratelimit-limit-tokens 300000")]}  # fmt: skip
    text = "\n".join(report.report_lines(_evidence(R1 + R4, limits=shared)))
    assert (
        "**Limit read from https://gw.test** at 2026-10-30 11:00 UTC: **25,000 tokens and 600 requests a "
        "minute**, set at the organisation level, so every model this key uses shares it: kimi-k2.5, "
        "qwen3-embedding-8b. The gateway's own words: `x-ratelimit-organization-limit-tokens 25000`. Other "
        "models state other limits: glm-5.3 (section 1)."
    ) in text
    given = _evidence(R1 + R4)
    given.budget_read = False
    assert "**The gateway at https://gw.test states no tokens-a-minute limit**" in report.source_sentence(
        given
    )


def test_429s_outside_every_session_are_not_blamed_on_the_sessions() -> None:
    """Laptop, 2026-10-30: 19 refusals, all in work of no session (a replay). Mutation: the verdict reading
    that as "similar actions are not slower" (further investigation)."""
    replay = _refused("plan_check", 610, "replay", module=None, api=None, request_id=None, session_id=None)
    text = _text([*R4, replay])
    assert "none of them in a threat scenario session" in text and "further investigation" not in text
    assert "| Token-limit errors (429) | 1 (0 of them in these sessions) |" in text


def test_each_session_shows_when_its_total_time_the_app_times_and_its_minutes() -> None:
    """Another session writes at 30-35 s: its 2,500 tokens are TSG's, not session 1's, and its hold lifts the
    peak to 23,484 (embed 100, the running gate 15,240, its own 8,144). Mutation: the session's tokens taken
    from all TSG's, the limits' check dated from the session's start, or the app's own stage times not
    matched to their action."""
    other = _row("write_scenario", 30, 5, (2_000, 500), request_id="r5", session_id="s5")
    text = _text([*R1, other, *R4])
    assert "### Session 1: 2026-10-30 09:00 UTC (s1), 1.6 minutes in all" in text
    assert "checked 2026-10-30 11:00 UTC, 1 h 58 min after this session ended" in text
    assert "the app's own stage times: Threat Identification 61 s, Scenario Writing 40 s." in text
    assert "| 09:00 | 11,600 | 14,100 | 23,484 | 94% | 1 / 1 |" in text
    assert "| 09:10 | 7,000 | 7,000 | 15,240 | 61% | 0 / 0 |" in text
    assert "| Create scenario, with 429s | 1 | 96 | 20 | 8 | 21 | 1 / 1 | 0 | 75% |" in text


def test_logged_429s_are_quoted_with_the_gateways_count_against_ours(tmp_path: Path) -> None:
    """A saved log in PowerShell's UTF-16, with `--timestamps` prefixes and lines that are not JSON. At the
    429 logged 50 s in, the gateway had counted 22,900 and TSG 16,244; it shows in its session too.
    Mutation: the UTF-16 log read as UTF-8 (nothing found), or the gateway's count taken as its remaining."""
    lines = [
        "not json",
        "2026-10-30T09:00:50Z " + json.dumps({"event": "ai.call_unavailable", "status": 429,
            "timestamp": "2026-10-30T09:00:50Z", "retry_after": "60", "limit_type": "tokens",
            "limit_scope": "organization", "limit": 25_000, "limit_remaining": 2_100}),
        json.dumps({"event": "job.not_claimed", "reason": "not_due"}),
        json.dumps({"event": "ai.call", "seconds": 3}),
    ]  # fmt: skip
    saved = tmp_path / "worker.log"
    saved.write_text("\n".join(lines), encoding="utf-16")
    logs = evidence.read_logs([str(saved)])
    assert [entry["event"] for entry in logs] == ["ai.call_unavailable", "job.not_claimed"]
    text = _text(R1 + R4, logs)
    quoted = (
        "2026-10-30T09:00:50Z  HTTP 429 (worker log): limit type tokens, scope organization, limit 25000, "
        "remaining 2100, Retry-After 60: the gateway had counted 22,900, TSG's own calls 16,244 (est.)"
    )
    sessions = text.index("## 5. Each session")
    assert (
        quoted in text[:sessions]
        and quoted in text[text.index("### Session 1") : text.index("### Session 2")]
    )
    assert "| job.not_claimed | " in text and " | 1 |" in text


def test_a_key_section_set_to_none_or_refused_is_a_limit_with_no_value() -> None:
    """Mutation: a field set to none dropped, or a refused section dropped (the key reads 'not stated')."""
    assert limits_check.section_line("key", "/key/info", {"tpm_limit": None, "rpm_limit": 100})[1] == [
        limits_check.Limit("key", "tokens", None, "/key/info tpm_limit none set"),
        limits_check.Limit("key", "requests", 100, "/key/info rpm_limit 100"),
    ]
    assert limits_check.section_line("key", "/key/info", "HTTP 403: this key may not read it")[1] == [
        limits_check.Limit("key", "tokens", None, REFUSED_KEY),
        limits_check.Limit("key", "requests", None, REFUSED_KEY),
    ]


def test_answer_headers_name_whose_limit_and_its_window() -> None:
    """Azure states the model's own limit and its window; LiteLLM names the key's, team's or organisation's,
    and what is left of each. Mutation: a scoped header taken as the model's, or the window dropped."""
    found = limits_check.header_limits({
        "x-ratelimit-limit-tokens": "100000",
        "x-ratelimit-renewalperiod-tokens": "60",
        "x-ratelimit-organization-limit-tokens": "25000",
        "x-ratelimit-api_key-limit-requests": "50",
        "x-ratelimit-organization-remaining-tokens": "1200",
    })  # fmt: skip
    assert found == [
        limits_check.Limit("model", "tokens", 100_000, "x-ratelimit-limit-tokens 100000", 60),
        limits_check.Limit("organisation", "tokens", 25_000, "x-ratelimit-organization-limit-tokens 25000"),
        limits_check.Limit("key", "requests", 50, "x-ratelimit-api_key-limit-requests 50"),
        limits_check.Limit(
            "organisation", "tokens left", 1_200, "x-ratelimit-organization-remaining-tokens 1200"
        ),
    ]


def _gateway(monkeypatch: pytest.MonkeyPatch, headers: dict[str, str]) -> list[tuple[str, dict]]:
    """Every httpx client the script opens talks to a LiteLLM gateway whose /key/info is refused; each
    question it is asked, (page, body), is listed in what this returns."""
    asked: list[tuple[str, dict]] = []

    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path in ("/chat/completions", "/embeddings", "/rerank"):
            asked.append((request.url.path, json.loads(request.content)))
            return httpx.Response(200, json={}, headers=headers)
        if request.url.path == "/key/info":
            return httpx.Response(403, json={})
        return httpx.Response(200, json={"data": []})

    real = httpx.Client
    monkeypatch.setattr(
        httpx, "Client", lambda **options: real(transport=httpx.MockTransport(handle), **options)
    )
    return asked


GATEWAY_ENV = {
    "CII_SCENARIO_CHAT_BASE_URL": "https://gw.test",
    "CII_SCENARIO_CHAT_API_KEY": KEY,
    "CII_SCENARIO_CHAT_MODEL": "litellm_proxy/kimi-k2.5",
    "CII_REMEDIATION_CHAT_BASE_URL": "https://gw.test",
    "CII_REMEDIATION_CHAT_API_KEY": KEY,
    "CII_REMEDIATION_CHAT_MODEL": "litellm_proxy/glm-5.3",
}


def test_the_live_limits_are_read_per_model_without_the_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """UAT 2026-10-29: the organization's 25,000 tokens a minute, under the team's, for every model the key
    uses on the gateway, the embedding and rerank models too, each asked its own kind of tiny question.
    Mutation: a model's limits put under another model, a search model asked a chat question or left out,
    or the key printed."""
    asked = _gateway(monkeypatch, {
        "x-ratelimit-organization-limit-tokens": "25000",
        "x-ratelimit-team-limit-tokens": "2000000",
    })  # fmt: skip
    env = {
        **GATEWAY_ENV,
        "CII_EMBEDDING_BASE_URL": "https://gw.test",
        "CII_EMBEDDING_API_KEY": KEY,
        "CII_EMBEDDING_MODEL": "litellm_proxy/qwen3-embedding-8b",
        "CII_RERANK_BASE_URL": "https://gw.test",
        "CII_RERANK_API_KEY": KEY,
        "CII_RERANK_MODEL": "litellm_proxy/qwen3-reranker-8b",
    }
    lines, found, checked = evidence.live_limits(env)
    assert list(found) == [
        "kimi-k2.5 @ https://gw.test (scenario)",
        "glm-5.3 @ https://gw.test (remediation)",
        "qwen3-embedding-8b @ https://gw.test (embedding)",
        "qwen3-reranker-8b @ https://gw.test (rerank)",
    ]
    assert [page for page, _ in asked] == ["/chat/completions", "/chat/completions", "/embeddings", "/rerank"]
    assert asked[2][1] == {"model": "qwen3-embedding-8b", "input": "hi"}
    assert asked[3][1] == {"model": "qwen3-reranker-8b", "query": "hi", "documents": ["hi"]}
    assert [
        (limit.scope, limit.value)
        for limit in found["glm-5.3 @ https://gw.test (remediation)"]
        if limit.value
    ] == [
        ("organisation", 25_000),
        ("team", 2_000_000),
    ]
    assert lines[0].startswith(f"{checked:%Y-%m-%d %H:%M:%S} UTC") and KEY not in "\n".join(lines)


def test_by_default_the_report_reads_todays_runs() -> None:
    """The owner, 2026-10-30: today's date. Mutation: the range starting a day ago."""
    args, now = evidence.parse_args([]), datetime.now(UTC)
    assert args.since == now.replace(hour=0, minute=0, second=0, microsecond=0)
    assert args.since <= args.until <= now


def test_no_budget_named_and_none_given_stops_with_a_plain_message(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Mutation: a report written against no budget."""
    _gateway(monkeypatch, {})
    env_file = tmp_path / ".env.uat"
    env_file.write_text(
        "\n".join(f"{k}={v}" for k, v in {**GATEWAY_ENV, "CII_MONGO_URL": "mongodb://x"}.items())
    )
    with pytest.raises(SystemExit) as stopped:
        evidence.main(["--env-file", str(env_file)])
    assert stopped.value.code == evidence.NO_BUDGET


def test_the_whole_report_from_mongodb_read_only(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """End to end on the local MongoDB (a database of its own, dropped after): only the rows in the range are
    read, the session's latest action's own times are matched by its request, the lowest limit applies, and
    nothing is written. Mutation: the highest limit applying, or the times matched by the session."""
    from app.core.config import get_settings  # noqa: PLC0415
    from app.core.database import get_mongodb  # noqa: PLC0415

    database = get_mongodb().client[f"{get_settings().mongo_db}_budget_evidence"]
    database["tsg_ai_usage"].insert_many([*R1, {**R4[0], "created_at": T0 - timedelta(days=2)}])
    session = {"_id": "s1", "job": {"request_id": "r1"}, "timings": {"threats_s": 61.0, "scenarios_s": 40.0}}
    database["tsg_sessions"].insert_one(session)
    _gateway(
        monkeypatch,
        {"x-ratelimit-organization-limit-tokens": "25000", "x-ratelimit-team-limit-tokens": "2000000"},
    )
    env = {**GATEWAY_ENV, "CII_MONGO_URL": get_settings().mongo_url, "CII_MONGO_DB": database.name}
    env_file, out = tmp_path / ".env.uat", tmp_path / "evidence.md"
    env_file.write_text("\n".join(f"{k}={v}" for k, v in env.items()))
    try:
        counts = {name: database[name].count_documents({}) for name in ("tsg_ai_usage", "tsg_sessions")}
        since, until = T0.isoformat(), (T0 + timedelta(hours=1)).isoformat()
        options = ["--since", since, "--until", until, "--users", "2", "--out", str(out)]
        evidence.main(["--env-file", str(env_file), *options])
        assert counts == {name: database[name].count_documents({}) for name in counts}
    finally:
        database.client.drop_database(database.name)
    text = out.read_text(encoding="utf-8")
    assert (
        "| Threat scenario sessions | 1 (1 action) |" in text
        and "Please raise the key's **25,000 tokens per minute**" in text
    )
    assert "the app's own stage times: Threat Identification 61 s, Scenario Writing 40 s." in text
    assert "**Applicable limit: 25,000 tokens per minute**" in text
    assert "| 2 users at once: tokens / requests (est.) |" in text
    assert "CII_SCENARIO_CHAT_MODEL=litellm_proxy/kimi-k2.5" in text and KEY not in text
