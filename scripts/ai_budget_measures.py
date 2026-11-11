"""What the AI budget evidence measures (scripts/ai_budget_evidence.py): TSG's AI attempts as the gateway
counts them, each minute's tokens against the limit, and each session's actions and stages. No reading or
writing: the entry script reads, scripts/ai_budget_report.py writes."""

from __future__ import annotations

import statistics
from bisect import bisect_right
from collections import defaultdict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from itertools import pairwise

from ai_capacity_report import Call, busiest_minute

WINDOW_SECONDS = 60  # the gateway's tokens- and requests-a-minute window
USERS = 5  # users starting the same action at once, for the capacity they need
SCENARIO_MODULE = "threat_scenarios"
SCENARIO_ACTIONS = ("create_scenario", "next_set", "regenerate")
MODULES = {
    "threat_scenarios": "Threat Scenario",
    "remediation": "Remediation",
    "service_mapper": "Service Mapper",
}
ACTIONS = {
    "create_scenario": "Create scenario",
    "next_set": "Next set",
    "regenerate": "Regenerate",
    "create_plan": "Create plan",
    "create_mapping": "Create mapping",
}
STAGES = {
    "tsg_find_threats": "Threat Identification",
    "tsg_write_scenarios": "Scenario Writing",
    "tsg_map_controls": "Control Mapping",
    "tsg_write_plan": "Treatment Plan Writing",
    "tsg_map_services": "Service Mapping",
}
#: A session's own stage times (tsg_sessions.timings, its latest action only) -> the stage.
APP_TIMES = {
    "threats_s": "tsg_find_threats",
    "scenarios_s": "tsg_write_scenarios",
    "controls_s": "tsg_map_controls",
}
REFUSED_ERROR = "RateLimitError"  # a 429's error_type on its usage row
NOT_ANSWERED = ("unavailable", "error")  # outcomes of an attempt that got no answer
ANSWERING, FAILING, REFUSED = "AI answering", "AI failures other than 429", "Refused by the limit (429)"
IDLE = "No request in flight"  # the rest: waiting to be sent (pacing, a call slot) or the app's own work
BUCKETS = (ANSWERING, FAILING, REFUSED)  # where calls overlap, the first wins; the rest is IDLE


@dataclass
class Attempt:
    """One AI attempt sent to a model, as its usage row tells it (a reused answer is none)."""

    module: str
    api: str
    request: str
    session: str
    ask: str
    stage: str  # the job stage that made it
    delivery: int  # the job's delivery attempt
    task: str
    chat: bool  # a chat request (a search call is none)
    outcome: str
    error: str  # a failed try's error type
    refused: bool  # the gateway's 429
    tokens: int  # prompt + answer: what the gateway keeps counted once the call ends
    held: int  # what it counts while the call runs: prompt + the whole answer cap
    start: float  # epoch seconds
    end: float

    @property
    def answered(self) -> bool:
        """The model answered (ok, unreadable or cut off)."""
        return self.outcome not in NOT_ANSWERED


def attempts_of(rows: list[dict], caps: Mapping[str, int]) -> list[Attempt]:
    """The rows' attempts, oldest first. A chat call holds its prompt and whole answer cap while it runs, as
    scripts/ai_capacity_report.py counts it; a search call what it used."""
    found = []
    for row in rows:
        if row.get("outcome") == "reused":
            continue
        created = row["created_at"]  # a row is noted as its attempt ends
        end = (created if created.tzinfo else created.replace(tzinfo=UTC)).timestamp()
        tokens_in, tokens_out = row.get("tokens_in") or 0, row.get("tokens_out") or 0
        held = tokens_in + max(caps.get(row["task"], 0), tokens_out) if tokens_in else tokens_out
        module, api, request, session = (
            row.get(name) or "" for name in ("module", "api", "request_id", "session_id")
        )
        ask, stage = str(row.get("ask_id") or row.get("_id")), row.get("job_task") or ""
        refused, start = row.get("error_type") == REFUSED_ERROR, end - (row.get("seconds") or 0.0)
        found.append(
            Attempt(module, api, request, session, ask, stage, row.get("attempt") or 0, row["task"],
                    row["task"] in caps, row["outcome"], row.get("error_type") or "", refused,
                    tokens_in + tokens_out, held, start, end)
        )  # fmt: skip
    return sorted(found, key=lambda attempt: attempt.start)


def gateway_counter(attempts: list[Attempt]) -> Callable[[float], tuple[int, int]]:
    """(tokens, requests) the gateway counts at a moment for the attempts started in the WINDOW_SECONDS up to
    it: a running call at its hold, a finished one at what it used; a refused one as a request only."""
    sent = [attempt for attempt in attempts if not attempt.refused]
    sent_starts, all_starts = [a.start for a in sent], [a.start for a in attempts]

    def counted(moment: float) -> tuple[int, int]:
        window = sent[bisect_right(sent_starts, moment - WINDOW_SECONDS) : bisect_right(sent_starts, moment)]
        tokens = sum(a.held if a.end > moment or a.start == moment else a.tokens for a in window)
        return tokens, bisect_right(all_starts, moment) - bisect_right(all_starts, moment - WINDOW_SECONDS)

    return counted


@dataclass
class Minute:
    """One UTC minute of TSG's AI calls, by the minute each started in."""

    refused: int = 0
    tokens: int = 0  # prompt + answer of the calls sent
    peak_tokens: int = 0  # estimated: the most the gateway counted at any call's start in this minute
    peak_requests: int = 0


def minutes_of(attempts: list[Attempt]) -> dict[int, Minute]:
    """Each minute with AI calls: 429s, tokens used and the peaks the gateway counted."""
    counted, minutes = gateway_counter(attempts), defaultdict[int, Minute](Minute)
    for attempt in attempts:
        minute = minutes[int(attempt.start // 60)]
        if attempt.refused:
            minute.refused += 1
        else:
            minute.tokens += attempt.tokens
        tokens, requests = counted(attempt.start)
        minute.peak_tokens = max(minute.peak_tokens, tokens)
        minute.peak_requests = max(minute.peak_requests, requests)
    return dict(minutes)


def failure_bucket(attempt: Attempt) -> str:
    """The bucket of a failed attempt and of the wait after it."""
    return REFUSED if attempt.refused else FAILING


def retry_pairs(attempts: list[Attempt]) -> list[tuple[Attempt, Attempt]]:
    """(the failed try, the next try) of each retry: an ask's next try after one with no usable answer, and a
    job's next delivery after one that ended on a failed try."""
    asks, deliveries = defaultdict(list), defaultdict(list)
    for attempt in attempts:
        asks[attempt.ask].append(attempt)
        deliveries[(attempt.stage, attempt.delivery)].append(attempt)
    pairs = [pair for tries in asks.values() for pair in pairwise(tries) if pair[0].outcome != "ok"]
    for stage in {attempt.stage for attempt in attempts}:
        numbers = sorted(number for (key, number) in deliveries if key == stage)
        for one, other in pairwise(numbers):
            # ponytail: a delivery's last try to end stands for why it stopped; a parallel ask may end later
            last = max(deliveries[(stage, one)], key=lambda a: a.end)
            if not last.answered:
                pairs.append((last, deliveries[(stage, other)][0]))
    return pairs


def split(attempts: list[Attempt]) -> dict[str, float]:
    """Seconds of the attempts' span in each bucket (a retry's wait goes with its failed try); they add up."""
    intervals = [(a.start, a.end, ANSWERING if a.answered else failure_bucket(a)) for a in attempts]
    intervals += [(b.end, a.start, failure_bucket(b)) for b, a in retry_pairs(attempts) if a.start > b.end]
    edges = sorted({edge for start, end, _ in intervals for edge in (start, end)})
    seconds = dict.fromkeys((*BUCKETS, IDLE), 0.0)
    for left, right in pairwise(edges):  # ponytail: O(n^2) per run; a run has a few hundred rows at most
        middle = (left + right) / 2
        covering = {bucket for start, end, bucket in intervals if start <= middle < end}
        seconds[next((bucket for bucket in BUCKETS if bucket in covering), IDLE)] += right - left
    return seconds


@dataclass
class Work:
    """One stage's (or one action's) AI work."""

    seconds: float  # from its first request to its last answer
    requests: int  # asks: a retry is the same request again
    tokens: int
    responses: list[float]  # each answer's own seconds: how long the model took
    chat_responses: list[float]  # the chat requests' alone
    idle: float  # estimated: no request of it in flight
    refused: int  # no response: refused by the limit (429)
    unanswered: int  # no response for another reason: a timeout, an unreachable or failing model
    unusable: int  # answers that could not be used: unreadable or cut off
    retries: int
    retry_wait: float  # from each failed try to its retry


def work_of(attempts: list[Attempt]) -> Work:
    """The attempts' work."""
    pairs = retry_pairs(attempts)
    return Work(
        max(a.end for a in attempts) - attempts[0].start,
        len({a.ask for a in attempts}),
        sum(a.tokens for a in attempts if not a.refused),
        [a.end - a.start for a in attempts if a.answered],
        [a.end - a.start for a in attempts if a.answered and a.chat],
        split(attempts)[IDLE],
        sum(a.refused for a in attempts),
        sum(not a.answered and not a.refused for a in attempts),
        sum(a.answered and a.outcome != "ok" for a in attempts),
        len(pairs),
        sum(max(0.0, after.start - before.end) for before, after in pairs),
    )


@dataclass
class Run:
    """One action (an API request) of a session, and its stages."""

    request: str
    attempts: list[Attempt]
    work: Work
    stages: dict[str, Work]  # by job stage, in the order each began
    demand: float  # estimated: median over its minutes of TSG's peak count as a share of the limit
    app_times: dict[str, float] | None  # the app's own stage seconds, for a session's latest action

    @property
    def first(self) -> Attempt:
        return self.attempts[0]

    @property
    def end(self) -> float:
        return max(a.end for a in self.attempts)


@dataclass
class Session:
    """One threat scenario session's actions in the range."""

    id: str
    runs: list[Run]

    @property
    def seconds(self) -> float:
        """Its actions' times added up."""
        return sum(run.work.seconds for run in self.runs)

    @property
    def refused(self) -> int:
        return sum(run.work.refused for run in self.runs)


def run_of(request: str, own: list[Attempt], minutes: dict[int, Minute], budget: int, app_times) -> Run:
    """One action's run."""
    first, last = int(own[0].start // 60), int(max(a.end for a in own) // 60)
    shares = [minutes[m].peak_tokens / budget if m in minutes else 0.0 for m in range(first, last + 1)]
    stages = defaultdict(list)
    for attempt in own:
        stages[attempt.stage].append(attempt)
    by_stage = {stage: work_of(tries) for stage, tries in stages.items()}
    return Run(request, own, work_of(own), by_stage, statistics.median(shares), app_times)


def sessions_of(
    attempts: list[Attempt], minutes: dict[int, Minute], budget: int, app_times: dict[str, dict[str, float]]
) -> list[Session]:
    """The sessions with a threat scenario action, oldest first, each with all its actions (any module)."""
    ids = {a.session for a in attempts if a.module == SCENARIO_MODULE and a.api in SCENARIO_ACTIONS}
    grouped: defaultdict[str, defaultdict[str, list[Attempt]]] = defaultdict(lambda: defaultdict(list))
    for attempt in attempts:
        if attempt.session and attempt.session in ids and attempt.request:
            grouped[attempt.session][attempt.request].append(attempt)
    sessions = [
        Session(session, sorted((run_of(request, own, minutes, budget, app_times.get(request))
                                 for request, own in requests.items()), key=lambda run: run.first.start))
        for session, requests in grouped.items()
    ]  # fmt: skip
    return sorted(sessions, key=lambda session: session.runs[0].first.start)


@dataclass
class Need:
    """What one action (an API) needs from the gateway, from its measured requests."""

    module: str
    api: str
    actions: int  # measured
    tokens: int  # one action's busiest minute as the gateway counts it, the worst measured
    requests: int  # requests in that busiest minute, the worst measured
    median_tokens: float


def needs_of(attempts: list[Attempt]) -> list[Need]:
    """Each API's need, heaviest first, measured as scripts/ai_capacity_report.py does: a refused or
    unreachable try would not be sent once the limit fits the load."""
    grouped: defaultdict[tuple[str, str], defaultdict[str, list[Attempt]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for attempt in attempts:
        if attempt.request and attempt.api:
            grouped[(attempt.module, attempt.api)][attempt.request].append(attempt)
    needs = []
    for (module, api), requests in grouped.items():
        busiest = [
            busiest_minute([Call(a.task, "", a.outcome != "unavailable", a.tokens, 0, a.held, a.start, a.end)
                            for a in own])
            for own in requests.values()
        ]  # fmt: skip
        busiest = [minute for minute in busiest if minute[1]]
        if busiest:
            tokens = [minute[0] for minute in busiest]
            needs.append(Need(module, api, len(busiest), max(tokens), max(m[1] for m in busiest),
                              statistics.median(tokens)))  # fmt: skip
    return sorted(needs, key=lambda need: need.tokens, reverse=True)


def logged_429s(logs: list[dict]) -> list[dict]:
    """The logged 429s (an ask that gave up after its tries), oldest first."""
    refused = [
        entry for entry in logs if entry["event"] == "ai.call_unavailable" and entry.get("status") == 429
    ]
    return sorted(refused, key=lambda entry: str(entry.get("timestamp")))


@dataclass
class Evidence:
    """Everything the report says."""

    since: datetime
    until: datetime
    attempts: list[Attempt]
    minutes: dict[int, Minute]
    sessions: list[Session]
    budget: int  # the applicable tokens-a-minute limit
    budget_read: bool  # stated by the gateway, not given with --budget
    checked: datetime  # when the gateway was asked
    limits: dict[str, list]  # each model (its gateway, who uses it) -> the ai_limits_check.Limit it states
    gateway: list[str]  # the gateway's answers, word for word
    logs: list[dict] | None
    settings: list[str]
    users: int = USERS  # for the capacity they need at once
