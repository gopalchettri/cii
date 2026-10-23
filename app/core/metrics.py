"""Prometheus metrics (scraped from /metrics; viewed in Grafana)."""

from collections.abc import Iterable
from contextlib import suppress

from prometheus_client import REGISTRY, Counter, Gauge, Histogram

from app.core.constants import Dependency

HTTP_REQUESTS = Counter("tsg_http_requests_total", "HTTP requests", ["method", "route", "status"])
HTTP_SECONDS = Histogram("tsg_http_request_seconds", "HTTP request duration", ["route"])
JOBS = Counter("tsg_jobs_total", "Background jobs by outcome", ["task", "outcome"])
RUNS = Counter("tsg_runs_total", "Runs started", ["kind"])
SCENARIOS = Counter("tsg_scenarios_total", "Scenario paths settled, by outcome", ["outcome"])
DECISIONS = Counter("tsg_decisions_total", "Scenarios newly accepted or rejected by reviewers", ["decision"])
PLANS = Counter("tsg_plans_total", "Remediation plan versions settled, by outcome", ["outcome"])
JOB_SECONDS = Histogram(
    "tsg_job_seconds", "Background job duration", ["task"], buckets=(1, 5, 15, 30, 60, 120, 300, 600, 1800)
)
AI_CALLS = Counter("tsg_ai_calls_total", "AI calls by outcome", ["task", "model", "outcome"])
AI_OUTAGES = Counter("tsg_ai_outages_total", "AI calls with no answer, by reason", ["task", "reason"])
AI_TOKENS = Counter("tsg_ai_tokens_total", "AI tokens", ["task", "model", "direction"])
#: Up to the longest AI timeout (90-120 s, app/ai/profiles.py): the default buckets stop at 10 s.
AI_SECONDS = Histogram(
    "tsg_ai_call_seconds",
    "AI call duration",
    ["task", "model"],
    buckets=(1, 2, 5, 10, 20, 30, 60, 90, 120, 180),
)
DEPENDENCY_UP = Gauge("tsg_dependency_up", "1 when the dependency answered the last check", ["name"])
JOBS_NOW = Gauge(
    "tsg_jobs_current",
    "Jobs now by kind and status (queued, retrying, running; failed: in the last 24 h), set by the reaper",
    ["kind", "status"],
)
#: When the reaper last finished a pass. ReaperNotRunning and the dashboard's beat tile read its age: a
#: pass made before Prometheus' first scrape still counts, which a rise in tsg_jobs_total cannot show.
#: Exported only by the worker that runs the reaper (start_reaper_clock): a 0 from every other process made
#: the newest pass depend on which one Prometheus scraped first after a start.
REAPER_LAST_PASS = Gauge(
    "tsg_reaper_last_pass_timestamp_seconds",
    "When the reaper last finished a pass (Unix time)",
    registry=None,
)
WORKERS_ONLINE = Gauge("tsg_workers_online", "Worker pods with a recent heartbeat", ["queue"])
#: Read from Redis at each scrape of a worker (AiSlots.count_calls_in_progress): every pod reports the same
#: total.
AI_SLOTS_IN_USE = Gauge("tsg_ai_slots_in_use", "AI calls in progress across all pods")
AI_SLOTS_CAP = Gauge("tsg_ai_slots_cap", "CII_MAX_CONCURRENT_AI_CALLS (0 = no limit)")
AUDIT_FAILURES = Counter("tsg_audit_failures_total", "Audit records that could not be written")
LIBRARY_CHECK_FAILURES = Counter(
    "tsg_library_check_failures_total", "Library checks that failed (the last loaded library is served)"
)


#: The job outcomes alerts read (Celery's state, lower case): see start_job_counters.
JOB_OUTCOMES = ("success", "retry", "failure")


def start_job_counters(tasks: Iterable[str]) -> None:
    """Every task's outcome series exists at 0 from start-up. A series that first appears already at 1 shows
    no increase to Prometheus, so the first failure after a restart would never fire JobsFailing."""
    for task in tasks:
        for outcome in JOB_OUTCOMES:
            JOBS.labels(task, outcome)


def start_reaper_clock() -> None:
    """This process runs the reaper: export its last pass, on time from now (a fresh start is on time)."""
    with suppress(ValueError):  # already exported: tests start several workers in one process
        REGISTRY.register(REAPER_LAST_PASS)
    REAPER_LAST_PASS.set_to_current_time()


def record_http_request(method: str, route: str, status: int, seconds: float) -> None:
    HTTP_REQUESTS.labels(method, route, str(status)).inc()
    HTTP_SECONDS.labels(route).observe(seconds)


def record_dependency_status(name: Dependency, up: bool) -> None:
    DEPENDENCY_UP.labels(name).set(1 if up else 0)


def record_workers_online(queue: str, count: int) -> None:
    WORKERS_ONLINE.labels(queue).set(count)
