"""Prometheus metrics (scraped from /metrics; viewed in Grafana)."""

from collections.abc import Iterable

from prometheus_client import Counter, Gauge, Histogram

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
AI_TOKENS = Counter("tsg_ai_tokens_total", "AI tokens", ["task", "model", "direction"])
AI_SECONDS = Histogram("tsg_ai_call_seconds", "AI call duration", ["task", "model"])
DEPENDENCY_UP = Gauge("tsg_dependency_up", "1 when the dependency answered the last check", ["name"])
JOBS_NOW = Gauge(
    "tsg_jobs_current",
    "Jobs now by kind and status (queued, retrying, running; failed: in the last 24 h), set by the reaper",
    ["kind", "status"],
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


def record_http_request(method: str, route: str, status: int, seconds: float) -> None:
    HTTP_REQUESTS.labels(method, route, str(status)).inc()
    HTTP_SECONDS.labels(route).observe(seconds)


def record_dependency_status(name: Dependency, up: bool) -> None:
    DEPENDENCY_UP.labels(name).set(1 if up else 0)


def record_workers_online(queue: str, count: int) -> None:
    WORKERS_ONLINE.labels(queue).set(count)
