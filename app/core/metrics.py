"""Prometheus metrics (scraped from /metrics; viewed in Grafana)."""

from collections.abc import Iterable
from contextlib import suppress

from prometheus_client import REGISTRY, Counter, Gauge, Histogram

from app.core.constants import Dependency, module_of

HTTP_REQUESTS = Counter("tsg_http_requests_total", "HTTP requests", ["method", "route", "status"])
HTTP_SECONDS = Histogram("tsg_http_request_seconds", "HTTP request duration", ["route"])
JOBS = Counter("tsg_jobs_total", "Background jobs by outcome", ["task", "module", "outcome"])
RUNS = Counter("tsg_runs_total", "Runs started", ["kind"])
SCENARIOS = Counter("tsg_scenarios_total", "Scenario paths settled, by outcome", ["outcome"])
DECISIONS = Counter("tsg_decisions_total", "Scenarios newly accepted or rejected by reviewers", ["decision"])
PLANS = Counter("tsg_plans_total", "Remediation plan versions settled, by outcome", ["outcome"])
#: Up to Lease.MAX_JOB_SECONDS (3600 s); a job still working after that lands in +Inf.
JOB_SECONDS = Histogram(
    "tsg_job_seconds",
    "Background job duration",
    ["task", "module"],
    buckets=(1, 5, 15, 30, 60, 120, 300, 600, 1800, 3600),
)
JOB_QUEUE_WAIT = Histogram(
    "tsg_job_queue_wait_seconds",
    "Time a job waited for a worker after it was due",
    ["task", "module"],
    buckets=(0.5, 1, 2, 5, 10, 30, 60, 120, 300, 600, 1800, 3600),
)
AI_CALLS = Counter("tsg_ai_calls_total", "AI calls by outcome", ["task", "model", "outcome"])
#: source: the gateway refused, or TSG's own limiter did (app/core/constants AiOutageSource).
AI_OUTAGES = Counter(
    "tsg_ai_outages_total", "AI calls with no answer, by reason and source", ["task", "reason", "source"]
)
AI_TOKENS = Counter("tsg_ai_tokens_total", "AI tokens", ["task", "model", "direction"])
#: Up to the longest AI timeout (90-120 s, app/ai/profiles.py): the default buckets stop at 10 s.
AI_SECONDS = Histogram(
    "tsg_ai_call_seconds",
    "AI call duration",
    ["task", "model"],
    buckets=(1, 2, 5, 10, 20, 30, 60, 90, 120, 180),
)
#: Each turn of a model's request-rate limiter (AiRequestRate), 0 included; none while its limit is 0.
AI_REQUEST_RATE_WAIT = Histogram(
    "tsg_ai_request_rate_wait_seconds",
    "Seconds an AI request waited for its turn in its model's request-rate limiter",
    ["model"],
    buckets=(0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300),
)
AI_RATE_LIMITED = Counter("tsg_ai_rate_limited_total", "HTTP 429 answers from the AI gateway", ["model"])
DEPENDENCY_UP = Gauge("tsg_dependency_up", "1 when the dependency answered the last check", ["name"])
JOBS_NOW = Gauge(
    "tsg_jobs_current",
    "Jobs now by kind and status (queued, retrying, running; failed: in the last 24 h), set by the reaper",
    ["kind", "status"],
)
#: Jobs whose lease renewer stopped them as hung (app/worker/lease_renewal.py): JobHung reads it.
JOBS_HUNG = Counter("tsg_jobs_hung_total", "Jobs stopped as hung: no lease check for Lease.STALL_SECONDS")
#: When the reaper last started a pass (ReaperNotRunning, the beat tile: beat sends it) and last finished
#: one (ReaperFailing). Their ages, not a rise in tsg_jobs_total: a pass made before Prometheus' first scrape
#: still counts. Exported by the one process that runs the reaper, from its first pass (record_reaper_time):
#: never a 0 or a made-up time that would hide a dead beat or failing passes.
REAPER_LAST_START = Gauge(
    "tsg_reaper_last_start_timestamp_seconds",
    "When the reaper last started a pass (Unix time)",
    registry=None,
)
REAPER_LAST_PASS = Gauge(
    "tsg_reaper_last_pass_timestamp_seconds",
    "When the reaper last finished a pass (Unix time)",
    registry=None,
)
WORKERS_ONLINE = Gauge("tsg_workers_online", "Worker pods with a recent heartbeat", ["queue"])
#: MongoDB's clock minus this process's clock (app/core/clock.py): ClockSkew fires when a pod is far off.
CLOCK_OFFSET = Gauge("tsg_clock_offset_seconds", "MongoDB's clock minus this process's clock")
#: Read from Redis at each scrape of a worker (AiSlots.count_calls_in_progress, current_limit): every pod
#: reports the same numbers. One pool each: the search calls', and each module's chat calls (ChatModule).
AI_SLOTS_IN_USE = Gauge("tsg_ai_slots_in_use", "AI calls in progress across all pods", ["pool"])
AI_SLOTS_CAP = Gauge(
    "tsg_ai_slots_cap",
    "A pool's limit on AI calls at once: its MAX_CONCURRENT_AI_CALLS or a 429's, the lower (0 = none)",
    ["pool"],
)
AUDIT_FAILURES = Counter("tsg_audit_failures_total", "Audit records that could not be written")
LIBRARY_CHECK_FAILURES = Counter(
    "tsg_library_check_failures_total", "Library checks that failed (the last loaded library is served)"
)


#: The job outcomes alerts read (Celery's state, lower case; expired: a timer message dropped unrun).
JOB_OUTCOMES = ("success", "retry", "failure", "expired")


def start_job_counters(tasks: Iterable[str]) -> None:
    """Every task's outcome series exists at 0 from start-up. A series that first appears already at 1 shows
    no increase to Prometheus, so the first failure after a restart would never fire JobsFailing."""
    for task in tasks:
        for outcome in JOB_OUTCOMES:
            JOBS.labels(task, module_of(task), outcome)


def count_job(task: str, outcome: str) -> None:
    """Count one job outcome under its task and the task's module."""
    JOBS.labels(task, module_of(task), outcome).inc()


def record_job_seconds(task: str, seconds: float) -> None:
    """Record how long one job ran, under its task and the task's module."""
    JOB_SECONDS.labels(task, module_of(task)).observe(seconds)


def record_queue_wait(task: str, seconds: float) -> None:
    """Record how long a claimed job waited after it was due (never below 0: the clocks may differ)."""
    JOB_QUEUE_WAIT.labels(task, module_of(task)).observe(max(seconds, 0.0))


def record_reaper_time(gauge: Gauge) -> None:
    """Set one of the reaper's gauges to now, exporting it from then on (only the process that reaps)."""
    gauge.set_to_current_time()  # before it is exported: a scrape never reads its initial 0
    with suppress(ValueError):  # already exported
        REGISTRY.register(gauge)


def record_http_request(method: str, route: str, status: int, seconds: float) -> None:
    HTTP_REQUESTS.labels(method, route, str(status)).inc()
    HTTP_SECONDS.labels(route).observe(seconds)


def record_dependency_status(name: Dependency, up: bool) -> None:
    DEPENDENCY_UP.labels(name).set(1 if up else 0)


def record_workers_online(queue: str, count: int) -> None:
    WORKERS_ONLINE.labels(queue).set(count)
