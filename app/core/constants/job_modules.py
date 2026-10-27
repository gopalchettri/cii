"""Which product module each job works for (job.started/job.finished lines, GET /v1/admin/jobs), and what
the job monitor answers."""

from enum import StrEnum
from typing import Final

from app.core.constants.jobs import AdminJobKind, TaskName


class Module(StrEnum):
    """The product module a job works for: on every job.started/job.finished log line and every
    GET /v1/admin/jobs row, so a job is traced to its module without knowing task names."""

    THREAT_SCENARIOS = "threat_scenarios"
    REMEDIATION = "remediation"
    SERVICE_MAPPER = "service_mapper"
    EXTERNAL_INTELLIGENCE = "external_intelligence"
    LIBRARY_EMBEDDINGS = "library_embeddings"
    MAINTENANCE = "maintenance"


#: Each task's and each admin job kind's module.
JOB_MODULES: Final[dict[str, Module]] = {
    TaskName.FIND_THREATS: Module.THREAT_SCENARIOS,
    TaskName.WRITE_SCENARIOS: Module.THREAT_SCENARIOS,
    TaskName.MAP_CONTROLS: Module.THREAT_SCENARIOS,
    TaskName.RETRY_CONTROLS: Module.THREAT_SCENARIOS,
    TaskName.WRITE_PLAN: Module.REMEDIATION,
    TaskName.MAP_SERVICES: Module.SERVICE_MAPPER,
    TaskName.REFRESH_EXTERNAL_INTELLIGENCE: Module.EXTERNAL_INTELLIGENCE,
    AdminJobKind.INTEL_REFRESH: Module.EXTERNAL_INTELLIGENCE,
    TaskName.BUILD_LIBRARY_INDEXES: Module.LIBRARY_EMBEDDINGS,
    AdminJobKind.EMBEDDINGS_BUILD: Module.LIBRARY_EMBEDDINGS,
    TaskName.REAP: Module.MAINTENANCE,
}


#: The task that runs each admin job kind: the reaper's job.failed line for an abandoned one names it.
ADMIN_JOB_TASKS: Final[dict[str, str]] = {
    AdminJobKind.EMBEDDINGS_BUILD: TaskName.BUILD_LIBRARY_INDEXES,
    AdminJobKind.INTEL_REFRESH: TaskName.REFRESH_EXTERNAL_INTELLIGENCE,
}


class AbandonReason(StrEnum):
    """Why a job was given up (a job_abandoned error's reason); the job.failed lines carry the same words."""

    WORKER_STOPPED = "abandoned"  # its worker stopped renewing its lease on every attempt
    NEVER_STARTED = "never_started"  # sent again and again, or left queued, and no worker ever took it


def module_of(kind: str) -> str:
    """The module of a task or admin job kind; "other" for one not listed."""
    return JOB_MODULES.get(kind, "other")


class JobMonitorMessage(StrEnum):
    NOT_FOUND = "Job '{job_id}' does not exist (or ended more than its listing's retention ago)."
    NOT_ADMIN_JOB = (
        "Job '{job_id}' is a {module} job: cancel it with its own call (a run: POST "
        "/v1/sessions/{{id}}/cancel; a plan: its cancel call). Only intelligence imports and embeddings "
        "builds are cancelled here."
    )
    ALREADY_ENDED = "Job '{job_id}' is already {status}: there is nothing to cancel."
