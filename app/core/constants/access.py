"""API keys and audit."""

from enum import StrEnum
from typing import Final


class AuditAction(StrEnum):
    """Every audited action (tsg_audit.action). The other blueprint actions arrive with their features."""

    KEY_MINTED = "key.minted"
    KEY_REVOKED = "key.revoked"
    RUN_STARTED = "run.started"
    RUN_NEXT_SET = "run.next_set"
    RUN_REGENERATED = "run.regenerated"
    SCENARIOS_ACCEPTED = "scenario.accepted"
    SCENARIOS_REJECTED = "scenario.rejected"
    LIBRARY_PROMOTED = "library.promoted"
    PLAN_REQUESTED = "plan.requested"
    PLAN_COMPLETED = "plan.completed"  # a plan version written by its job (the actor is the job)
    LIBRARY_PROPOSED = "library.proposed"  # a hand-written scenario's new threat, pending a curator
    PLAN_REGENERATED = "plan.regenerated"
    PLAN_ACCEPTED = "plan.accepted"
    PLAN_REJECTED = "plan.rejected"
    LIBRARY_DECIDED = "library.decided"  # a curator approved or rejected pending threats (#24)
    ADMIN_JOB_STARTED = "admin.job_started"  # an admin job queued (#18)
    ADMIN_JOB_FINISHED = "admin.job_finished"  # an admin job done or failed (the actor is the job)
    RUN_CANCELLED = "run.cancelled"  # its owner stopped a run (G214)
    SESSION_DELETED = "session.deleted"  # a run removed for good, with its scenarios and plans (G214)
    PLAN_CANCELLED = "plan.cancelled"  # its owner stopped a remediation plan being written (G214)
    EXTERNAL_INTELLIGENCE_REFRESHED = "external_intelligence.refreshed"  # a source read (actor: the job)
    EXTERNAL_INTELLIGENCE_REFRESH_FAILED = "external_intelligence.refresh_failed"
    EXTERNAL_INTELLIGENCE_EVIDENCE_USED = "external_intelligence.evidence_used"  # one batch's search
    EXTERNAL_INTELLIGENCE_SWITCHED = "external_intelligence.switched"  # an admin turned it on or off
    EXTERNAL_INTELLIGENCE_SOURCE_REVOKED = "external_intelligence.source_revoked"  # records, vectors purged
    EXTERNAL_INTELLIGENCE_SOURCE_APPROVED = "external_intelligence.source_approved"  # approved again


class AuditTarget(StrEnum):
    """What kind of record an audited action changed (tsg_audit.target.type)."""

    API_CLIENT = "api_client"
    SESSION = "session"
    SCENARIO = "scenario"
    REMEDIATION = "remediation"
    LIBRARY_THREAT = "library_threat"
    ADMIN_JOB = "admin_job"
    EXTERNAL_INTELLIGENCE_SOURCE = "external_intelligence_source"


class Audit:
    KEEP_DAYS: Final = 365  # tsg_audit retention (TTL on `at`)
    ADMIN_USER: Final = "admin"  # who an admin call is recorded as when it sends no X-User-Id


class ApiKey:
    PREFIX: Final = "tsg_"
    RANDOM_BYTES: Final = 32
    SHOWN_PREFIX_LENGTH: Final = 8


class ApiClientMessage(StrEnum):
    NAME_TAKEN = "An active API client named '{name}' already exists."
    NOT_FOUND = "API client '{client_id}' does not exist."
