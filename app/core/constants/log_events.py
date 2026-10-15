"""Every log event name."""

from enum import StrEnum


class LogEvent(StrEnum):
    """Every log event name (domain.action), searched in Grafana / Loki."""

    HTTP_REQUEST = "http.request"
    HTTP_APP_ERROR = "http.app_error"
    HTTP_UNHANDLED_ERROR = "http.unhandled_error"
    DEPENDENCY_UNAVAILABLE = "dependency.unavailable"
    AI_CALL = "ai.call"
    AI_CALL_RECORD_FAILED = "ai.call_record_failed"
    AI_CALL_REUSED = "ai.call_reused"  # G244: a retried job's earlier answer, no AI call made
    AI_CALL_REUSE_FAILED = "ai.call_reuse_failed"  # the record store could not be read: asked
    AI_CALL_REFUSED = "ai.call_refused"  # a key, permission or model name the gateway refused
    AI_CALL_UNAVAILABLE = "ai.call_unavailable"  # the provider error class and HTTP status of an outage
    AI_SLOTS_BUSY = "ai.slots_busy"
    AI_SLOT_FREE_FAILED = "ai.slot_free_failed"
    LIBRARY_RELOADED = "library.reloaded"
    # tsg_GetControlLibrary is the old one (no retired controls): install
    # scripts/sql/tsg_GetControlLibrary.sql.
    LIBRARY_RETIRED_CONTROLS_MISSING = "library.retired_controls_missing"
    # tsg_GetThreatLibrary from before 2026-10-12 (G211): no Threat_Catalogue.AssetType; threats untyped
    LIBRARY_THREAT_ASSET_TYPE_MISSING = "library.threat_asset_type_missing"
    LIBRARY_ASSET_TYPE_UNKNOWN = "library.asset_type_unknown"  # an AssetType not IT, OT or IT\OT (G211)
    CONTEXT_SERVICE_NOT_LINKED = "context.service_not_linked"  # the asked service is used anyway
    CONTEXT_OPTION_VALUE_NOT_FOUND = "context.option_value_not_found"  # a stored code with no name: seed data
    LIBRARY_CHECK_FAILED = "library.check_failed"
    LIBRARY_INDEXES_BUILT = "library.indexes_built"
    LIBRARY_INDEXES_BUILD_FAILED = "library.indexes_build_failed"
    PLANNER_BATCH_ASKED_AGAIN = "planner.relevance_batch_asked_again"  # an unusable batch, asked afresh once
    PLANNER_THREATS_NOT_JUDGED = "planner.threats_not_judged"  # a gate batch unusable after its retries
    PLANNER_BATCH_SPLIT = "planner.relevance_batch_split"  # a cut-off answer: each half asked alone
    PLANNER_CHECK_NOT_MADE = "planner.check_not_made"  # a quality check skipped: noted on the plan
    PLANNER_FACTS_SHORTENED = "planner.facts_shortened"
    PLANNER_ACTORS_NOT_RANKED = "planner.actors_not_ranked"  # embedding down: library order decides
    PLANNER_PLAN_MADE = "planner.plan_made"
    WRITER_PLAN_CHECK_NOT_MADE = "writer.plan_check_not_made"  # a note on the scenario, never a failure
    WRITER_REWRITE_UNUSABLE = "writer.rewrite_unusable"  # the first draft is kept
    WRITER_SCENARIO_SAVED = "writer.scenario_saved"
    WRITER_PATH_FAILED = "writer.path_failed"  # an unexpected error: a failure card, the stack logged
    CONTROLS_MAPPED = "controls.mapped"
    CONTROLS_NOT_MAPPED = "controls.not_mapped"  # no compatible control, an empty library or a setting to fix
    CONTROLS_MAP_FAILED = "controls.map_failed"  # an unexpected error: that scenario only, the stack logged
    WRITER_OUTAGE_SETTLED = "writer.outage_settled"  # an outage only some paths kept hitting: failure cards
    WRITER_PATH_ABANDONED = "writer.path_abandoned"  # failed or blocked Generation.MAX_PATH_ATTEMPTS times
    WRITER_REGENERATE_FAILED = (
        "writer.regenerate_failed"  # no new version: the old one stays current, with why
    )
    EMBEDDINGS_RETIRED = "embedding.retired"
    EMBEDDING_STORED_SIZE_WRONG = "embedding.stored_size_wrong"
    JOB_NOT_CLAIMED = "job.not_claimed"
    JOB_LEASE_LOST = "job.lease_lost"
    JOB_STOPPED_BY_OWNER = "job.stopped_by_owner"  # its run or plan was cancelled or deleted (G214)
    JOB_LEASE_RENEW_FAILED = "job.lease_renew_failed"
    JOB_RETRY_SCHEDULED = "job.retry_scheduled"
    JOB_FAILED = "job.failed"
    JOB_TOO_LONG = "job.too_long"
    JOB_REQUEUED = "job.requeued"
    JOB_SEND_FAILED = "job.send_failed"
    JOB_QUEUE_SIZE_UNKNOWN = "job.queue_size_unknown"
    JOB_REAP_FAILED = "job.reap_failed"
    WORKER_METRICS_SERVING = "worker.metrics_serving"
    WORKER_HEARTBEAT_FAILED = "worker.heartbeat_failed"
    WORKER_NONE_ONLINE = "worker.none_online"
    WORKERS_UNKNOWN = "worker.count_unknown"
    EVENT_PUBLISH_FAILED = "event.publish_failed"
    EVENT_HUB_RECONNECTING = "event.hub_reconnecting"
    EVENT_HUB_FAILED = "event.hub_failed"
    AUDIT_RECORDED = "audit.recorded"
    AUDIT_WRITE_FAILED = "audit.write_failed"
    EXTERNAL_INTELLIGENCE_REFRESHED = "external_intelligence.refreshed"
    EXTERNAL_INTELLIGENCE_SOURCE_FAILED = "external_intelligence.source_failed"
    EXTERNAL_INTELLIGENCE_CLAIM_LOST = "external_intelligence.claim_lost"
    EXTERNAL_INTELLIGENCE_SNAPSHOT_ACTIVATED = "external_intelligence.snapshot_activated"
    EXTERNAL_INTELLIGENCE_SNAPSHOT_SUPERSEDED = "external_intelligence.snapshot_superseded"
    EXTERNAL_INTELLIGENCE_SNAPSHOT_BUILD_FAILED = "external_intelligence.snapshot_build_failed"
    EXTERNAL_INTELLIGENCE_NO_DATA = "external_intelligence.no_data_yet"  # once per process: run the import
    EXTERNAL_INTELLIGENCE_EVIDENCE_SEARCH_FAILED = "external_intelligence.evidence_search_failed"
    EXTERNAL_INTELLIGENCE_SWITCH_CHANGED = "external_intelligence.switch_changed"
    EXTERNAL_INTELLIGENCE_TEXT_QUARANTINED = "external_intelligence.text_quarantined"
    EXTERNAL_INTELLIGENCE_SENTENCES_REMOVED = "external_intelligence.sentences_removed"  # G237: the rest kept
    # The step trace (DEBUG_STEP_OUTPUT=true only): every workflow step's inputs, results, output and time.
    STEP_STARTED = "step.started"
    STEP_RESULT = "step.result"
    STEP_FINISHED = "step.finished"
    STEP_FAILED = "step.failed"
