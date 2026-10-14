"""Prometheus metrics of external intelligence. They live here, not in app/core/metrics.py (not edited by this
feature), where both the engine and the services can reach them: same naming and label conventions."""

from enum import StrEnum

from prometheus_client import Counter, Gauge, Histogram


class MetricOutcome(StrEnum):
    OK = "ok"
    FAILED = "failed"


REFRESHES = Counter(
    "tsg_external_intelligence_refreshes_total", "Source refreshes by outcome", ["source", "outcome"]
)
SNAPSHOT_AGE_SECONDS = Gauge(
    "tsg_external_intelligence_snapshot_age_seconds", "Seconds since the evidence index in use was built"
)
EVIDENCE_SEARCHES = Counter(
    "tsg_external_intelligence_searches_total", "Threat evidence searches by outcome", ["outcome"]
)
EVIDENCE_USED = Counter("tsg_external_intelligence_evidence_used_total", "Evidence records used")
QUARANTINED = Counter("tsg_external_intelligence_quarantined_total", "Source records quarantined", ["source"])
RERANK_SECONDS = Histogram(
    "tsg_external_intelligence_rerank_seconds",
    "Seconds of one evidence rerank call (not counting the wait for the gate)",
)
