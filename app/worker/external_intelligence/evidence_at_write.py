"""External evidence at write time: the distinct threats of the paths a batch is about to write are searched
together (one embedding call) on every delivery, and the result is kept in memory only."""

from collections.abc import Iterable, Iterator
from typing import Any

import structlog

from app.ai.common import outage_reason
from app.core.clock import utc_now
from app.core.constants import (
    AuditAction,
    AuditTarget,
    EvidenceLimits,
    IntelLimits,
    IntelSource,
    LogEvent,
    RecordedFields,
    TaskName,
)
from app.core.exceptions import TEMPORARY_ERRORS
from app.core.redaction import clipped_text, redact
from app.data_access.admin.audit_repository import AuditRepository
from app.data_access.external_intelligence.intel_feed_repository import IntelFeedRepository
from app.domain.external_intelligence.evidence_finder import EvidenceFinder
from app.domain.scenario.library_rules import compatible_asset_types
from app.domain.shared.audit import audit_target
from app.domain.shared.names import shorten_text
from app.models.external_intelligence.evidence import EvidenceBatchSummary
from app.models.external_intelligence.evidence_request import (
    EvidenceRequest,
    EvidenceResult,
    RecordedProduct,
    RecordedProducts,
)
from app.models.external_intelligence.source_health import FeedFreshness
from app.models.scenario.asset_context import FrozenContext
from app.worker.scenario.plan_progress import PlanProgress

log = structlog.get_logger(__name__)

#: Each threat's evidence and the audit of its search, by threat key, as the threats and the brief hold them.
EvidenceByThreat = dict[str, dict[str, Any]]


class EvidenceAtWrite:
    """The evidence search of one batch; the caller already read the switch, so this never reads it again."""

    def __init__(
        self,
        run: dict[str, Any],
        threats: dict[str, dict[str, Any]],
        progress: PlanProgress,
        finder: EvidenceFinder,
        feeds: IntelFeedRepository,
        audit: AuditRepository,
    ) -> None:
        self._run, self._threats, self._progress = run, threats, progress
        self._finder, self._feeds, self._audit = finder, feeds, audit

    def attach(self, path_ids: Iterable[str]) -> None:
        """Search every distinct threat of these paths and set its evidence and search on it, in memory only
        (the brief reads it there). A search an outage stopped is held on each threat as its failure: its
        paths wait and a later delivery searches again. Any other error is raised."""
        steps = {step for path_id in path_ids for step in self._progress.paths[path_id].get("steps") or ()}
        keys = [key for key in sorted(steps) if key in self._threats]
        if not keys:
            return
        approved = set(self._feeds.list_approved_sources())  # the sources Legal allows, read once per batch
        context = FrozenContext.from_record(self._run["context"])
        try:
            requests = {key: evidence_request(context, self._threats[key]) for key in keys}
            found = self._search_batch(requests, approved, self._is_stale(approved))
        except TEMPORARY_ERRORS as exc:  # an outage never costs the batch: its paths wait
            log.warning(
                LogEvent.EXTERNAL_INTELLIGENCE_EVIDENCE_SEARCH_FAILED, threats=len(keys), exc_info=True
            )
            fault = clipped_text(redact(f"{type(exc).__name__}: {exc}"), IntelLimits.FAILURE_REASON_CHARS)
            for key in keys:
                self._threats[key]["intel_search"] = {"failure": fault, "outage": outage_reason(exc)}
            return
        for key, fields in found.items():
            self._threats[key].update(fields)

    def _search_batch(
        self, requests: dict[str, EvidenceRequest], approved: set[IntelSource], stale: bool
    ) -> EvidenceByThreat:
        """One audited search batch (one embedding call): each threat's fields with when it was searched,
        from approved sources only."""
        results, summary = self._finder.find_evidence(list(requests.values()), stale=stale, approved=approved)
        self._audit_batch(summary)
        searched_at = utc_now().isoformat()
        pairs = zip(requests, results, strict=True)
        return {key: _threat_fields(result, searched_at) for key, result in pairs}

    def _is_stale(self, approved: set[IntelSource]) -> bool:
        """True when an approved source that has data is older than IntelLimits.STALE_AFTER_HOURS, from one
        read of the source health."""
        return FeedFreshness.of(self._feeds.list_source_health(), approved, utc_now()).stale

    def _audit_batch(self, summary: EvidenceBatchSummary) -> None:
        """Write one audit row per search batch (its snapshot, threats and evidence counts); each threat's
        own search is audited on its scenario (content.intel_search)."""
        if summary.snapshot_id is None:
            return
        target = audit_target(AuditTarget.SESSION, self._run["_id"])
        actor = {"system": TaskName.WRITE_SCENARIOS}
        self._audit.create_audit_record(
            AuditAction.EXTERNAL_INTELLIGENCE_EVIDENCE_USED, actor, target, after=summary.as_doc()
        )


def evidence_request(context: FrozenContext, threat: dict[str, Any]) -> EvidenceRequest:
    """The search for one plan threat: its type and name only (redacted and cut); the asset enters through
    the IT / OT filter and the products it records."""
    systems = _systems_of(context, threat)
    types = compatible_asset_types(
        context.asset.get("category_code"), (system.get("category_code") for system in systems)
    )
    products = RecordedProducts(tuple(_recorded(row) for row in (context.asset_context, *systems)))
    text = shorten_text(
        redact(f"Threat: {threat['type']['name']}: {threat['name']}"), EvidenceLimits.QUERY_MAX_CHARS
    )
    return EvidenceRequest(text, types, products)


def _systems_of(context: FrozenContext, threat: dict[str, Any]) -> list[dict[str, Any]]:
    """The systems the threat concerns; every system of the run when none of them is known."""
    wanted = set(threat.get("systems") or ())
    return [system for system in context.systems if system.get("id") in wanted] or list(context.systems)


def _recorded(row: dict[str, Any]) -> RecordedProduct:
    """The vendors, products and versions one record of the asset (itself or a system) states, as written."""

    def values(keys: Iterable[str]) -> tuple[str, ...]:
        """Every text the row states under these field names."""
        return tuple(text for key in keys for text in _stated_texts(row.get(key)))

    return RecordedProduct(
        values(RecordedFields.VENDOR_KEYS),
        values(RecordedFields.PRODUCT_KEYS),
        values(RecordedFields.VERSION_KEYS),
    )


def _stated_texts(value: Any) -> Iterator[str]:
    """The non-blank texts of a field holding one value or a list of them."""
    for item in value if isinstance(value, list | tuple) else [value]:
        if item is not None and str(item).strip():
            yield str(item).strip()


def _threat_fields(result: EvidenceResult, searched_at: str) -> dict[str, Any]:
    """One search result as the threat carries it: its evidence and its search audit, dated."""
    return {
        "evidence": [item.as_doc() | {"searched_at": searched_at} for item in result.evidence],
        "intel_search": result.search.as_doc() | {"searched_at": searched_at},
    }
