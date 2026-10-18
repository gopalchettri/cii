"""External evidence at write time: the threats of the paths a batch is about to write are searched together
(one embedding call), once each, and what settled is saved on the plan so every version cites the same."""

import dataclasses
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from typing import Any

import structlog

from app.core.config import get_settings
from app.core.constants import (
    AuditAction,
    AuditTarget,
    EvidenceLimits,
    EvidenceSearchFailure,
    IntelKind,
    IntelLimits,
    IntelSource,
    LogEvent,
    RecordedFields,
    TaskName,
)
from app.core.redaction import clipped_text, redact
from app.data_access.audit import record_audit
from app.domain.shared.names import shorten_text
from app.models.asset_context import FrozenContext
from app.models.external_intelligence.evidence import EvidenceBatchSummary
from app.models.external_intelligence.evidence_request import (
    EvidenceRequest,
    EvidenceResult,
    RecordedProduct,
    RecordedProducts,
)
from app.models.library import compatible_asset_types
from app.worker.external_intelligence.intel_access import IntelAccess
from app.worker.plan_progress import PlanProgress

log = structlog.get_logger(__name__)

#: Each threat's evidence and the audit of its search, by threat key, as the plan and the brief hold them.
EvidenceByThreat = dict[str, dict[str, Any]]
#: The joined sources an old vulnerability entry, kept before `joined` was recorded, may rest on.
_LEGACY_JOINED = (IntelSource.FIRST_EPSS, IntelSource.NIST_NVD)


class EvidenceAtWrite:
    """The evidence search of one batch; the caller already read the switch, so this never reads it again."""

    def __init__(
        self,
        run: dict[str, Any],
        threats: dict[str, dict[str, Any]],
        progress: PlanProgress,
        access: IntelAccess,
    ) -> None:
        self._run, self._threats, self._progress, self._access = run, threats, progress, access

    def attach(self, path_ids: Iterable[str]) -> None:
        """Search the distinct threats of these paths that carry no search yet, set the evidence on them (the
        brief reads it there) and save what settled on the plan. A search that could not be made is not
        saved: its paths wait and a later delivery searches again."""
        approved = set(self._access.approved_sources())  # the sources Legal allows, read once per batch
        keys = self._unsearched(path_ids, approved)
        if not keys:
            return
        context = FrozenContext.from_record(self._run["context"])
        try:
            found = self._search_with_retries(context, keys, approved)
        except Exception as exc:  # a search fault never costs the batch: its paths wait as outages
            log.warning(
                LogEvent.EXTERNAL_INTELLIGENCE_EVIDENCE_SEARCH_FAILED, threats=len(keys), exc_info=True
            )
            # Held here only, never on the plan, so the next try searches again.
            fault = clipped_text(redact(f"{type(exc).__name__}: {exc}"), IntelLimits.FAILURE_REASON_CHARS)
            for key in keys:
                self._threats[key]["intel_search"] = {"failure": fault}
            return
        for key, fields in found.items():
            self._threats[key].update(fields)
        settled = {key: fields for key, fields in found.items() if _is_settled(fields)}
        if settled:
            self._progress.keep_evidence(settled)

    def _search_with_retries(
        self, context: FrozenContext, keys: list[str], approved: set[IntelSource]
    ) -> EvidenceByThreat:
        """Search each threat; one that settled with nothing usable is searched again in other words, up to
        EVIDENCE_SEARCH_RETRIES times, its earlier searches kept as `attempts`. The feeds' health is read
        once for all of these searches."""
        stale = self._access.is_stale(approved)
        requests = {key: evidence_request(context, self._threats[key]) for key in keys}
        found = self._search_batch(requests, approved, stale)
        for attempt in range(get_settings().evidence_search_retries):
            found_nothing = [
                key for key, fields in found.items() if _is_settled(fields) and not fields["evidence"]
            ]
            if not found_nothing:
                break
            again = {key: alternative_request(context, self._threats[key], attempt) for key in found_nothing}
            retried = self._search_batch(again, approved, stale)
            for key, fields in retried.items():
                earlier = found[key]["intel_search"]
                attempts = [*earlier.pop("attempts", []), earlier]
                found[key] = fields | {"intel_search": fields["intel_search"] | {"attempts": attempts}}
        return found

    def _search_batch(
        self, requests: dict[str, EvidenceRequest], approved: set[IntelSource], stale: bool
    ) -> EvidenceByThreat:
        """One audited search batch (one embedding call): each threat's fields with when it was searched,
        from approved sources only."""
        results, summary = self._access.find_evidence(list(requests.values()), stale)
        self._audit(summary)
        searched_at = datetime.now(UTC).isoformat()
        return {
            key: _approved_only(_plan_fields(result, searched_at), approved)
            for key, result in zip(requests, results, strict=True)
        }

    def _unsearched(self, path_ids: Iterable[str], approved: set[IntelSource]) -> list[str]:
        """The distinct threats of these paths with no search yet. A kept search whose evidence rests on a
        source revoked since (its own or one joined into it) is dropped here, so the threat is searched
        again and no new write cites that source."""
        steps = {step for path_id in path_ids for step in self._progress.paths[path_id].get("steps") or ()}
        keys = [key for key in sorted(steps) if key in self._threats]
        for key in keys:
            threat = self._threats[key]
            if not all(_from_approved(item, approved) for item in threat.get("evidence") or ()):
                threat.update(evidence=[], intel_search=None)
        return [key for key in keys if self._threats[key].get("intel_search") is None]

    def _audit(self, summary: EvidenceBatchSummary) -> None:
        """Write one audit row per search batch (its snapshot, threats and evidence counts); each threat's
        own search is audited on its scenario (content.intel_search)."""
        if summary.snapshot_id is None:
            return
        target = {"type": AuditTarget.SESSION, "id": self._run["_id"]}
        actor = {"system": TaskName.WRITE_SCENARIOS}
        record_audit(AuditAction.EXTERNAL_INTELLIGENCE_EVIDENCE_USED, actor, target, after=summary.as_doc())


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


def alternative_request(context: FrozenContext, threat: dict[str, Any], attempt: int) -> EvidenceRequest:
    """The same search in other words, for a threat whose search found nothing usable: first the kind of
    attack, the threat and its systems' technology, then a short keyword form (same filter, no AI call)."""
    request = evidence_request(context, threat)
    rows = (context.asset_context, *_systems_of(context, threat))
    technology = ", ".join(dict.fromkeys(text for row in rows for text in _recorded(row).products))
    technology = technology or "not recorded"
    asset_type = str(context.asset_context.get("asset_type") or "")
    kind, threat_type = threat.get("category") or "", threat["type"]["name"]
    wordings = (
        f"Attack: {threat_type}: {threat['name']}\nKind of attack: {kind}\nTechnology: {technology}\n"
        f"Asset type: {asset_type}",
        f"{kind} {threat_type} {asset_type} {technology}",
    )
    text = shorten_text(redact(wordings[min(attempt, len(wordings) - 1)]), EvidenceLimits.QUERY_MAX_CHARS)
    return dataclasses.replace(request, text=text)


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


def _plan_fields(result: EvidenceResult, searched_at: str) -> dict[str, Any]:
    """One search result as the plan's threat stores it: its evidence and its search audit, dated."""
    return {
        "evidence": [item.as_doc() | {"searched_at": searched_at} for item in result.evidence],
        "intel_search": result.search.as_doc() | {"searched_at": searched_at},
    }


def _approved_only(fields: dict[str, Any], approved: set[IntelSource]) -> dict[str, Any]:
    """A search's fields without what came from a revoked source (this worker's index may still hold its
    records until it follows the next snapshot)."""
    evidence = [item for item in fields["evidence"] if _from_approved(item, approved)]
    if len(evidence) == len(fields["evidence"]):
        return fields
    if not evidence:
        # Nothing left: the top-k was chosen among the revoked source's records, so it is an outage, not a
        # settled "no evidence": the path waits for the rebuilt index. ponytail: a search that kept nothing
        # at all is trusted as settled even in that window; its candidates carry no source to tell.
        failed = fields["intel_search"] | {"failure": EvidenceSearchFailure.UNAVAILABLE}
        return {"evidence": [], "intel_search": failed}
    return fields | {"evidence": evidence}


def _from_approved(item: dict[str, Any], approved: set[IntelSource]) -> bool:
    """True when every source an evidence entry rests on is approved: its own and those joined into it."""
    legacy = _LEGACY_JOINED if item.get("kind") == IntelKind.VULNERABILITY else ()
    return {item.get("source"), *item.get("joined", legacy)} <= approved


def _is_settled(fields: dict[str, Any]) -> bool:
    """True for a search worth keeping on the plan: made against a snapshot, and not failed."""
    search = fields["intel_search"]
    return search.get("failure") is None and search.get("snapshot_id") is not None
