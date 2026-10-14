"""External evidence at write time: the threats whose scenarios a batch is about to write are searched
together (ONE embedding call for the batch), then saved on the plan. A plan lists many more threats than are
ever written (set by set, only when asked), so planning searches none.

The caller decided the batch is written as evidence stories (the switch read once, there: G229), so this never
reads the switch again. A threat is searched once: one already carrying its search (a path tried again, a
redelivery, a regenerate) keeps it, so a scenario's numbered evidence never changes between versions. A search
that found nothing usable is made again with other words, EVIDENCE_SEARCH_RETRIES times at most (no AI call;
the earlier searches kept in intel_search.attempts). A search that could not be made (an outage, or no
snapshot yet) is NOT saved: the threat's path waits (the evidence gate holds it back) and a later delivery
searches again."""

from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

import structlog

from app.core.config import get_settings
from app.core.constants import AuditAction, AuditTarget, LogEvent, TaskName
from app.data_access.audit import record_audit
from app.models.asset_context import FrozenContext
from app.models.external_intelligence.evidence import EvidenceBatchSummary
from app.models.external_intelligence.evidence_request import EvidenceRequest, EvidenceResult
from app.worker.external_intelligence.evidence_request_builder import EvidenceRequestBuilder
from app.worker.external_intelligence.intel_access import IntelAccess
from app.worker.plan_progress import PlanProgress

log = structlog.get_logger(__name__)

#: A threat's evidence and the audit of its search, as the plan and the brief hold them.
Found = dict[str, dict[str, Any]]


class EvidenceAtWrite:
    def __init__(
        self,
        run: dict[str, Any],
        threats: dict[str, dict[str, Any]],
        progress: PlanProgress,
        access: IntelAccess,
    ) -> None:
        self._run, self._threats, self._progress, self._access = run, threats, progress, access

    def attach(self, path_ids: Iterable[str]) -> None:
        """Searches the distinct threats of these paths that carry no search yet, sets the evidence on them
        (the writer's brief reads it there), saves what settled on the plan, and audits each search batch."""
        keys = self._unsearched(path_ids)
        if not keys:
            return
        builder = EvidenceRequestBuilder(FrozenContext.from_record(self._run["context"]))
        try:
            found = self._search_with_retries(builder, keys)
        except Exception:  # noqa: BLE001 - a search fault never costs the batch: its paths wait as outages
            log.warning(
                LogEvent.EXTERNAL_INTELLIGENCE_EVIDENCE_SEARCH_FAILED, threats=len(keys), exc_info=True
            )
            return
        for key, fields in found.items():
            self._threats[key].update(fields)
        settled = {key: fields for key, fields in found.items() if _is_settled(fields)}
        if settled:
            self._progress.keep_evidence(settled)

    def _search_with_retries(self, builder: EvidenceRequestBuilder, keys: list[str]) -> Found:
        """Each threat's evidence and search; one that settled with nothing usable is searched again with
        other words, up to EVIDENCE_SEARCH_RETRIES times, its earlier searches kept as `attempts`."""
        found = self._find({key: builder.build(self._threats[key]) for key in keys})
        for attempt in range(get_settings().evidence_search_retries):
            empty = [key for key, fields in found.items() if _is_settled(fields) and not fields["evidence"]]
            if not empty:
                break
            again = self._find({key: builder.alternative(self._threats[key], attempt) for key in empty})
            for key, fields in again.items():
                earlier = found[key]["intel_search"]
                past = [*earlier.pop("attempts", []), earlier]
                found[key] = fields | {"intel_search": fields["intel_search"] | {"attempts": past}}
        return found

    def _find(self, requests: dict[str, EvidenceRequest]) -> Found:
        """One search batch (one embedding call), audited once; each threat's fields with when it was made."""
        results, summary = self._access.find_evidence(list(requests.values()))
        self._audit(summary)
        searched_at = datetime.now(UTC).isoformat()
        return {key: _fields_of(result, searched_at) for key, result in zip(requests, results, strict=True)}

    def _unsearched(self, path_ids: Iterable[str]) -> list[str]:
        steps = {step for path_id in path_ids for step in self._progress.paths[path_id].get("steps") or ()}
        return [
            key
            for key in sorted(steps)
            if key in self._threats and self._threats[key].get("intel_search") is None
        ]

    def _audit(self, summary: EvidenceBatchSummary) -> None:
        """ONE row per search batch: which snapshot, how many threats, how much evidence. The per-threat
        search is audited on its scenario (content.intel_search)."""
        if summary.snapshot_id is None:
            return
        target = {"type": AuditTarget.SESSION, "id": self._run["_id"]}
        actor = {"system": TaskName.WRITE_SCENARIOS}
        record_audit(AuditAction.EXTERNAL_INTELLIGENCE_EVIDENCE_USED, actor, target, after=summary.as_doc())


def _fields_of(result: EvidenceResult, searched_at: str) -> dict[str, Any]:
    return {
        "evidence": [item.as_doc() | {"searched_at": searched_at} for item in result.evidence],
        "intel_search": result.search.as_doc() | {"searched_at": searched_at},
        "known_groups": [group.as_doc() for group in result.groups],  # G230: kept with the evidence
    }


def _is_settled(fields: dict[str, Any]) -> bool:
    """A search worth keeping on the plan: made against a snapshot, and not failed."""
    search = fields["intel_search"]
    return search.get("failure") is None and search.get("snapshot_id") is not None
