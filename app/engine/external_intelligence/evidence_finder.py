"""External evidence for threats: what is known about how such a threat is carried out, found in the evidence
index of the approved intelligence sources.

One batch: every request's search text is built by the caller, the IT / OT filter is applied BEFORE ranking,
ALL queries are embedded in ONE call, then each request's few candidates are reranked (a few in parallel, but
at most RERANKS_AT_ONCE in the whole process: the gate). A candidate is used, or left out with a recorded
reason. A search that cannot be made (a service down) leaves that request without evidence and says why; it
never fails the batch. The finder holds no run's state, so one instance serves every thread; the index is read
ONCE per batch, so a swap in the middle never mixes two indexes in one batch.

The threshold is the per-environment cut-off of the 0-100 ranking scores of the reranker in use (their scale
differs per model, so a score is never compared across models); the audit row names that model."""

import time
from collections.abc import Callable, Sequence
from dataclasses import replace
from typing import Any

import structlog

from app.ai.common import IncompleteAiAnswer, UnusableAiAnswer
from app.core.constants import EvidenceLimits, EvidenceSearchFailure, LogEvent
from app.core.exceptions import MONGO_UNAVAILABLE_ERRORS, REDIS_UNAVAILABLE_ERRORS, Unavailable
from app.engine.external_intelligence.evidence_search import EvidenceSearch
from app.engine.external_intelligence.evidence_selection import EvidenceSelector
from app.engine.external_intelligence.known_groups import pick_known_groups
from app.engine.external_intelligence.plain_facts import PlainFactWriter
from app.engine.external_intelligence.product_link import ProductLinkChecker
from app.engine.external_intelligence.rerank_gate import RerankGate, get_rerank_gate
from app.engine.shared.parallel import run_in_parallel
from app.models.external_intelligence.evidence import (
    Considered,
    Evidence,
    EvidenceBatchSummary,
    IntelHit,
)
from app.models.external_intelligence.evidence_request import EvidenceRequest, EvidenceResult
from app.models.external_intelligence.ranked_search_record import RankedSearchRecord
from app.search.external_intelligence import intelligence_metrics as metrics

log = structlog.get_logger(__name__)
#: How an embedding or rerank call can fail without the request being any less found: it has no evidence.
_SEARCH_ERRORS: tuple[type[Exception], ...] = (
    Unavailable,
    IncompleteAiAnswer,
    UnusableAiAnswer,
    *MONGO_UNAVAILABLE_ERRORS,
    *REDIS_UNAVAILABLE_ERRORS,
)


class EvidenceFinder:
    def __init__(
        self,
        search_provider: Callable[[], EvidenceSearch],
        threshold: float,
        *,
        gate: RerankGate | None = None,
        writer: PlainFactWriter | None = None,
    ) -> None:
        self._provider = search_provider  # the index in use now: empty until the first build is done
        self._threshold = threshold
        self._gate = gate or get_rerank_gate()
        self._selector = EvidenceSelector(threshold, writer or PlainFactWriter())

    def find_evidence(
        self, requests: Sequence[EvidenceRequest], *, stale: bool
    ) -> tuple[list[EvidenceResult], EvidenceBatchSummary]:
        """One result per request, in order, and what the batch did."""
        search = self._provider()
        searched = bool(requests) and search.has_records
        snapshot_id = search.snapshot_id if searched else None
        model = search.rerank_model
        if searched:
            results = self._search_all(search, requests, stale, model)
        else:
            results = [EvidenceResult((), _record(r, self._threshold, model)) for r in requests]
        return results, self._summarise(search, results, stale and searched, snapshot_id)

    def _search_all(
        self, search: EvidenceSearch, requests: Sequence[EvidenceRequest], stale: bool, model: str
    ) -> list[EvidenceResult]:
        def record(request: EvidenceRequest, *args: Any, **kwargs: Any) -> RankedSearchRecord:
            return _record(request, self._threshold, model, search.snapshot_id, *args, stale=stale, **kwargs)

        searches = [(request.text, request.asset_types) for request in requests]
        try:
            candidates = search.find_candidates(searches, EvidenceLimits.CANDIDATES)
        except (
            _SEARCH_ERRORS
        ):  # the embedding service: every request goes without evidence, the batch goes on
            log.warning(
                LogEvent.EXTERNAL_INTELLIGENCE_EVIDENCE_SEARCH_FAILED, requests=len(requests), exc_info=True
            )
            failure = EvidenceSearchFailure.UNAVAILABLE
            return [EvidenceResult((), record(r, failure=failure)) for r in requests]

        def rank_one(position: int) -> EvidenceResult:
            request = requests[position]
            try:
                scored = self._rerank(search, request.text, candidates[position])
            except _SEARCH_ERRORS:  # the reranker: this request alone goes without evidence
                log.warning(LogEvent.EXTERNAL_INTELLIGENCE_EVIDENCE_SEARCH_FAILED, requests=1, exc_info=True)
                return EvidenceResult((), record(request, failure=EvidenceSearchFailure.UNAVAILABLE))
            return self._chosen(search, request, scored, record)

        return run_in_parallel(
            rank_one, range(len(requests)), EvidenceLimits.SEARCHES_AT_ONCE, "evidence-rerank"
        )

    def _chosen(
        self,
        search: EvidenceSearch,
        request: EvidenceRequest,
        scored: list[IntelHit],
        record: Callable[..., RankedSearchRecord],
    ) -> EvidenceResult:
        """The evidence chosen from one request's scored candidates, each told what it says about place, and
        the real groups behind it (G230, G232); none chosen, the closest one, never cited (G254). No AI
        call."""
        checker = ProductLinkChecker(request.recorded_products)
        evidence, considered = self._selector.select(scored, checker)
        known, near = search.corpus.groups, request.near

        def placed(item: Evidence) -> Evidence:
            return replace(item, scope=near.scope(known.by_technique.get(item.ref, ())))

        evidence = tuple(map(placed, evidence))
        refs, related = [item.ref for item in evidence], [c.ref for c in considered]
        groups = pick_known_groups(request.actor, refs, related, known, near)
        closest = None if evidence else self._selector.nearest(scored, checker)
        return EvidenceResult(evidence, record(request, considered), groups, closest and placed(closest))

    def _rerank(self, search: EvidenceSearch, query: str, hits: list[IntelHit]) -> list[IntelHit]:
        if not hits:  # nothing to score: no call, no place in the gate
            return []
        with self._gate.hold_place():
            started = time.perf_counter()
            scored = search.score_candidates(query, hits)
            metrics.RERANK_SECONDS.observe(time.perf_counter() - started)
        return scored

    def _summarise(
        self, search: EvidenceSearch, results: list[EvidenceResult], stale: bool, snapshot_id: str | None
    ) -> EvidenceBatchSummary:
        used = sum(len(result.evidence) for result in results)
        found = sum(1 for result in results if result.evidence)
        if snapshot_id is not None:
            failed = sum(1 for result in results if result.search.failure is not None)
            metrics.EVIDENCE_SEARCHES.labels(metrics.MetricOutcome.FAILED).inc(failed)
            metrics.EVIDENCE_SEARCHES.labels(metrics.MetricOutcome.OK).inc(len(results) - failed)
            metrics.EVIDENCE_USED.inc(used)
        versions = dict(search.source_versions) if snapshot_id else {}
        searched = len(results) if snapshot_id else 0
        return EvidenceBatchSummary(snapshot_id, versions, searched, found, used, stale)


def _record(
    request: EvidenceRequest,
    threshold: float,
    model: str,
    snapshot_id: str | None = None,
    considered: tuple[Considered, ...] = (),
    *,
    stale: bool = False,
    failure: EvidenceSearchFailure | None = None,
) -> RankedSearchRecord:
    return RankedSearchRecord(
        request.text,
        tuple(sorted(request.asset_types)),
        snapshot_id,
        threshold,
        considered,
        stale,
        failure,
        model,
    )
