"""Finds each threat's evidence in the active evidence index: one embedding call for the batch, a rerank per
threat behind the process gate, then the rule-based choice of what counts as evidence (the nearest when none
meets the threshold). A search that cannot be made leaves that threat without evidence and says why; it never
fails the batch."""

import threading
import time
from collections.abc import Callable, Collection, Sequence
from dataclasses import replace

import structlog

from app.ai.common import IncompleteAiAnswer, UnusableAiAnswer, outage_reason
from app.core.constants import (
    AiOutage,
    Applicability,
    EvidenceDecision,
    EvidenceLimits,
    EvidenceReason,
    EvidenceRole,
    EvidenceSearchFailure,
    IntelKind,
    IntelSource,
    LogEvent,
)
from app.core.exceptions import TEMPORARY_ERRORS
from app.domain.external_intelligence.facts import PlainFactWriter
from app.domain.external_intelligence.product_link import ProductLinkChecker
from app.domain.external_intelligence.rerank_gate import RerankGate
from app.domain.shared.parallel import run_in_parallel
from app.models.external_intelligence.evidence import (
    Considered,
    Evidence,
    EvidenceBatchSummary,
    EvidenceSearchRecord,
    IntelHit,
)
from app.models.external_intelligence.evidence_request import EvidenceRequest, EvidenceResult
from app.search.external_intelligence import intelligence_metrics as metrics
from app.search.external_intelligence.evidence_index import EvidenceIndex

log = structlog.get_logger(__name__)
#: How an embedding or rerank call can fail without the request being any less found: it has no evidence.
_SEARCH_ERRORS: tuple[type[Exception], ...] = (*TEMPORARY_ERRORS, IncompleteAiAnswer, UnusableAiAnswer)
#: The kinds whose record says which products and versions it concerns.
_HAS_APPLICABILITY = (IntelKind.VULNERABILITY, IntelKind.ADVISORY)
#: A candidate's evidence (None when left out) and the row that records the decision.
Judgement = tuple[Evidence | None, Considered]


class EvidenceFinder:
    """Shared by every thread: it holds no run's state and reads the index once per batch, so a swap in the
    middle never mixes two indexes in one batch."""

    def __init__(
        self,
        search_provider: Callable[[], EvidenceIndex],
        threshold: float,
        *,
        gate: RerankGate,
        candidates: int,
        kept_per_threat: int,
    ) -> None:
        self._provider = search_provider  # the index in use now: empty until the first build is done
        self._threshold = threshold  # the cut-off on the reranker's own 0-100 scale
        self._gate = gate
        self._candidates = candidates  # records reranked per threat (EVIDENCE_CANDIDATES)
        self._selector = EvidenceSelector(threshold, PlainFactWriter(), kept_per_threat)
        # Each candidate's score, best first, by (snapshot, rerank model, query, candidate ids): another path
        # of the same threat, a later set, a retry or another run asks the same rerank again.
        self._scored: dict[tuple[object, ...], tuple[tuple[tuple[IntelSource, str], float], ...]] = {}
        self._scored_lock = threading.Lock()

    def find_evidence(
        self, requests: Sequence[EvidenceRequest], *, stale: bool, approved: Collection[IntelSource]
    ) -> tuple[list[EvidenceResult], EvidenceBatchSummary]:
        """One result per request, in order, and what the batch did; candidates are of `approved` sources."""
        search = self._provider()
        searched = bool(requests) and search.has_records
        if searched:
            results = self._search_all(search, requests, stale, approved)
        else:  # nothing to search: settled empty, or no snapshot yet (search.snapshot_id says which)
            snapshot, outage, words = search.snapshot_id, search.outage, search.outage_message
            waiting = [self._record(search, r, snapshot, False, (), None, outage, words) for r in requests]
            results = [EvidenceResult((), record) for record in waiting]
        return results, _summary(search, results, stale and searched, searched)

    def _search_all(
        self,
        search: EvidenceIndex,
        requests: Sequence[EvidenceRequest],
        stale: bool,
        approved: Collection[IntelSource],
    ) -> list[EvidenceResult]:
        """Embed every request in one call (the IT / OT and approved-source filters applied before ranking),
        then rerank and choose each request's candidates, a few at once."""
        snapshot, down = search.snapshot_id, EvidenceSearchFailure.UNAVAILABLE
        searches = [(request.text, request.asset_types) for request in requests]
        try:
            candidates = search.find_candidates(searches, self._candidates, approved)
        except _SEARCH_ERRORS as exc:  # the embedding service: no request gets evidence, the batch goes on
            log.warning(
                LogEvent.EXTERNAL_INTELLIGENCE_EVIDENCE_SEARCH_FAILED, requests=len(requests), exc_info=True
            )
            outage = outage_reason(exc)
            lost = [self._record(search, r, snapshot, stale, (), down, outage, str(exc)) for r in requests]
            return [EvidenceResult((), record) for record in lost]

        def rank_one(position: int) -> EvidenceResult:
            """Rerank one request's candidates and choose its evidence."""
            request = requests[position]
            try:
                scored = self._rerank(search, request.text, candidates[position])
            except _SEARCH_ERRORS as exc:  # the reranker: this request alone gets no evidence now
                log.warning(LogEvent.EXTERNAL_INTELLIGENCE_EVIDENCE_SEARCH_FAILED, requests=1, exc_info=True)
                outage = outage_reason(exc)
                record = self._record(search, request, snapshot, stale, (), down, outage, str(exc))
                return EvidenceResult((), record)
            checker = ProductLinkChecker(request.recorded_products)
            evidence, considered = self._selector.select(scored, checker)
            return EvidenceResult(evidence, self._record(search, request, snapshot, stale, considered))

        return run_in_parallel(
            rank_one, range(len(requests)), EvidenceLimits.SEARCHES_AT_ONCE, "evidence-rerank"
        )

    def _rerank(self, search: EvidenceIndex, query: str, hits: list[IntelHit]) -> list[IntelHit]:
        """Score `hits` against `query` while holding a place of the rerank gate; no hits, no call. A rerank
        already answered for the same snapshot, model, query and candidates is taken from memory."""
        if not hits:
            return []
        candidate_ids = tuple((hit.source, hit.external_id) for hit in hits)
        key = (search.snapshot_id, search.rerank_model, query, candidate_ids)
        with self._scored_lock:
            known = self._scored.get(key)
        if known is not None:  # the scores only: the records are this index's own
            by_id = dict(zip(candidate_ids, hits, strict=True))
            return [replace(by_id[ref], score=score) for ref, score in known]
        with self._gate.hold_place():
            started = time.perf_counter()
            scored = search.score_candidates(query, hits)
            metrics.RERANK_SECONDS.observe(time.perf_counter() - started)
        # ponytail: first in, first out; an older snapshot's entries wait to be pushed out, never served.
        with self._scored_lock:  # only a whole answer gets here: a failed or short one raised
            self._scored[key] = tuple(((hit.source, hit.external_id), hit.score) for hit in scored)
            if len(self._scored) > EvidenceLimits.RERANKS_KEPT:
                del self._scored[next(iter(self._scored))]
        return scored

    def _record(
        self,
        search: EvidenceIndex,
        request: EvidenceRequest,
        snapshot_id: str | None,
        stale: bool,
        considered: tuple[Considered, ...] = (),
        failure: EvidenceSearchFailure | None = None,
        outage: AiOutage | None = None,
        outage_message: str = "",
    ) -> EvidenceSearchRecord:
        """The audit of one request's search, with the reranker and any outage in its own words."""
        types = tuple(sorted(request.asset_types))
        return EvidenceSearchRecord(
            request.text,
            types,
            snapshot_id,
            self._threshold,
            considered,
            stale,
            failure,
            search.rerank_model,
            outage,
            outage_message if outage else "",  # a fault not the AI's keeps its driver text out of the audit
        )


class EvidenceSelector:
    """Chooses a request's evidence from its scored candidates; the request's product checker is passed in."""

    def __init__(self, threshold: float, writer: PlainFactWriter, kept_per_threat: int) -> None:
        self._threshold = threshold
        self._writer = writer
        self._kept = kept_per_threat  # EVIDENCE_KEPT_PER_THREAT

    def select(
        self, scored: Sequence[IntelHit], checker: ProductLinkChecker
    ) -> tuple[tuple[Evidence, ...], tuple[Considered, ...]]:
        """The evidence used (best first, at most EVIDENCE_KEPT_PER_THREAT) and one row per candidate; when
        none meets the threshold, the nearest under it, by the same other rules, each marked nearest."""
        found = self._choose(scored, checker, nearest=False)
        return found if found[0] else self._choose(scored, checker, nearest=True)

    def _choose(
        self, scored: Sequence[IntelHit], checker: ProductLinkChecker, *, nearest: bool
    ) -> tuple[tuple[Evidence, ...], tuple[Considered, ...]]:
        """Every candidate judged, the threshold ignored when `nearest`; the usable ones within the limit."""
        usable: list[Evidence] = []
        rows: list[Considered | Evidence] = []
        for hit in scored:  # best first, so the limit keeps the most relevant
            evidence, row = self._judge(hit, usable, checker, nearest)
            if evidence is not None:
                usable.append(evidence)
            rows.append(evidence or row)
        used = choose_within_limit(usable, self._kept)
        return tuple(used), tuple(self._final_row(row, used) for row in rows)

    def _judge(
        self, hit: IntelHit, usable: list[Evidence], checker: ProductLinkChecker, nearest: bool
    ) -> Judgement:
        """Leave a candidate out when under the threshold (unless `nearest`), a product record the asset's
        products cannot tie or that concerns another product or version, or a duplicate; else make it
        evidence."""
        if hit.score < self._threshold and not nearest:
            return _left_out(hit, EvidenceDecision.BELOW_THRESHOLD, self._below_threshold(hit.score))
        applicability = None
        if hit.kind in _HAS_APPLICABILITY:
            if checker.has_no_link(hit):
                return _left_out(hit, EvidenceDecision.NO_PRODUCT_LINK, EvidenceReason.NO_PRODUCT_LINK.value)
            applicability, reason = checker.judge(hit)
            if applicability == Applicability.NOT_APPLICABLE:
                return _left_out(hit, EvidenceDecision.NOT_APPLICABLE, self._writer.safe_reason(reason))
        if any(item.ref == hit.external_id for item in usable):
            return _left_out(hit, EvidenceDecision.DUPLICATE, EvidenceReason.DUPLICATE.value)
        used = Considered(hit.external_id, hit.score, EvidenceDecision.USED)
        return self._evidence(hit, applicability, nearest), used

    def _evidence(self, hit: IntelHit, applicability: Applicability | None, nearest: bool) -> Evidence:
        """The evidence entry of a used candidate: its plain facts, cleaned title and link, and dates."""
        return Evidence(
            hit.external_id,
            hit.kind,
            hit.source,
            self._writer.safe_title(hit),
            self._writer.safe_url(hit),
            hit.score,
            self._writer.write_facts(hit),
            applicability,
            # The record's own publication date (NVD, ICS advisories), else its KEV listing date.
            published=hit.data.get("published") or hit.data.get("date_added") or None,
            modified=hit.modified,
            fetched_at=hit.fetched_at,
            # Direct only when the weakness is confirmed in the asset's own product; else context.
            role=EvidenceRole.DIRECT if applicability == Applicability.CONFIRMED else EvidenceRole.CONTEXT,
            mitigations=self._writer.safe_mitigations(hit),  # the control search reads them
            joined=hit.joined,
            nearest=nearest,
        )

    def _final_row(self, row: Considered | Evidence, used: list[Evidence]) -> Considered:
        """A usable record's row: USED when it fit the limit (a nearest one says its score is under the
        threshold), else OVER_LIMIT; other rows stand."""
        if isinstance(row, Considered):
            return row
        if any(row is item for item in used):
            reason = self._below_threshold(row.score) if row.nearest else ""
            return Considered(row.ref, row.score, EvidenceDecision.USED, reason)
        reason = EvidenceReason.OVER_LIMIT.format(limit=self._kept)
        return Considered(row.ref, row.score, EvidenceDecision.OVER_LIMIT, reason)

    def _below_threshold(self, score: float) -> str:
        """The reason a score under the threshold gives."""
        return EvidenceReason.BELOW_THRESHOLD.format(score=score, threshold=self._threshold)


def choose_within_limit(usable: list[Evidence], limit: int) -> list[Evidence]:
    """`usable` is best first. The first `limit` are taken; then, best first, every kind still missing takes
    the place of the lowest-scored record whose kind is held more than once. Order and ties are fixed."""
    chosen = list(usable[:limit])
    for extra in usable[limit:]:
        if any(item.kind == extra.kind for item in chosen):
            continue
        shared = [i for i, item in enumerate(chosen) if sum(o.kind == item.kind for o in chosen) > 1]
        if shared:
            chosen[shared[-1]] = extra
    return sorted(chosen, key=usable.index)


def _left_out(hit: IntelHit, decision: EvidenceDecision, reason: str) -> Judgement:
    """The judgement of a candidate left out, with the decision and its reason."""
    return None, Considered(hit.external_id, hit.score, decision, reason)


def _summary(
    search: EvidenceIndex, results: list[EvidenceResult], stale: bool, searched: bool
) -> EvidenceBatchSummary:
    """What the batch did, for its one audit row; the search metrics counted."""
    used = sum(len(result.evidence) for result in results)
    found = sum(1 for result in results if result.evidence)
    if not searched:  # no request, or nothing to search: no snapshot named, nothing counted
        return EvidenceBatchSummary(None, {}, 0, found, used, False)
    failed = sum(1 for result in results if result.search.failure is not None)
    metrics.EVIDENCE_SEARCHES.labels(metrics.MetricOutcome.FAILED).inc(failed)
    metrics.EVIDENCE_SEARCHES.labels(metrics.MetricOutcome.OK).inc(len(results) - failed)
    metrics.EVIDENCE_USED.inc(used)
    versions = dict(search.source_versions)
    return EvidenceBatchSummary(search.snapshot_id, versions, len(results), found, used, stale)
