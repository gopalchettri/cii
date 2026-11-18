"""The process-wide limit on evidence reranks."""

import threading
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import replace
from decimal import ROUND_FLOOR, Decimal
from typing import Any

import structlog

from app.ai.common import IncompleteAiAnswer, UnusableAiAnswer
from app.core.asset_types import compatible_asset_types
from app.core.clock import utc_now
from app.core.config import get_settings
from app.core.constants import (
    AiOutage,
    EvidenceDecision,
    EvidenceLimits,
    EvidenceReason,
    EvidenceSearchFailure,
    IntelLimits,
    IntelSource,
    LogEvent,
    RerankGateLimits,
)
from app.core.exceptions import TEMPORARY_ERRORS, outage_reason
from app.core.lease_signal import raise_if_lease_lost
from app.core.redaction import clipped_text, redact
from app.core.singletons import singleton
from app.domain.intel.facts import safe_mitigations, safe_title, safe_url, write_facts
from app.domain.intel.index import EvidenceIndex, get_evidence_index_keeper
from app.domain.shared.names import shorten_text
from app.domain.shared.parallel import run_in_parallel
from app.schemas.intel_records import (
    Considered,
    Evidence,
    EvidenceRequest,
    EvidenceResult,
    EvidenceSearchRecord,
    IntelHit,
)
from app.schemas.scenario_internal import FrozenContext


class RerankGate:
    """A bounded number of places for evidence reranks; a waiter checks its lease every `check_every` s."""

    def __init__(self, size: int, check_every: float = RerankGateLimits.CHECK_EVERY_SECONDS) -> None:
        """`size` places."""
        self._places = threading.BoundedSemaphore(size)
        self._check_every = check_every

    @contextmanager
    def hold_place(self) -> Iterator[None]:
        """Hold one place of the gate for the block: waits as long as the lease holds."""
        raise_if_lease_lost()
        while not self._places.acquire(timeout=self._check_every):
            raise_if_lease_lost()
        try:
            yield
        finally:
            self._places.release()


def rerank_gate_for(rerank_base_url: str) -> RerankGate:
    """The gate for the reranker in use: a remote one."""
    if rerank_base_url:
        return RerankGate(RerankGateLimits.RERANKS_AT_ONCE)
    return RerankGate(RerankGateLimits.LOCAL_RERANKS_AT_ONCE)


log = structlog.get_logger(__name__)
#: How an embedding or rerank call can fail without the request being any less found: it has no evidence.
_SEARCH_ERRORS: tuple[type[Exception], ...] = (*TEMPORARY_ERRORS, IncompleteAiAnswer, UnusableAiAnswer)


#: Each candidate's score, best first, by (snapshot, rerank model, query, candidate ids): another path of the
#: same threat, a later set, a retry or another run asks the same rerank again.
_scored: dict[tuple[object, ...], tuple[tuple[tuple[IntelSource, str], float], ...]] = {}
_scored_lock = threading.Lock()


@singleton
def get_rerank_gate() -> RerankGate:
    """The process's one rerank gate."""
    return rerank_gate_for(get_settings().rerank_base_url)


def find_evidence(requests: Sequence[EvidenceRequest]) -> list[EvidenceResult]:
    """One result per request, in order, from the index in use now (empty until the first build is done)."""
    search, settings = get_evidence_index_keeper().current_index(), get_settings()
    threshold, kept = settings.evidence_similarity_threshold, settings.evidence_kept_per_threat

    def lost(request: EvidenceRequest, exc: Exception | None = None) -> EvidenceResult:
        """No evidence: nothing to search (the index says why), or the search failed with `exc`."""
        failure = None if exc is None else EvidenceSearchFailure.UNAVAILABLE
        outage, words = (search.outage, search.outage_message) if exc is None else (outage_reason(exc), str(exc))
        return EvidenceResult((), _record(search, request, threshold, (), failure, outage, words))

    if not requests or not search.has_records:  # settled empty, or no snapshot yet (snapshot_id says which)
        return [lost(request) for request in requests]
    searches = [(request.text, request.asset_types) for request in requests]
    try:
        candidates = search.find_candidates(searches, settings.evidence_candidates)
    except _SEARCH_ERRORS as exc:  # the embedding service: no request gets evidence, the batch goes on
        log.warning(LogEvent.EXTERNAL_INTELLIGENCE_EVIDENCE_SEARCH_FAILED, requests=len(requests), exc_info=True)
        return [lost(request, exc) for request in requests]

    def rank_one(position: int) -> EvidenceResult:
        """Rerank one request's candidates and choose its evidence."""
        request = requests[position]
        try:
            scored = _rerank(search, request.text, candidates[position])
        except _SEARCH_ERRORS as exc:  # the reranker: this request alone gets no evidence now
            log.warning(LogEvent.EXTERNAL_INTELLIGENCE_EVIDENCE_SEARCH_FAILED, requests=1, exc_info=True)
            return lost(request, exc)
        found = _choose(scored, threshold, kept, nearest=False)
        evidence, considered = found if found[0] else _choose(scored, threshold, kept, nearest=True)
        return EvidenceResult(evidence, _record(search, request, threshold, considered))

    return run_in_parallel(rank_one, range(len(requests)), EvidenceLimits.SEARCHES_AT_ONCE, "evidence-rerank")


def _rerank(search: EvidenceIndex, query: str, hits: list[IntelHit]) -> list[IntelHit]:
    if not hits:
        return []
    candidate_ids = tuple((hit.source, hit.external_id) for hit in hits)
    key = (search.snapshot_id, search.rerank_model, query, candidate_ids)
    with _scored_lock:
        known = _scored.get(key)
    if known is not None:  # the scores only: the records are this index's own
        by_id = dict(zip(candidate_ids, hits, strict=True))
        return [replace(by_id[ref], score=score) for ref, score in known]
    with get_rerank_gate().hold_place():
        scored = search.score_candidates(query, hits)
    # ponytail: first in, first out; an older snapshot's entries wait to be pushed out, never served.
    with _scored_lock:  # only a whole answer gets here: a failed or short one raised
        _scored[key] = tuple(((hit.source, hit.external_id), hit.score) for hit in scored)
        if len(_scored) > EvidenceLimits.RERANKS_KEPT:
            del _scored[next(iter(_scored))]
    return scored


def _record(
    search: EvidenceIndex,
    request: EvidenceRequest,
    threshold: float,
    considered: tuple[Considered, ...] = (),
    failure: EvidenceSearchFailure | None = None,
    outage: AiOutage | None = None,
    outage_message: str = "",
) -> EvidenceSearchRecord:
    types = tuple(sorted(request.asset_types))
    return EvidenceSearchRecord(
        request.text,
        types,
        search.snapshot_id,
        threshold,
        considered,
        failure,
        search.rerank_model,
        outage,
        outage_message if outage else "",  # a fault not the AI's keeps its driver text out of the audit
    )


def _choose(
    scored: Sequence[IntelHit], threshold: float, kept: int, *, nearest: bool
) -> tuple[tuple[Evidence, ...], tuple[Considered, ...]]:
    usable: list[IntelHit] = []
    rows: list[Considered | IntelHit] = []
    for hit in scored:  # best first, so the limit keeps the most relevant
        row = _judge(hit, usable, threshold, nearest)
        if row is None:
            usable.append(hit)
        rows.append(row or hit)
    used = usable[:kept]
    evidence = tuple(_evidence(hit, nearest) for hit in used)
    return evidence, tuple(_final_row(row, used, threshold, kept, nearest) for row in rows)


def _judge(hit: IntelHit, usable: list[IntelHit], threshold: float, nearest: bool) -> Considered | None:
    if hit.score < threshold and not nearest:
        return _left_out(hit, EvidenceDecision.BELOW_THRESHOLD, _below_threshold(hit.score, threshold))
    if any(item.external_id == hit.external_id for item in usable):
        return _left_out(hit, EvidenceDecision.DUPLICATE, EvidenceReason.DUPLICATE.value)
    return None


def _final_row(
    row: Considered | IntelHit, used: list[IntelHit], threshold: float, kept: int, nearest: bool
) -> Considered:
    if isinstance(row, Considered):
        return row
    if any(row is item for item in used):
        reason = _below_threshold(row.score, threshold) if nearest else ""
        return Considered(row.external_id, row.score, EvidenceDecision.USED, reason)
    reason = EvidenceReason.OVER_LIMIT.format(limit=kept)
    return Considered(row.external_id, row.score, EvidenceDecision.OVER_LIMIT, reason)


def _below_threshold(score: float, threshold: float) -> str:
    shown = Decimal(score).quantize(Decimal("0.1"), rounding=ROUND_FLOOR)  # exact: 29.96 reads 29.9
    return EvidenceReason.BELOW_THRESHOLD.format(score=shown, threshold=threshold)


def _evidence(hit: IntelHit, nearest: bool) -> Evidence:
    return Evidence(
        hit.external_id,
        hit.kind,
        hit.source,
        safe_title(hit),
        safe_url(hit),
        hit.score,
        write_facts(hit),
        modified=hit.modified,
        fetched_at=hit.fetched_at,
        mitigations=safe_mitigations(hit),  # the control search reads them
        nearest=nearest,
    )


def _left_out(hit: IntelHit, decision: EvidenceDecision, reason: str) -> Considered:
    return Considered(hit.external_id, hit.score, decision, reason)


def attach_evidence(
    run: dict[str, Any], threats: dict[str, dict[str, Any]], paths: dict[str, dict[str, Any]], path_ids: Iterable[str]
) -> None:
    """Search every distinct threat of these paths and set its evidence and search on it."""
    steps = {step for path_id in path_ids for step in paths[path_id].get("steps") or ()}
    keys = [key for key in sorted(steps) if key in threats]
    if not keys:
        return
    context = FrozenContext.from_record(run["context"])
    try:
        results = find_evidence([evidence_request(context, threats[key]) for key in keys])
    except TEMPORARY_ERRORS as exc:  # an outage never costs the batch: its paths wait
        log.warning(LogEvent.EXTERNAL_INTELLIGENCE_EVIDENCE_SEARCH_FAILED, threats=len(keys), exc_info=True)
        fault = clipped_text(redact(f"{type(exc).__name__}: {exc}"), IntelLimits.FAILURE_REASON_CHARS)
        for key in keys:
            threats[key]["intel_search"] = {"failure": fault, "outage": outage_reason(exc)}
        return
    searched_at = utc_now().isoformat()
    for key, result in zip(keys, results, strict=True):
        threats[key]["evidence"] = [item.as_doc() | {"searched_at": searched_at} for item in result.evidence]
        threats[key]["intel_search"] = result.search.as_doc() | {"searched_at": searched_at}


def evidence_request(context: FrozenContext, threat: dict[str, Any]) -> EvidenceRequest:
    """The search for one plan threat: its type and name only (redacted and cut)."""
    wanted = set(threat.get("systems") or ())
    systems = [system for system in context.systems if system.get("id") in wanted] or list(context.systems)
    types = compatible_asset_types(
        context.asset.get("category_code"), (system.get("category_code") for system in systems)
    )
    text = shorten_text(redact(f"Threat: {threat['type']['name']}: {threat['name']}"), EvidenceLimits.QUERY_MAX_CHARS)
    return EvidenceRequest(text, types)
