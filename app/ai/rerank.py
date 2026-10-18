"""Rerank gateway: how well each document answers the query, 0-100. A local model when no base URL is set
(dev), the proxy's reranker otherwise."""

import math
import time
from importlib.util import find_spec
from typing import Any

import litellm

from app.ai.common import (
    IncompleteAiAnswer,
    UnusableAiAnswer,
    apply_proxy_settings,
    build_api_key_header,
    call_with_retries,
    count_and_convert_ai_errors,
)
from app.ai.local_turns import LocalTurns
from app.ai.profiles import RERANK_MODEL_PROFILES, find_model_profile
from app.ai.slots import UNLIMITED_AI_SLOTS, AiSlots, get_ai_slots, max_slot_hold_seconds
from app.core import metrics
from app.core.config import get_settings
from app.core.constants import AiLimits, AiOutcome, AiTask, ErrorMessage
from app.core.lease_signal import raise_if_lease_lost
from app.core.singletons import singleton
from app.models.ai import RerankModelProfile

#: What the local reranker loads its model with (pyproject's "local" extra; requirements.txt).
_LOCAL_PACKAGE = "sentence_transformers"


class LocalRerankerMissing(Exception):
    """CII_RERANK_BASE_URL is empty, so the reranker runs on this machine; its package is not installed."""


class RerankModel:
    def __init__(  # noqa: PLR0913 — the provider's address, key and limiter: each one is needed
        self,
        model: str,
        profile: RerankModelProfile,
        base_url: str,
        api_key: str,
        key_header: str = "",
        slots: AiSlots = UNLIMITED_AI_SLOTS,
    ):
        self._model = model
        self.profile = profile
        self._base_url = base_url
        self._api_key = api_key
        self._key_header = build_api_key_header(key_header, api_key, option="headers")
        self._local_model: Any = None
        self._turns = LocalTurns()  # the local model: loaded once, one prediction at a time, scenarios first
        self._slots = slots  # remote calls only: a local model shares no provider

    def score_relevance(self, query: str, documents: list[str]) -> list[float]:
        if not documents:
            return []
        started = time.perf_counter()
        # A local model that would not load is counted too, so AiErrorRateHigh sees it on the laptop.
        with count_and_convert_ai_errors(AiTask.RERANK, self._model):
            scores = (
                self._score_with_provider(query, documents)
                if self._base_url
                else self._score_with_local_model(query, documents)
            )
        metrics.AI_CALLS.labels(AiTask.RERANK, self._model, AiOutcome.OK).inc()
        metrics.AI_SECONDS.labels(AiTask.RERANK, self._model).observe(time.perf_counter() - started)
        return scores

    def _score_with_provider(self, query: str, documents: list[str]) -> list[float]:
        # call_with_retries is the only retry; a short answer is asked again too.
        with self._slots.hold_slot(max_slot_hold_seconds(self.profile.timeout_seconds)):
            return call_with_retries(
                lambda: self._read_checked_scores(
                    litellm.rerank(
                        model=self._model,
                        query=query,
                        documents=documents,
                        top_n=len(documents),
                        api_base=self._base_url,
                        api_key=self._api_key,
                        timeout=self.profile.timeout_seconds,
                        **self._key_header,
                    ),
                    len(documents),
                )
            )

    def _read_checked_scores(self, response: Any, expected: int) -> list[float]:
        """0-100 per document, in input order, checked: exactly one score per document, each a probability
        (finite, 0-1)."""
        results = sorted(response.results, key=lambda result: result["index"])
        if [result["index"] for result in results] != list(range(expected)):
            # A missing document would otherwise score 0 in silence and its control would just vanish.
            raise IncompleteAiAnswer(
                ErrorMessage.AI_ANSWER_INCOMPLETE.format(
                    task=AiTask.RERANK, model=self._model, expected=expected
                )
            )
        scores = [float(result["relevance_score"]) for result in results]
        if bad := [score for score in scores if not (math.isfinite(score) and 0.0 <= score <= 1.0)]:
            # A raw logit times 100 would pass the 75 bar or the 60 control cut-off by accident (G112).
            raise UnusableAiAnswer(
                ErrorMessage.RERANK_SCORE_OUT_OF_RANGE.format(model=self._model, score=bad[0])
            )
        return [100.0 * score for score in scores]

    def _score_with_local_model(self, query: str, documents: list[str]) -> list[float]:
        """ponytail: dev-only CPU model; UAT uses the proxy. Loaded once per process on first use, and one
        prediction at a time (G199): one already uses every core, so ten at once (a worker's threads) only
        thrashed, and none of them finished in 38 minutes (live test 2026-10-11). A few documents per turn,
        scenarios first (G222, local_turns.py): a 40-control mapping never holds it while a next set waits.
        Each pair is scored on its own, so the turns change no score."""
        step = AiLimits.LOCAL_RERANK_TURN_DOCUMENTS
        scores: list[float] = []
        for start in range(0, len(documents), step):
            with self._turns.turn():
                # A job stopped while it waited (G214) ends here: no CPU prediction for no one.
                raise_if_lease_lost()
                pairs = [(query, document) for document in documents[start : start + step]]
                # CrossEncoder.predict already applies the sigmoid for a one-label model: scores are 0..1.
                scores += [100.0 * float(p) for p in self._loaded_local_model().predict(pairs)]
        return scores

    def _loaded_local_model(self) -> Any:
        if self._local_model is None:
            from sentence_transformers import CrossEncoder

            self._local_model = CrossEncoder(self._model)
        return self._local_model


@singleton
def get_rerank_model() -> RerankModel:
    """G265 (laptop E2E 2026-10-16): a local reranker whose package is missing stops start-up here (API and
    worker build it at start), as a model with no profile does. Before, every rerank failed at call time and
    each write job retried for minutes as if the AI were busy."""
    settings = get_settings()
    if not settings.rerank_base_url and find_spec(_LOCAL_PACKAGE) is None:
        raise LocalRerankerMissing(ErrorMessage.LOCAL_RERANKER_MISSING.format(model=settings.rerank_model))
    apply_proxy_settings(settings)
    return RerankModel(
        settings.rerank_model,
        find_model_profile(RERANK_MODEL_PROFILES, settings.rerank_model),
        settings.rerank_base_url,
        settings.rerank_api_key.get_secret_value(),
        settings.ai_key_header,
        get_ai_slots(),
    )
