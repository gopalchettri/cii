"""Rerank gateway: how well each document answers the query, 0-100. A local model when no base URL is set
(dev), the proxy's reranker otherwise."""

import math
import time
from importlib.util import find_spec
from typing import Any

import litellm

from app.ai.attempts import call_with_retries, note_ai_usage, one_ask, search_tokens
from app.ai.common import (
    IncompleteAiAnswer,
    UnusableAiAnswer,
    build_api_key_header,
    count_and_convert_ai_errors,
)
from app.ai.local_turns import LocalTurns
from app.ai.profiles import RERANK_MODEL_PROFILES, find_model_profile
from app.ai.slots import UNLIMITED_AI_REQUEST_RATE, UNLIMITED_AI_SLOTS, AiRequestRate, AiSlots
from app.core import metrics
from app.core.config import Settings
from app.core.constants import AiLimits, AiOutcome, AiTask, ErrorMessage
from app.core.lease_signal import raise_if_lease_lost
from app.models.ai.profiles import RerankModelProfile

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
        request_rate: AiRequestRate = UNLIMITED_AI_REQUEST_RATE,
    ):
        self._model = model
        self.profile = profile
        self._base_url = base_url
        self._api_key = api_key
        self._key_header = build_api_key_header(key_header, api_key, option="headers")
        self._local_model: Any = None
        self._turns = LocalTurns()  # the local model: loaded once, one prediction at a time, scenarios first
        self._slots = slots  # remote calls only: a local model shares no provider
        self._request_rate = request_rate

    def score_relevance(self, query: str, documents: list[str]) -> list[float]:
        if not documents:
            return []
        # A local model that would not load is counted too, so AiErrorRateHigh sees it on the laptop.
        with one_ask():  # its failed attempts and its answer: one ask's usage rows, written as it ends
            with count_and_convert_ai_errors(AiTask.RERANK, self._model):
                if self._base_url:
                    (scores, tokens), seconds = self._score_with_provider(query, documents)
                else:  # a local model counts against no gateway's budget: no tokens
                    (scores, seconds), tokens = self._score_with_local_model(query, documents), {}
            # ponytail: a local (laptop-only) model that fails gets no usage row: it never reaches a provider
            note_ai_usage(AiTask.RERANK, self._model, AiOutcome.OK, seconds=seconds, **tokens)
        metrics.AI_CALLS.labels(AiTask.RERANK, self._model, AiOutcome.OK).inc()
        metrics.AI_SECONDS.labels(AiTask.RERANK, self._model).observe(seconds)
        return scores

    def preload(self) -> None:
        """Load the local model now, in a turn so no rerank loads it a second time (a cold load takes about 50
        s); the proxy's model needs none."""
        if self._base_url:
            return
        with self._turns.turn():
            self._loaded_local_model()

    def _score_with_provider(
        self, query: str, documents: list[str]
    ) -> tuple[tuple[list[float], dict[str, int]], float]:
        """((the scores, the tokens the gateway counted), the answering attempt's seconds)."""

        def ask() -> tuple[list[float], dict[str, int]]:
            response = litellm.rerank(
                model=self._model,
                query=query,
                documents=documents,
                top_n=len(documents),
                api_base=self._base_url,
                api_key=self._api_key,
                timeout=self.profile.timeout_seconds,
                **self._key_header,
            )
            return self._read_checked_scores(response, len(documents)), search_tokens(response)

        # call_with_retries is the only retry and holds an AI slot per try; a short answer is asked again too.
        return call_with_retries(ask, self._request_rate, self._slots, model=self._model, task=AiTask.RERANK)

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

    def _score_with_local_model(self, query: str, documents: list[str]) -> tuple[list[float], float]:
        """ponytail: dev-only CPU model; UAT uses the proxy. Loaded once per process on first use, and one
        prediction at a time (G199): one already uses every core, so ten at once (a worker's threads) only
        thrashed, and none of them finished in 38 minutes (live test 2026-10-11). A few documents per turn,
        scenarios first (G222, local_turns.py): a 40-control mapping never holds it while a next set waits.
        Each pair is scored on its own, so the turns change no score. (The scores, the seconds predicting:
        never the waits for a turn or the model's loading, as a provider call's are its own attempt's.)"""
        seconds, step = 0.0, AiLimits.LOCAL_RERANK_TURN_DOCUMENTS
        scores: list[float] = []
        for start in range(0, len(documents), step):
            with self._turns.turn():
                # A job stopped while it waited (G214) ends here: no CPU prediction for no one.
                raise_if_lease_lost()
                pairs = [(query, document) for document in documents[start : start + step]]
                model, started = self._loaded_local_model(), time.perf_counter()
                # CrossEncoder.predict already applies the sigmoid for a one-label model: scores are 0..1.
                scores += [100.0 * float(p) for p in model.predict(pairs)]
                seconds += time.perf_counter() - started
        return scores, seconds

    def _loaded_local_model(self) -> Any:
        if self._local_model is None:
            from sentence_transformers import CrossEncoder

            self._local_model = CrossEncoder(self._model)
        return self._local_model


def rerank_model_from(settings: Settings, slots: AiSlots, request_rate: AiRequestRate) -> RerankModel:
    """The rerank model the settings name; LocalRerankerMissing for a local model whose package is not
    installed, so start-up stops (API and worker build it at start) instead of every rerank failing later."""
    if not settings.rerank_base_url and find_spec(_LOCAL_PACKAGE) is None:
        raise LocalRerankerMissing(ErrorMessage.LOCAL_RERANKER_MISSING.format(model=settings.rerank_model))
    return RerankModel(
        settings.rerank_model,
        find_model_profile(RERANK_MODEL_PROFILES, settings.rerank_model),
        settings.rerank_base_url,
        settings.rerank_api_key.get_secret_value(),
        settings.ai_key_header,
        slots,
        request_rate,
    )
