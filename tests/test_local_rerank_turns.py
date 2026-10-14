"""G222: the laptop's CPU reranker takes turns, scenarios first. A next set waited minutes behind control
mapping (40 controls per scenario, one prediction at a time); now a waiting foreground call goes before any
waiting background one, mapping scores a few documents per turn, and a stopped job never predicts."""

import threading
import time
from collections.abc import Callable

import pytest
from prometheus_client import REGISTRY

from app import ai
from app.core.constants import AiLimits, AiOutcome, AiTask, EvidenceLimits
from app.core.exceptions import LeaseLost
from app.core.lease_signal import lease_lost_signal
from app.models.ai import RerankModelProfile


class _Model:
    """A local model recording (caller, documents) per prediction; the first prediction for `hold` waits."""

    def __init__(self, hold: str = "") -> None:
        self.order: list[tuple[str, int]] = []
        self.holding, self.release = threading.Event(), threading.Event()
        self._hold = hold

    def predict(self, pairs: list[tuple[str, str]]) -> list[float]:
        caller = pairs[0][0]
        if caller == self._hold and not self.holding.is_set():
            self.holding.set()
            assert self.release.wait(10)
        self.order.append((caller, len(pairs)))
        return [0.5] * len(pairs)


def _reranker(model: _Model) -> ai.RerankModel:
    rerank = ai.RerankModel("test-local-rerank", RerankModelProfile(timeout_seconds=5), "", "")
    rerank._local_model = model  # the local model, as loaded on first use
    return rerank


def _start(work: Callable[[], object], *, background: bool, errors: list[BaseException]) -> threading.Thread:
    def run() -> None:
        try:
            if background:
                with ai.background_reranks():
                    work()
            else:
                work()
        except BaseException as exc:  # noqa: BLE001 — the test reads it
            errors.append(exc)

    thread = threading.Thread(target=run)
    thread.start()
    return thread


def _until(condition: Callable[[], bool]) -> None:
    deadline = time.monotonic() + 5
    while not condition():
        assert time.monotonic() < deadline
        time.sleep(0.01)


def test_a_waiting_scenario_goes_before_waiting_control_mapping() -> None:
    model = _Model(hold="mapping")
    rerank, errors = _reranker(model), []
    first = _start(lambda: rerank.score_relevance("mapping", ["a"]), background=True, errors=errors)
    assert model.holding.wait(5)
    more = _start(lambda: rerank.score_relevance("more mapping", ["b"]), background=True, errors=errors)
    time.sleep(0.05)  # the second mapping call waits first
    scenario = _start(lambda: rerank.score_relevance("scenario", ["c"]), background=False, errors=errors)
    _until(lambda: rerank._turns._foreground_waiting == 1)
    model.release.set()
    for thread in (first, more, scenario):
        thread.join(10)
    assert errors == [] and [caller for caller, _ in model.order] == ["mapping", "scenario", "more mapping"]


def test_mapping_scores_a_few_documents_per_turn_so_a_scenario_never_waits_for_the_whole_call() -> None:
    assert AiLimits.LOCAL_RERANK_TURN_DOCUMENTS == EvidenceLimits.CANDIDATES  # one turn = one evidence call
    model = _Model(hold="mapping")
    rerank, errors, scores = _reranker(model), [], {}
    mapping = _start(
        lambda: scores.update(mapping=rerank.score_relevance("mapping", [f"control {n}" for n in range(13)])),
        background=True,
        errors=errors,
    )
    assert model.holding.wait(5)
    scenario = _start(
        lambda: rerank.score_relevance("scenario", ["evidence"]), background=False, errors=errors
    )
    _until(lambda: rerank._turns._foreground_waiting == 1)
    model.release.set()
    for thread in (mapping, scenario):
        thread.join(10)
    assert errors == []
    assert model.order == [("mapping", 6), ("scenario", 1), ("mapping", 6), ("mapping", 1)]
    assert scores["mapping"] == [50.0] * 13  # every document, in order: the turns change no score


def _rerank_errors() -> float:
    labels = {"task": AiTask.RERANK, "model": "test-local-rerank", "outcome": AiOutcome.ERROR}
    return REGISTRY.get_sample_value("tsg_ai_calls_total", labels) or 0.0


def test_a_stopped_job_waiting_for_its_turn_never_predicts_and_is_no_ai_error() -> None:
    model = _Model(hold="scenario")
    rerank, errors, signal = _reranker(model), [], {}
    errors_before = _rerank_errors()
    first = _start(lambda: rerank.score_relevance("scenario", ["a"]), background=False, errors=errors)
    assert model.holding.wait(5)

    def cancelled_mapping() -> None:
        with lease_lost_signal("cancelled-run") as lost:
            signal["lost"] = lost
            rerank.score_relevance("mapping", ["b"])

    mapping = _start(cancelled_mapping, background=True, errors=errors)
    _until(lambda: "lost" in signal)
    signal["lost"].set()  # its owner cancelled the run while it waited
    model.release.set()
    for thread in (first, mapping):
        thread.join(10)
    assert [type(error) for error in errors] == [LeaseLost]
    assert [caller for caller, _ in model.order] == ["scenario"]
    assert _rerank_errors() == errors_before


def test_a_rerank_outside_background_work_is_foreground() -> None:
    assert not ai.reranks_in_background()
    with ai.background_reranks():
        assert ai.reranks_in_background()
    assert not ai.reranks_in_background()


@pytest.mark.parametrize("documents", [[], ["only one"]])
def test_short_calls_score_in_one_turn(documents: list[str]) -> None:
    model = _Model()
    assert _reranker(model).score_relevance("scenario", documents) == [50.0] * len(documents)
    assert model.order == ([("scenario", 1)] if documents else [])
