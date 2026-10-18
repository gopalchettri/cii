"""G265 (laptop E2E 2026-10-16): CII_RERANK_BASE_URL empty runs the reranker on this machine, which needs the
sentence-transformers package. The worker's Python lacked it: every rerank failed at call time, the evidence
search was reported as "no_intelligence_snapshot", and each write job retried for minutes as if the AI were
busy. Start-up now stops, naming the package, as it does for a model with no profile."""

import pytest

from app import container
from app.ai import rerank
from app.ai.slots import UNLIMITED_AI_SLOTS
from app.core.config import Settings, get_settings
from app.worker import lifecycle


def _local_setup(monkeypatch: pytest.MonkeyPatch, base_url: str, installed: bool) -> Settings:
    monkeypatch.setattr(rerank, "find_spec", lambda name: object() if installed else None)
    return get_settings().model_copy(update={"rerank_base_url": base_url})


def test_a_local_reranker_without_its_package_stops_start_up(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _local_setup(monkeypatch, "", installed=False)
    with pytest.raises(rerank.LocalRerankerMissing, match="sentence-transformers"):
        rerank.rerank_model_from(settings, UNLIMITED_AI_SLOTS)


def test_the_worker_refuses_to_start_and_says_why(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _local_setup(monkeypatch, "", installed=False)

    def local_model() -> rerank.RerankModel:
        return rerank.rerank_model_from(settings, UNLIMITED_AI_SLOTS)

    monkeypatch.setattr(container, "get_rerank_model", local_model)
    with pytest.raises(SystemExit, match="sentence-transformers"):
        lifecycle._prepare_stores_and_models()


@pytest.mark.parametrize(("base_url", "installed"), [("http://rerank.invalid", False), ("", True)])
def test_a_reranker_service_or_an_installed_package_starts(
    monkeypatch: pytest.MonkeyPatch, base_url: str, installed: bool
) -> None:
    settings = _local_setup(monkeypatch, base_url, installed)
    assert isinstance(rerank.rerank_model_from(settings, UNLIMITED_AI_SLOTS), rerank.RerankModel)
