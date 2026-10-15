"""CII_AI_BYPASS_PROXY (v1's TSG_LITELLM_BYPASS_PROXY), set in the env file only: the UAT Windows server's
proxy cannot reach the LiteLLM gateway, so its host goes on NO_PROXY; no other host does. The AI key never
reaches a log."""

import logging
import os

import pytest

import app.ai  # noqa: F401  # caps the library loggers on import
from app.ai.common import bypass_proxy_for_ai
from app.core.config import Settings, get_settings

GATEWAY = "https://llmapi.example:443/v1"


def _settings(bypass: bool) -> Settings:
    return get_settings().model_copy(
        update={
            "ai_bypass_proxy": bypass,
            "chat_model": "litellm_proxy/chat",
            "chat_base_url": GATEWAY,
            "chat_fallback_model": "",
            "embedding_model": "litellm_proxy/embed",
            "embedding_base_url": "llmapi.example",  # no scheme: still read as a host
            "rerank_model": "openai/rerank",  # not a LiteLLM gateway model: its host keeps the proxy
            "rerank_base_url": "https://other-provider.example",
        }
    )


@pytest.fixture(autouse=True)
def _proxy_env(monkeypatch: pytest.MonkeyPatch) -> None:
    # Windows reads env names without case (one variable); Linux has two: clear both, then set one.
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.setenv("NO_PROXY", "localhost")


def test_the_gateway_goes_on_no_proxy_once_and_keeps_what_was_there() -> None:
    bypass_proxy_for_ai(_settings(True))
    bypass_proxy_for_ai(_settings(True))  # every model factory calls it
    assert os.environ["NO_PROXY"] == "localhost,llmapi.example"
    assert os.environ["no_proxy"].split(",")[-1] == "llmapi.example"  # Linux tools read the lowercase one


def test_off_leaves_the_proxy_in_charge() -> None:
    bypass_proxy_for_ai(_settings(False))
    assert os.environ["NO_PROXY"] == "localhost"
    assert "llmapi.example" not in os.environ.get("no_proxy", "")


def test_the_openai_client_cannot_log_the_ai_key() -> None:
    # At DEBUG it logs each request's headers, the gateway key among them (UAT log, 2026-10-15).
    assert logging.getLogger("openai").getEffectiveLevel() >= logging.WARNING
