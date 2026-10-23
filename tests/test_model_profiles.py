"""Model profiles: every configured model resolves, a local path resolves by folder, an unknown name stops."""

import dataclasses
import re
from pathlib import Path

import pytest

from app.ai.profiles import (
    CHAT_MODEL_PROFILES,
    EMBEDDING_MODEL_PROFILES,
    RERANK_MODEL_PROFILES,
    UnknownModelProfile,
    find_model_profile,
)
from app.models.ai.profiles import ChatModelProfile

_PROFILES_BY_SETTING = {
    "CII_CHAT_MODEL": CHAT_MODEL_PROFILES,
    "CII_CHAT_FALLBACK_MODEL": CHAT_MODEL_PROFILES,
    "CII_EMBEDDING_MODEL": EMBEDDING_MODEL_PROFILES,
    "CII_RERANK_MODEL": RERANK_MODEL_PROFILES,
}


def test_every_model_named_in_env_example_has_a_profile() -> None:
    env_example = (Path(__file__).parents[1] / ".env.example").read_text(encoding="utf-8")
    for setting, profiles in _PROFILES_BY_SETTING.items():
        match = re.search(rf"^{setting}=(\S*)", env_example, re.MULTILINE)
        assert match, setting
        if match.group(1):  # an empty fallback model is allowed
            find_model_profile(profiles, match.group(1))


def test_a_local_model_path_resolves_by_its_folder_name() -> None:
    profile = find_model_profile(RERANK_MODEL_PROFILES, "C:/models/bge-reranker-v2-m3")
    assert profile is RERANK_MODEL_PROFILES["bge-reranker-v2-m3"]


def test_an_unknown_model_name_is_refused_with_its_name() -> None:
    with pytest.raises(UnknownModelProfile, match="openai/gpt-unknown"):
        find_model_profile(CHAT_MODEL_PROFILES, "openai/gpt-unknown")


def test_each_chat_model_states_its_own_context_with_the_answer_kept_free() -> None:
    """No shared default limit: each model's comes from its own context (sources in app/ai/profiles.py)."""
    defaults = {
        field.name
        for field in dataclasses.fields(ChatModelProfile)
        if field.default is not dataclasses.MISSING
    }
    assert "context_tokens" not in defaults
    contexts = {name: chat.context_tokens for name, chat in CHAT_MODEL_PROFILES.items()}
    assert contexts == {
        "openai/Kimi-K2.6": 100_000,
        "litellm_proxy/kimi-k2.5": 262_144,
        "litellm_proxy/glm-5.3": 1_000_000,
    }
    assert CHAT_MODEL_PROFILES["openai/Kimi-K2.6"].max_input_chars == (100_000 - 12_288) * 3


def test_the_uat_models_keep_the_values_uat_runs_with() -> None:
    """Owner's UAT values (2026-10-08). Reasoning stays "none": v1 UAT sends that too (thinking off)."""
    for name in ("litellm_proxy/kimi-k2.5", "litellm_proxy/glm-5.3"):
        chat = CHAT_MODEL_PROFILES[name]
        assert (chat.max_output_tokens, chat.supports_json_mode, chat.reasoning_effort) == (
            12_288,
            True,
            "none",
        )
    embed = EMBEDDING_MODEL_PROFILES["litellm_proxy/qwen3-embedding-8b"]
    assert (embed.dimensions, embed.batch_size, embed.max_text_chars, embed.concurrency) == (
        4096,
        32,
        4000,
        4,
    )
    assert "litellm_proxy/qwen3-reranker-8b" in RERANK_MODEL_PROFILES
