"""What each AI model is like. `.env` only NAMES the model; its properties live here, keyed by that name.

Adding a model = one entry below + its name in `.env`; no other code changes. An unknown name stops the app
at start-up (main.py builds every AI gateway there), never a silent default that fails every later call."""

from pathlib import PurePath

from app.core.constants import ErrorMessage
from app.models.ai.profiles import ChatModelProfile, EmbeddingModelProfile, RerankModelProfile


class UnknownModelProfile(Exception):
    """The model named in .env has no entry in this file."""


CHAT_MODEL_PROFILES: dict[str, ChatModelProfile] = {
    # dev, Azure AI Foundry. Thinking off measured on this model: 6 output tokens instead of 45-139.
    # Context: the deployment's 100,000 tokens a minute (x-ratelimit-limit-tokens, 2026-10-23), below the
    # model's 262,144: one call over it is refused (429), however long the wait.
    "openai/Kimi-K2.6": ChatModelProfile(
        max_output_tokens=12_288,
        timeout_seconds=90,
        supports_json_mode=True,
        reasoning_effort="none",
        context_tokens=100_000,
    ),
    # UAT, LiteLLM proxy. kimi answers in ~5 s; 120 s covers its longest answers.
    # Context: the gateway's /model/info max_tokens (2026-07-29); no tpm or key limit set there.
    "litellm_proxy/kimi-k2.5": ChatModelProfile(
        max_output_tokens=12_288,
        timeout_seconds=120,
        supports_json_mode=True,
        reasoning_effort="none",
        context_tokens=262_144,
    ),
    # UAT's fallback model (CII_<MODULE>_CHAT_FALLBACK_MODEL); 1 million tokens of input (owner, 2026-10-23).
    # It answers in 55-99 s: 180 s keeps its longest answers from timing out (a timed-out gate batch fails
    # the job).
    "litellm_proxy/glm-5.3": ChatModelProfile(
        max_output_tokens=12_288,
        timeout_seconds=180,
        supports_json_mode=True,
        reasoning_effort="none",
        context_tokens=1_000_000,
    ),
}


EMBEDDING_MODEL_PROFILES: dict[str, EmbeddingModelProfile] = {
    "openai/text-embedding-3-large": EmbeddingModelProfile(
        dimensions=3072, batch_size=64, timeout_seconds=90, max_text_chars=8_000
    ),
    # UAT values (owner, 2026-10-08): as v1 runs them there. The query instruction is the model card's
    # (huggingface.co/Qwen/Qwen3-Embedding-8B, get_detailed_instruct: no space after "Query:").
    "litellm_proxy/qwen3-embedding-8b": EmbeddingModelProfile(
        dimensions=4096,
        batch_size=32,
        timeout_seconds=120,
        max_text_chars=4_000,
        concurrency=4,
        query_instruction="Instruct: {task}\nQuery:",
    ),
}


RERANK_MODEL_PROFILES: dict[str, RerankModelProfile] = {
    "bge-reranker-v2-m3": RerankModelProfile(timeout_seconds=90),  # dev, local folder
    "litellm_proxy/qwen3-reranker-8b": RerankModelProfile(timeout_seconds=120),
}


def find_model_profile[Profile](profiles: dict[str, Profile], model: str) -> Profile:
    """The profile for a model name from .env. A local model is configured as a folder path, so its
    profile is filed under the folder name (`C:/models/bge-reranker-v2-m3` -> `bge-reranker-v2-m3`)."""
    profile = profiles.get(model) or profiles.get(PurePath(model).name)
    if profile is None:
        raise UnknownModelProfile(ErrorMessage.MODEL_PROFILE_MISSING.format(model=model))
    return profile
