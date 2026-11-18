"""What each AI model is like. `.env` only NAMES the model; its properties live here, keyed by that name.

Adding a model = one entry below + its name in `.env`; no other code changes. An unknown name stops the app
at start-up (main.py builds every AI gateway there), never a silent default that fails every later call."""

from dataclasses import dataclass
from pathlib import PurePath

from app.core.constants import AiLimits, ErrorMessage


@dataclass(frozen=True)
class ChatModelProfile:
    max_output_tokens: int  # counts hidden thinking as well as the visible answer
    timeout_seconds: int  # one reply; proxy models queue under load
    supports_json_mode: bool  # sends response_format=json_object
    reasoning_effort: str | None  # "none" = thinking off (owner decision); None = never sent
    # Most tokens one call holds, prompt and answer together: the smaller of the model's context window and
    # any cap in front of it (a gateway's, a deployment's tokens per minute).
    context_tokens: int

    @property
    def max_input_chars(self) -> int:
        """Longest prompt sent, the answer's tokens kept free: a longer one raises TruncatedAiAnswer."""
        return (self.context_tokens - self.max_output_tokens) * AiLimits.PROMPT_CHARS_PER_TOKEN


@dataclass(frozen=True)
class EmbeddingModelProfile:
    dimensions: int  # the model's native vector length; every answer is checked against it
    batch_size: int  # the provider's per-request cap, not a preference
    timeout_seconds: int
    max_text_chars: int  # longer texts are cut to this before embedding (the model's input limit)
    concurrency: int = 1  # batches sent at once when one call has several (the provider's allowance)
    # Raise by 1 when the provider re-points this model name to other weights of the same size: every stored
    # vector is then made again, instead of new and old vectors being compared (silently wrong rankings).
    revision: int = 1
    # What a search query is sent after, `{task}` the search's task (QUERY_TASKS), as the model card asks;
    # None: the model takes queries plain. Library texts are always sent plain.
    query_instruction: str | None = None

    def instruction_for(self, task: str) -> str | None:
        """The instruction a query of `task` is sent after; None when the model takes queries plain."""
        return None if self.query_instruction is None else self.query_instruction.format(task=task)

    def query_as_sent(self, query: str, task: str) -> str:
        """The query after its instruction, the query (never the instruction) cut to fit max_text_chars."""
        instruction = self.instruction_for(task) or ""
        return instruction + query[: self.max_text_chars - len(instruction)]


@dataclass(frozen=True)
class RerankModelProfile:
    timeout_seconds: int  # remote models only; a local model runs in-process


class UnknownModelProfile(Exception):
    """The model named in .env has no entry in this file."""


#: Positional: max_output_tokens, timeout_seconds, supports_json_mode, reasoning_effort, context_tokens.
CHAT_MODEL_PROFILES: dict[str, ChatModelProfile] = {
    # dev, Azure AI Foundry. Thinking off measured on this model: 6 output tokens instead of 45-139.
    # Context: the deployment's 100,000 tokens a minute (x-ratelimit-limit-tokens, 2026-10-23), below the
    # model's 262,144: one call over it is refused (429), however long the wait.
    "openai/Kimi-K2.6": ChatModelProfile(12_288, 90, True, "none", 100_000),
    # UAT, LiteLLM proxy. kimi answers in ~5 s; 120 s covers its longest answers.
    # Context: the gateway's model info (2026-10-29): max_input_tokens 114,688, plus the answer kept free.
    "litellm_proxy/kimi-k2.5": ChatModelProfile(12_288, 120, True, "none", 114_688 + 12_288),
    # UAT's glm (remediation, service mapper): the gateway's model info (2026-10-29), max_input_tokens
    # 262,144, plus the answer kept free. It answers in 55-99 s: 180 s keeps its longest answers from timing
    # out (a timed-out gate batch fails the job).
    "litellm_proxy/glm-5.3": ChatModelProfile(12_288, 180, True, "none", 262_144 + 12_288),
}


#: Positional: dimensions, batch_size, timeout_seconds, max_text_chars.
EMBEDDING_MODEL_PROFILES: dict[str, EmbeddingModelProfile] = {
    "openai/text-embedding-3-large": EmbeddingModelProfile(3072, 64, 90, 8_000),
    # UAT values (owner, 2026-10-08): as v1 runs them there. The query instruction is the model card's
    # (huggingface.co/Qwen/Qwen3-Embedding-8B, get_detailed_instruct: no space after "Query:").
    "litellm_proxy/qwen3-embedding-8b": EmbeddingModelProfile(
        4096, 32, 120, 4_000, concurrency=4, query_instruction="Instruct: {task}\nQuery:"
    ),
}


RERANK_MODEL_PROFILES: dict[str, RerankModelProfile] = {
    "bge-reranker-v2-m3": RerankModelProfile(timeout_seconds=90),  # dev, local folder
    "litellm_proxy/qwen3-reranker-8b": RerankModelProfile(timeout_seconds=120),
}


def find_model_profile[Profile](profiles: dict[str, Profile], model: str) -> Profile:
    """The profile for a model name from .env; a local model's folder path is found by its folder name."""
    profile = profiles.get(model) or profiles.get(PurePath(model).name)
    if profile is None:
        raise UnknownModelProfile(ErrorMessage.MODEL_PROFILE_MISSING.format(model=model))
    return profile
