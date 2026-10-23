"""AI model profiles: what each model is like. Which model has which profile is the table in
app/ai/profiles.py."""

from dataclasses import dataclass

from app.core.constants import AiLimits


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
        """Longest prompt sent (all messages together), the answer's tokens kept free: a longer one raises
        TruncatedAiAnswer before any call, and the caller sends less. The landscape budget is half of it."""
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


@dataclass(frozen=True)
class RerankModelProfile:
    timeout_seconds: int  # remote models only; a local model runs in-process
