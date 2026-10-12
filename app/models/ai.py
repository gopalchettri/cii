"""AI model profiles: what each model is like. Which model has which profile is the table in
app/ai/profiles.py."""

from dataclasses import dataclass


@dataclass(frozen=True)
class ChatModelProfile:
    max_output_tokens: int  # counts hidden thinking as well as the visible answer
    timeout_seconds: int  # one reply; proxy models queue under load
    supports_json_mode: bool  # sends response_format=json_object
    reasoning_effort: str | None  # "none" = thinking off (owner decision); None = never sent
    # Longest prompt sent (all messages together): a longer one raises TruncatedAiAnswer before any call, and
    # the caller sends less (e.g. halves the batch). The landscape budget is half of it (§8).
    max_input_chars: int = 60_000


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
