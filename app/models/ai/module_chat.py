"""One module's chat settings as it uses them (app/ai/module_chat.py builds them from the settings)."""

from dataclasses import dataclass

from pydantic import SecretStr


@dataclass(frozen=True)
class ModuleChat:
    base_url: str
    api_key: SecretStr
    model: str
    model_thinking: bool
    max_input_tokens: int | None  # None: the model's own (app/ai/profiles.py)
    max_output_tokens: int | None
    timeout_seconds: int | None
    requests_per_minute: int
    tokens_per_minute: int
    max_concurrent_ai_calls: int
