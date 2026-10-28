"""One module's chat settings as it uses them (app/ai/module_chat.py builds them from the settings)."""

from dataclasses import dataclass

from pydantic import SecretStr


@dataclass(frozen=True)
class ModuleChat:
    base_url: str
    api_key: SecretStr
    model: str
    model_thinking: bool
    requests_per_minute: int
    tokens_per_minute: int
    max_concurrent_ai_calls: int
    fallback_model: str  # "" = no fallback
    fallback_model_thinking: bool
    fallback_requests_per_minute: int
    max_concurrent_fallback_calls: int
