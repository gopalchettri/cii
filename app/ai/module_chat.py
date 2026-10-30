"""Each module's chat settings (owner 2026-10-28): its own CII_<MODULE>_ lines alone; with no fallback model
of its own it has no fallback, so no fallback thinking or limits either."""

from typing import Any

from app.core.config import Settings
from app.core.constants import ChatModule
from app.models.ai.module_chat import ModuleChat


def module_chat(settings: Settings, module: ChatModule) -> ModuleChat:
    """`module`'s chat model, key, thinking and limits, from its CII_<MODULE>_ lines."""

    def own(name: str) -> Any:
        return getattr(settings, f"{module}_{name}")

    fallback: str = own("chat_fallback_model")
    return ModuleChat(
        base_url=own("chat_base_url"),
        api_key=own("chat_api_key"),
        model=own("chat_model"),
        model_thinking=own("chat_model_thinking"),
        max_input_tokens=own("chat_max_input_tokens"),
        max_output_tokens=own("chat_max_output_tokens"),
        timeout_seconds=own("chat_timeout_seconds"),
        requests_per_minute=own("chat_requests_per_minute"),
        tokens_per_minute=own("chat_tokens_per_minute"),
        max_concurrent_ai_calls=own("max_concurrent_ai_calls"),
        fallback_model=fallback,
        fallback_model_thinking=bool(fallback) and own("chat_fallback_model_thinking"),
        fallback_max_input_tokens=own("chat_fallback_max_input_tokens"),
        fallback_max_output_tokens=own("chat_fallback_max_output_tokens"),
        fallback_timeout_seconds=own("chat_fallback_timeout_seconds"),
        fallback_requests_per_minute=own("chat_fallback_requests_per_minute") if fallback else 0,
        max_concurrent_fallback_calls=own("max_concurrent_fallback_calls") if fallback else 0,
    )
