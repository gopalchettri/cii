"""Each module's chat settings (owner 2026-10-28): a line it sets wins, a blank one is the shared CII_CHAT_
one; its fallback model is its own alone (blank = none, so no fallback thinking or limits either)."""

from typing import Final

from pydantic import SecretStr

from app.core.config import Settings
from app.core.constants import ChatModule
from app.models.ai.module_chat import ModuleChat

_BLANK: Final = (None, "", SecretStr(""))


def module_chat(settings: Settings, module: ChatModule) -> ModuleChat:
    """`module`'s chat model, key, thinking and limits, from its CII_<MODULE>_ lines and the shared ones."""

    def own[Value](name: str, shared: Value) -> Value:
        value = getattr(settings, f"{module}_{name}")
        return shared if value in _BLANK else value

    fallback: str = getattr(settings, f"{module}_chat_fallback_model")

    def own_fallback[Value](name: str, off: Value) -> Value:
        return getattr(settings, f"{module}_{name}") if fallback else off

    return ModuleChat(
        base_url=own("chat_base_url", settings.chat_base_url),
        api_key=own("chat_api_key", settings.chat_api_key),
        model=own("chat_model", settings.chat_model),
        model_thinking=own("chat_model_thinking", settings.chat_model_thinking),
        requests_per_minute=own("chat_requests_per_minute", settings.chat_requests_per_minute),
        tokens_per_minute=own("chat_tokens_per_minute", settings.chat_tokens_per_minute),
        max_concurrent_ai_calls=own("max_concurrent_ai_calls", settings.max_concurrent_ai_calls),
        fallback_model=fallback,
        fallback_model_thinking=own_fallback("chat_fallback_model_thinking", False),
        fallback_requests_per_minute=own_fallback("chat_fallback_requests_per_minute", 0),
        max_concurrent_fallback_calls=own_fallback("max_concurrent_fallback_calls", 0),
    )
