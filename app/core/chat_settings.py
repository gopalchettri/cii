"""The chat models (owner 2026-10-28): the shared CII_CHAT_ lines, and each module's own, named as the shared
one with the module after CII_ (CII_REMEDIATION_CHAT_MODEL for CII_CHAT_MODEL). A blank module line takes the
shared value. Each module has its own fallback model alone: blank = none, and so no fallback thinking or
limits (app/ai/module_chat.py). Settings reads these too (one class would be too long)."""

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings


class ChatModelSettings(BaseSettings):
    """The shared chat lines, then threat scenarios' (finding and writing), remediation plans' and the service
    mapper's: each module its own model, key, thinking and limits, with its own AI slots and request turns."""

    chat_base_url: str
    chat_api_key: SecretStr
    chat_model: str
    # CII_CHAT_MODEL_THINKING: false (default) = that model's thinking off (LiteLLM gateway models:
    # app/ai/chat.py); true = the model's own default.
    chat_model_thinking: bool = False
    # Requests a minute to a module's main model, all pods, retries included (AiRequestRate); 0 = no limit.
    chat_requests_per_minute: int = Field(default=0, ge=0)
    chat_tokens_per_minute: int = Field(default=0, ge=0)  # the same in tokens; big requests wait more
    # Most AI calls at once, all pods: the search calls' (embedding, reranker) and each module's chat calls',
    # each its own; a call waits for a free slot (AiSlots). 0 = only a 429's limit; v1 16.
    max_concurrent_ai_calls: int = Field(default=16, ge=0)

    scenario_chat_base_url: str = ""
    scenario_chat_api_key: SecretStr = SecretStr("")
    scenario_chat_model: str = ""
    scenario_chat_model_thinking: bool | None = None
    scenario_chat_requests_per_minute: int | None = Field(default=None, ge=0)
    scenario_chat_tokens_per_minute: int | None = Field(default=None, ge=0)
    scenario_max_concurrent_ai_calls: int | None = Field(default=None, ge=0)
    scenario_chat_fallback_model: str = ""
    scenario_chat_fallback_model_thinking: bool = False
    scenario_chat_fallback_requests_per_minute: int = Field(default=0, ge=0)
    scenario_max_concurrent_fallback_calls: int = Field(default=0, ge=0)

    remediation_chat_base_url: str = ""
    remediation_chat_api_key: SecretStr = SecretStr("")
    remediation_chat_model: str = ""
    remediation_chat_model_thinking: bool | None = None
    remediation_chat_requests_per_minute: int | None = Field(default=None, ge=0)
    remediation_chat_tokens_per_minute: int | None = Field(default=None, ge=0)
    remediation_max_concurrent_ai_calls: int | None = Field(default=None, ge=0)
    remediation_chat_fallback_model: str = ""
    remediation_chat_fallback_model_thinking: bool = False
    remediation_chat_fallback_requests_per_minute: int = Field(default=0, ge=0)
    remediation_max_concurrent_fallback_calls: int = Field(default=0, ge=0)

    service_mapper_chat_base_url: str = ""
    service_mapper_chat_api_key: SecretStr = SecretStr("")
    service_mapper_chat_model: str = ""
    service_mapper_chat_model_thinking: bool | None = None
    service_mapper_chat_requests_per_minute: int | None = Field(default=None, ge=0)
    service_mapper_chat_tokens_per_minute: int | None = Field(default=None, ge=0)
    service_mapper_max_concurrent_ai_calls: int | None = Field(default=None, ge=0)
    service_mapper_chat_fallback_model: str = ""
    service_mapper_chat_fallback_model_thinking: bool = False
    service_mapper_chat_fallback_requests_per_minute: int = Field(default=0, ge=0)
    service_mapper_max_concurrent_fallback_calls: int = Field(default=0, ge=0)
