"""Each module's own chat model (owner 2026-10-28): threat scenarios (CII_SCENARIO_...), remediation plans
(CII_REMEDIATION_...) and the service mapper (CII_SERVICE_MAPPER_...), the same 11 lines each, read on their
own; the same or a different model, key and gateway per module. URL, key and model are required. A blank
fallback model means none, and its other fallback lines are ignored (app/ai/module_chat.py). Settings reads
these too (one class would be too long)."""

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings


class ChatModelSettings(BaseSettings):
    """Per module: its model on its gateway with its key; thinking false = off (LiteLLM gateway models), true
    = the model's own default; its longest question and answer in tokens and its wait for one answer, blank =
    the model's (app/ai/profiles.py); requests and tokens a minute to it, all pods, retries included, 0 = no
    limit; its AI calls at once, all pods, 0 = only a 429's limit; then the same for its fallback."""

    scenario_chat_base_url: str
    scenario_chat_api_key: SecretStr
    scenario_chat_model: str
    scenario_chat_model_thinking: bool = False
    scenario_chat_max_input_tokens: int | None = Field(default=None, ge=1024)
    scenario_chat_max_output_tokens: int | None = Field(default=None, ge=256)
    scenario_chat_timeout_seconds: int | None = Field(default=None, ge=5, le=1800)
    scenario_chat_requests_per_minute: int = Field(default=0, ge=0)
    scenario_chat_tokens_per_minute: int = Field(default=0, ge=0)
    scenario_max_concurrent_ai_calls: int = Field(default=16, ge=0)
    scenario_chat_fallback_model: str = ""
    scenario_chat_fallback_model_thinking: bool = False
    scenario_chat_fallback_max_input_tokens: int | None = Field(default=None, ge=1024)
    scenario_chat_fallback_max_output_tokens: int | None = Field(default=None, ge=256)
    scenario_chat_fallback_timeout_seconds: int | None = Field(default=None, ge=5, le=1800)
    scenario_chat_fallback_requests_per_minute: int = Field(default=0, ge=0)
    scenario_max_concurrent_fallback_calls: int = Field(default=0, ge=0)

    remediation_chat_base_url: str
    remediation_chat_api_key: SecretStr
    remediation_chat_model: str
    remediation_chat_model_thinking: bool = False
    remediation_chat_max_input_tokens: int | None = Field(default=None, ge=1024)
    remediation_chat_max_output_tokens: int | None = Field(default=None, ge=256)
    remediation_chat_timeout_seconds: int | None = Field(default=None, ge=5, le=1800)
    remediation_chat_requests_per_minute: int = Field(default=0, ge=0)
    remediation_chat_tokens_per_minute: int = Field(default=0, ge=0)
    remediation_max_concurrent_ai_calls: int = Field(default=16, ge=0)
    remediation_chat_fallback_model: str = ""
    remediation_chat_fallback_model_thinking: bool = False
    remediation_chat_fallback_max_input_tokens: int | None = Field(default=None, ge=1024)
    remediation_chat_fallback_max_output_tokens: int | None = Field(default=None, ge=256)
    remediation_chat_fallback_timeout_seconds: int | None = Field(default=None, ge=5, le=1800)
    remediation_chat_fallback_requests_per_minute: int = Field(default=0, ge=0)
    remediation_max_concurrent_fallback_calls: int = Field(default=0, ge=0)

    service_mapper_chat_base_url: str
    service_mapper_chat_api_key: SecretStr
    service_mapper_chat_model: str
    service_mapper_chat_model_thinking: bool = False
    service_mapper_chat_max_input_tokens: int | None = Field(default=None, ge=1024)
    service_mapper_chat_max_output_tokens: int | None = Field(default=None, ge=256)
    service_mapper_chat_timeout_seconds: int | None = Field(default=None, ge=5, le=1800)
    service_mapper_chat_requests_per_minute: int = Field(default=0, ge=0)
    service_mapper_chat_tokens_per_minute: int = Field(default=0, ge=0)
    service_mapper_max_concurrent_ai_calls: int = Field(default=16, ge=0)
    service_mapper_chat_fallback_model: str = ""
    service_mapper_chat_fallback_model_thinking: bool = False
    service_mapper_chat_fallback_max_input_tokens: int | None = Field(default=None, ge=1024)
    service_mapper_chat_fallback_max_output_tokens: int | None = Field(default=None, ge=256)
    service_mapper_chat_fallback_timeout_seconds: int | None = Field(default=None, ge=5, le=1800)
    service_mapper_chat_fallback_requests_per_minute: int = Field(default=0, ge=0)
    service_mapper_max_concurrent_fallback_calls: int = Field(default=0, ge=0)
