"""Environment settings: connections, AI models, secrets and limits; every field has a line in each .env file."""

import re
from dataclasses import dataclass, fields
from typing import Annotated, Literal

from pydantic import AfterValidator, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.ai_tuning_settings import AiTuningSettings
from app.core.constants import (
    COUNTRY_REGIONS,
    PLACE_WORDS,
    ChatModule,
    ContextProperties,
    Env,
    ErrorMessage,
    EvidenceSettingMessage,
    Limits,
    PropertyMessage,
)
from app.core.singletons import singleton

_WORD_RANGE = re.compile(r"\s*(\d+)\s*-\s*(\d+)\s*")


def _refuse_a_proxy_url_without_scheme(value: SecretStr) -> SecretStr:
    proxy = value.get_secret_value()
    if proxy and not proxy.startswith(("http://", "https://")):
        raise ValueError(ErrorMessage.PROXY_URL_WITHOUT_SCHEME)  # else every outside call fails later, unexplained
    return value


#: CII_PROXY_URL: an http(s):// address every outside call goes through (AI calls too unless
#: CII_AI_BYPASS_PROXY); blank = HTTP(S)_PROXY, else Windows' setting. Never *_PROXY: Python reads those.
ProxyUrl = Annotated[SecretStr, AfterValidator(_refuse_a_proxy_url_without_scheme)]


@dataclass(frozen=True)
class ModuleChat:
    """One module's chat settings as it uses them (Settings.chat_of)."""

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


class ChatModelSettings(BaseSettings):
    """Each module's own chat model, key and gateway (CII_<MODULE>_CHAT_...); thinking false = off; token
    limits and timeout blank = the model's profile; rates 0 = no limit; calls at once 0 = 429s only."""

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

    def chat_of(self, module: ChatModule) -> ModuleChat:
        """`module`'s chat model, key, thinking and limits, from its CII_<MODULE>_ lines."""
        own = {f.name: getattr(self, f"{module}_chat_{f.name}") for f in fields(ModuleChat)[:-1]}
        return ModuleChat(**own, max_concurrent_ai_calls=getattr(self, f"{module}_max_concurrent_ai_calls"))


class AiOutputSettings(BaseSettings):
    """What the AI produces: a scenario's controls, text lengths and the service mapper's counts."""

    # Controls scoring at least CONTROL_SIMILARITY_THRESHOLD (0-100) are "strong", at most MAX_CONTROLS; fewer
    # than MIN_CONTROLS: the nearest top them up; none: the NEAREST_CONTROLS nearest are kept as "fallback".
    control_similarity_threshold: float = Field(
        default=50.0, ge=0, le=100, validation_alias="CONTROL_SIMILARITY_THRESHOLD"
    )
    # No default: missing from the env file, the app does not start.
    control_candidates: int = Field(ge=1, validation_alias="CONTROL_CANDIDATES")
    min_controls: int = Field(default=3, ge=1, validation_alias="MIN_CONTROLS")
    max_controls: int = Field(default=5, ge=1, validation_alias="MAX_CONTROLS")
    nearest_controls: int = Field(default=3, ge=1, validation_alias="NEAREST_CONTROLS")
    # Words the writer is asked for, "min-max": the max is a hard limit, the min a target; code never cuts.
    threat_scenario_word_limit: str = Field(default="150-200", validation_alias="THREAT_SCENARIO_WORD_LIMIT")
    risk_statement_word_limit: str = Field(default="100-150", validation_alias="RISK_STATEMENT_WORD_LIMIT")
    # The evidence passage ending a story, on top of the scenario statement's own limit.
    evidence_statement_word_limit: str = Field(default="30-80", validation_alias="EVIDENCE_STATEMENT_WORD_LIMIT")
    # The country the assets are in ("UAE" or "United Arab Emirates"): a fact for the writer; it ranks nothing.
    threat_context_country: str = Field(default="United Arab Emirates", validation_alias="THREAT_CONTEXT_COUNTRY")
    # Services the AI is asked for per direction (fewer is fine, none in both lists); 0 turns a direction off.
    service_mapper_upstream_total_count: int = Field(
        default=10, ge=0, le=100, validation_alias="SERVICE_MAPPER_UPSTREAM_TOTAL_COUNT"
    )
    service_mapper_downstream_total_count: int = Field(
        default=10, ge=0, le=100, validation_alias="SERVICE_MAPPER_DOWNSTREAM_TOTAL_COUNT"
    )
    # Runs per mapping, the first included (Generate, then Generate again or Regenerate); 0 = no limit.
    service_mapper_max_generations: int = Field(default=5, ge=0, validation_alias="SERVICE_MAPPER_MAX_GENERATIONS")

    @model_validator(mode="after")
    def refuse_output_limits_that_cannot_work(self) -> "AiOutputSettings":
        most = self.max_controls
        if not (self.control_candidates >= most >= self.min_controls and most >= self.nearest_controls):
            raise ValueError(
                ErrorMessage.CONTROL_COUNT_INVALID.format(
                    candidates=self.control_candidates,
                    most=most,
                    least=self.min_controls,
                    nearest=self.nearest_controls,
                )
            )
        if 0 < (value := self.control_similarity_threshold) < 1:
            message = ErrorMessage.CONTROL_THRESHOLD_AS_FRACTION
            raise ValueError(message.format(setting="CONTROL_SIMILARITY_THRESHOLD", value=value, percent=value * 100))
        _ = self.scenario_words, self.risk_words, self.evidence_words  # an unreadable range stops start-up
        if self.context_country not in COUNTRY_REGIONS:
            message = ErrorMessage.COUNTRY_UNKNOWN
            raise ValueError(message.format(value=self.threat_context_country, known=", ".join(COUNTRY_REGIONS)))
        return self

    @property
    def context_country(self) -> str:
        """THREAT_CONTEXT_COUNTRY by its own name ("UAE" is the United Arab Emirates)."""
        name = self.threat_context_country.strip()
        return PLACE_WORDS.get(name.casefold(), name)

    @property
    def scenario_words(self) -> tuple[int, int]:
        return _word_range("THREAT_SCENARIO_WORD_LIMIT", self.threat_scenario_word_limit)

    @property
    def risk_words(self) -> tuple[int, int]:
        return _word_range("RISK_STATEMENT_WORD_LIMIT", self.risk_statement_word_limit)

    @property
    def evidence_words(self) -> tuple[int, int]:
        return _word_range("EVIDENCE_STATEMENT_WORD_LIMIT", self.evidence_statement_word_limit)


def _word_range(setting: str, text: str) -> tuple[int, int]:
    found = _WORD_RANGE.fullmatch(text)
    least, most = (int(found.group(1)), int(found.group(2))) if found else (0, 0)
    if not 1 <= least <= most:
        raise ValueError(ErrorMessage.WORD_LIMIT_INVALID.format(setting=setting, value=text))
    return least, most


class Settings(ChatModelSettings, AiTuningSettings, AiOutputSettings):
    model_config = SettingsConfigDict(
        env_prefix="CII_", env_file=".env", extra="ignore", env_ignore_empty=True, populate_by_name=True
    )

    # A deployment that forgets CII_ENV gets production's checks.
    env: Env = Env.PROD
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"  # a typo stops start-up, not logging
    # JSON log files for the laptop's local Loki; pods: empty.
    log_dir: str = ""
    # Comma-separated browser origins; empty = none.
    cors_origins: str = ""

    db_dsn: str
    mongo_url: str
    mongo_db: str = "cii_tsg"
    redis_url: str
    redis_celery_broker_url: str
    redis_ca_file: str = ""  # the CA that signed a rediss:// server's certificate; empty = the system's CAs

    embedding_base_url: str
    embedding_api_key: SecretStr
    embedding_model: str  # its vector size, batch cap and timeout: app/ai/profiles.py

    rerank_base_url: str = ""  # empty = local model at rerank_model (dev)
    rerank_api_key: SecretStr = SecretStr("")
    rerank_model: str

    # A gateway that reads the AI key from its own header (UAT's LiteLLM: x-litellm-api-key) gets it there
    # too, on every chat, embedding and rerank call; the standard Authorization header is still sent.
    ai_key_header: str = ""
    # CII_AI_BYPASS_PROXY (v1's LITELLM_BYPASS_PROXY): true/blank = litellm_proxy/ models skip the proxy
    ai_bypass_proxy: bool = True
    proxy_url: ProxyUrl = SecretStr("")  # CII_PROXY_URL: see ProxyUrl

    admin_api_key: SecretStr = SecretStr("")

    worker_metrics_port: int = 9100

    # Largest request body, in MB: a body is read before the key is checked, so this bounds what anyone sends.
    max_request_mb: int = Field(default=2, gt=0)
    # Most search calls (embedding, reranker) at once, all pods; a call waits for a free slot (AiSlots).
    # 0 = only a 429's limit; v1 16. Each module's chat calls have their own (ChatModelSettings).
    max_concurrent_ai_calls: int = Field(default=16, ge=0)
    # Each search model's own AI requests a minute, all pods, retries included (AiRequestRate); 0 = no limit.
    embedding_requests_per_minute: int = Field(default=0, ge=0)
    rerank_requests_per_minute: int = Field(default=0, ge=0)

    # Scenarios a run writes: 0 = every valid path; N = the N most relevant, the rest kept as target_reached.
    total_scenario_count: int = Field(default=0, ge=0, validation_alias="TOTAL_SCENARIO_COUNT")
    # Scenarios are written set by set: the first INITIAL_SET_SIZE, then NEXT_SET_SIZE per "next set" call.
    initial_set_size: int = Field(default=6, ge=1, validation_alias="INITIAL_SET_SIZE")
    next_set_size: int = Field(default=6, ge=1, validation_alias="NEXT_SET_SIZE")
    # Versions kept per plan, all in one MongoDB record (100-400 KB each, 16 MB cap): 40 at most.
    regenerations_max_version_count: int = Field(
        default=10, ge=1, le=40, validation_alias="REGENERATIONS_MAX_VERSION_COUNT"
    )

    # Reranker score (0-100) at which an AI-proposed threat IS a library threat or takes a library type.
    threat_similarity_threshold: float = Field(
        default=75.0, ge=0, le=100, validation_alias="THREAT_SIMILARITY_THRESHOLD"
    )

    # External intelligence master switch, off by default: false means nothing is read, searched or shown.
    external_intelligence_enabled: bool = Field(default=False, validation_alias="EXTERNAL_INTELLIGENCE_ENABLED")
    # Lowest reranker score (0-100) at which an intelligence record is evidence; calibrate per reranker model.
    evidence_similarity_threshold: float = Field(
        default=1.0, ge=0, le=100, validation_alias="EVIDENCE_SIMILARITY_THRESHOLD"
    )
    # Intelligence records the reranker scores per threat: more finds the right one, each rerank is slower.
    evidence_candidates: int = Field(default=30, ge=1, le=100, validation_alias="EVIDENCE_CANDIDATES")
    # Intelligence records kept per threat after the reranker: the writer sees them all and cites one.
    evidence_kept_per_threat: int = Field(default=3, ge=1, le=10, validation_alias="EVIDENCE_KEPT_PER_THREAT")

    # Comma-separated dbo.tsg_GetAssetContext columns a run requires (a start without one is refused 422).
    asset_properties_required: str = Field(default="", validation_alias=ContextProperties.ASSET_REQUIRED_SETTING)
    system_properties_required: str = Field(default="", validation_alias=ContextProperties.SYSTEM_REQUIRED_SETTING)

    @model_validator(mode="after")
    def refuse_unsafe_settings_outside_dev(self) -> "Settings":
        """UAT and production refuse laptop-only settings: start-up stops with the reason."""
        if self.env is Env.DEV:
            return self
        if self.env is Env.PROD and "*" in self.cors_origin_list:
            raise ValueError(ErrorMessage.CORS_WILDCARD_IN_PROD)
        admin_key = self.admin_api_key.get_secret_value()
        if admin_key and len(admin_key) < Limits.MIN_ADMIN_KEY_CHARS:
            raise ValueError(ErrorMessage.ADMIN_KEY_TOO_SHORT.format(minimum=Limits.MIN_ADMIN_KEY_CHARS))
        if self.external_intelligence_enabled and "evidence_similarity_threshold" not in self.model_fields_set:
            raise ValueError(EvidenceSettingMessage.THRESHOLD_NOT_SET)
        return self

    @model_validator(mode="after")
    def refuse_always_used_properties(self) -> "Settings":
        """id, name, category_code and alias are always used: requiring one stops start-up."""
        for setting, text in (
            (ContextProperties.ASSET_REQUIRED_SETTING, self.asset_properties_required),
            (ContextProperties.SYSTEM_REQUIRED_SETTING, self.system_properties_required),
        ):
            if always := [name for name in _names(text) if name in ContextProperties.ALWAYS_USED]:
                raise ValueError(PropertyMessage.ALWAYS_USED.format(setting=setting, names=always))
        return self

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def required_asset_properties(self) -> frozenset[str]:
        return frozenset(_names(self.asset_properties_required))

    @property
    def required_system_properties(self) -> frozenset[str]:
        return frozenset(_names(self.system_properties_required))


def _names(text: str) -> list[str]:
    return [name.strip() for name in text.split(",") if name.strip()]


@singleton
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]  # values come from the environment / .env
