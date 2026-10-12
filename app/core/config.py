"""Environment settings: connections, AI endpoints/models, secrets, and the operational limits the owner tunes
per environment (request size, AI calls at once; 2026-10-09). Business values: core/constants/.

Every field here has a line in .env, .env.uat and .env.example (tests/test_config.py checks the names)."""

from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.constants import ContextProperties, Env, ErrorMessage, Limits, PropertyMessage, Tracing
from app.core.singletons import singleton


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="CII_", env_file=".env", extra="ignore", env_ignore_empty=True, populate_by_name=True
    )

    # Safe by default: a deployment that forgets CII_ENV gets production's checks (the laptop's .env says
    # dev).
    env: Env = Env.PROD
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"  # a typo stops start-up, not logging
    # Laptop only: also write the JSON log lines to <log_dir>/api.log and worker-<name>.log, where the
    # local Loki reads them (pods log to stdout only and leave this empty).
    log_dir: str = ""
    # Comma-separated browser origins; empty = none (the API is called server to server).
    cors_origins: str = ""

    db_dsn: str
    mongo_url: str
    mongo_db: str = "cii_tsg"
    redis_url: str
    redis_celery_broker_url: str

    chat_base_url: str
    chat_api_key: SecretStr
    chat_model: str
    chat_fallback_model: str = ""

    embedding_base_url: str
    embedding_api_key: SecretStr
    embedding_model: str  # its vector size, batch cap and timeout: app/ai/profiles.py

    rerank_base_url: str = ""  # empty = local model at rerank_model (dev)
    rerank_api_key: SecretStr = SecretStr("")
    rerank_model: str

    # A gateway that reads the AI key from its own header (UAT's LiteLLM: x-litellm-api-key) gets it there
    # too, on every chat, embedding and rerank call; the standard Authorization header is still sent.
    ai_key_header: str = ""

    admin_api_key: SecretStr = SecretStr("")

    # Each worker pod serves its /metrics (AI calls, jobs) on this port for Prometheus.
    worker_metrics_port: int = 9100

    # Largest request body, in MB, for every request. FastAPI reads a body before it checks the caller's
    # key, so this bounds what anyone can make a pod read. One limit for all (owner, 2026-10-09): no endpoint
    # takes file uploads; one that does gets its own limit by its address, never by the Content-Type.
    max_request_mb: int = Field(default=2, gt=0)
    # Most AI calls at once across all pods; 0 = no limit. v1 runs 16 (TSG_MAX_CONCURRENT_LLM_CALLS).
    # Enforced by the AI slot limiter (app/ai/slots.py): a call waits for a free slot.
    max_concurrent_ai_calls: int = Field(default=16, ge=0)

    # Owner, 2026-10-10: when true, every workflow step logs its redacted inputs, results, output, time
    # taken and errors (app/core/tracing.py); when false, only the operational, security and audit logs. The
    # env name is the owner's own, without the CII_ prefix. Step lines are INFO: CII_LOG_LEVEL must be INFO or
    # DEBUG.
    debug_step_output: bool = Field(default=False, validation_alias="DEBUG_STEP_OUTPUT")
    # Owner's names, without the CII_ prefix: DEBUG_STEP_DETAIL adds the inner sub-step records (BM25,
    # similarity, merges, ranking…) inside each traced step, only when DEBUG_STEP_OUTPUT is true; a ranked
    # record keeps its DEBUG_STEP_TOP best entries (1-40).
    debug_step_detail: bool = Field(default=False, validation_alias="DEBUG_STEP_DETAIL")
    debug_step_top: int = Field(
        default=Tracing.DETAIL_TOP, ge=1, le=Tracing.PREVIEW_KEYS, validation_alias="DEBUG_STEP_TOP"
    )

    # How many scenarios a run writes (spec v4.0 §1; the owner's exact name, without the CII_ prefix):
    # 0 = every valid path found; N = the N most relevant, the rest kept in the plan as target_reached.
    # Applied only after every path is found and ranked; never padded. A negative, decimal or text value
    # stops start-up.
    total_scenario_count: int = Field(default=0, ge=0, validation_alias="TOTAL_SCENARIO_COUNT")
    # Scenarios are written set by set, only when asked (owner 2026-10-11, as v1): the run writes its first
    # INITIAL_SET_SIZE paths so a reviewer can start reading, then each "next set" call writes the next
    # NEXT_SET_SIZE. A review batch size, never a limit: the total still comes from TOTAL_SCENARIO_COUNT.
    initial_set_size: int = Field(default=6, ge=1, validation_alias="INITIAL_SET_SIZE")
    next_set_size: int = Field(default=6, ge=1, validation_alias="NEXT_SET_SIZE")

    # How similar a match must be, 0-100 on the reranker's relevance scale, one scale for all three (owner
    # 2026-10-11): a control kept for a scenario (none reaches it: the single nearest, with a warning); an
    # AI-proposed threat that IS a library threat or takes a library type; an attacker offered when a threat's
    # type links none (0 = no filter; none reaches it: the closest still acts, with a warning). Linked
    # attackers are never filtered: a curator chose them.
    control_similarity_threshold: float = Field(
        default=60.0, ge=0, le=100, validation_alias="CONTROL_SIMILARITY_THRESHOLD"
    )
    threat_similarity_threshold: float = Field(
        default=75.0, ge=0, le=100, validation_alias="THREAT_SIMILARITY_THRESHOLD"
    )
    actor_similarity_threshold: float = Field(
        default=0.0, ge=0, le=100, validation_alias="ACTOR_SIMILARITY_THRESHOLD"
    )

    # Which asset and supporting-system facts a run requires (a start without one is refused 422; owner
    # 2026-10-11): comma-separated column names of dbo.tsg_GetAssetContext; empty = none. Which facts a run
    # USES is the procedure's choice: every column it returns.
    asset_properties_required: str = Field(default="", validation_alias="ASSET_PROPERTIES_REQUIRED")
    system_properties_required: str = Field(default="", validation_alias="SYSTEM_PROPERTIES_REQUIRED")

    @model_validator(mode="after")
    def refuse_unsafe_settings_outside_dev(self) -> "Settings":
        """UAT and production refuse settings that are only acceptable on a laptop: start-up stops with the
        reason instead of running open."""
        if self.env is Env.DEV:
            return self
        if "*" in self.cors_origin_list:
            raise ValueError(ErrorMessage.CORS_WILDCARD_OUTSIDE_DEV)
        admin_key = self.admin_api_key.get_secret_value()
        if admin_key and len(admin_key) < Limits.MIN_ADMIN_KEY_CHARS:
            raise ValueError(ErrorMessage.ADMIN_KEY_TOO_SHORT.format(minimum=Limits.MIN_ADMIN_KEY_CHARS))
        return self

    @model_validator(mode="after")
    def refuse_always_used_properties(self) -> "Settings":
        """Every environment: id, name, category_code and alias are always used, never a fact a run can lack;
        requiring one stops start-up. A name the procedure does not return is refused at the first run, which
        is when the procedure is read (property_selection.check_required)."""
        for setting, text in (
            ("ASSET_PROPERTIES_REQUIRED", self.asset_properties_required),
            ("SYSTEM_PROPERTIES_REQUIRED", self.system_properties_required),
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
    """A comma-separated list, as written (order kept for messages), blanks dropped."""
    return [name.strip() for name in text.split(",") if name.strip()]


@singleton
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]  # values come from the environment / .env
