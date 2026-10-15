"""Environment settings: connections, AI endpoints/models, secrets, and the operational limits the owner tunes
per environment (request size, AI calls at once; 2026-10-09). Business values: core/constants/.

Every field here has a line in .env, .env.uat and .env.example (tests/test_config.py checks the names)."""

import re
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.constants import (
    COUNTRY_REGIONS,
    PLACE_WORDS,
    ContextProperties,
    Env,
    ErrorMessage,
    EvidenceSettingMessage,
    Limits,
    PropertyMessage,
    Tracing,
)
from app.core.singletons import singleton

_WORD_RANGE = re.compile(r"\s*(\d+)\s*-\s*(\d+)\s*")


class ScenarioOutputSettings(BaseSettings):
    """What a scenario gets: its controls (owner 2026-10-13, G225) and how long its texts are (G226). Settings
    reads these too (one class would pass the size limit)."""

    # A scenario's controls, in five steps: the CONTROL_CANDIDATES closest library controls that fit the asset
    # type are found; the reranker scores each 0-100; every one at or above CONTROL_SIMILARITY_THRESHOLD is
    # kept as "strong" (the owner's 0.50 is 50); never more than MAX_CONTROLS; none reaching it: the nearest
    # are kept as "fallback" up to MIN_CONTROLS. Never zero (owner 2026-10-13, G227).
    control_similarity_threshold: float = Field(
        default=50.0, ge=0, le=100, validation_alias="CONTROL_SIMILARITY_THRESHOLD"
    )
    # No value in code (owner 2026-10-15, G249): read only from the env file; missing, the app does not start.
    control_candidates: int = Field(ge=1, validation_alias="CONTROL_CANDIDATES")
    min_controls: int = Field(default=1, ge=1, validation_alias="MIN_CONTROLS")
    max_controls: int = Field(default=10, ge=1, validation_alias="MAX_CONTROLS")
    # Words in a scenario statement and in a risk statement, "min-max", for both writers.
    threat_scenario_word_limit: str = Field(default="300-400", validation_alias="THREAT_SCENARIO_WORD_LIMIT")
    risk_statement_word_limit: str = Field(default="150-200", validation_alias="RISK_STATEMENT_WORD_LIMIT")
    # External intelligence on (G229): a threat whose search found no usable evidence is searched again with
    # other words this many times (0-2; no AI call); still none, its scenario is not written.
    evidence_search_retries: int = Field(default=1, ge=0, le=2, validation_alias="EVIDENCE_SEARCH_RETRIES")
    # G229: a scenario is a near copy of one already finished in its run when at least this share (0-100) of
    # its three-word phrases are shared, AND it is about the same thing: the same threat, or the same target,
    # systems and kind with at least NEAR_COPY_PART_SIMILARITY of its mechanism and consequence words shared.
    # Measured 2026-10-13: distinct scenarios of runs 03276384 and 82f22cc3 shared at most 3.5; a copy with
    # two sentences reworded about 72.
    near_copy_text_similarity: float = Field(
        default=30.0, gt=0, le=100, validation_alias="NEAR_COPY_TEXT_SIMILARITY"
    )
    near_copy_part_similarity: float = Field(
        default=50.0, gt=0, le=100, validation_alias="NEAR_COPY_PART_SIMILARITY"
    )
    # G232 (owner 2026-10-14): the country the assets are in ("UAE" or "United Arab Emirates"): planning and
    # the writers read it as a fact, and the real groups and the evidence are ranked and labelled by it.
    threat_context_country: str = Field(
        default="United Arab Emirates", validation_alias="THREAT_CONTEXT_COUNTRY"
    )

    @model_validator(mode="after")
    def refuse_output_limits_that_cannot_work(self) -> "ScenarioOutputSettings":
        if not self.control_candidates >= self.max_controls >= self.min_controls:
            raise ValueError(
                ErrorMessage.CONTROL_COUNT_INVALID.format(
                    candidates=self.control_candidates, most=self.max_controls, least=self.min_controls
                )
            )
        if 0 < (value := self.control_similarity_threshold) < 1:
            message = ErrorMessage.CONTROL_THRESHOLD_AS_FRACTION
            raise ValueError(
                message.format(setting="CONTROL_SIMILARITY_THRESHOLD", value=value, percent=value * 100)
            )
        _ = self.scenario_words, self.risk_words  # a range that cannot be read stops start-up
        if self.context_country not in COUNTRY_REGIONS:
            message = ErrorMessage.COUNTRY_UNKNOWN
            raise ValueError(
                message.format(value=self.threat_context_country, known=", ".join(COUNTRY_REGIONS))
            )
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


def _word_range(setting: str, text: str) -> tuple[int, int]:
    found = _WORD_RANGE.fullmatch(text)
    least, most = (int(found.group(1)), int(found.group(2))) if found else (0, 0)
    if not 1 <= least <= most:
        raise ValueError(ErrorMessage.WORD_LIMIT_INVALID.format(setting=setting, value=text))
    return least, most


class Settings(ScenarioOutputSettings):
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
    # v1's TSG_LITELLM_BYPASS_PROXY: true = litellm_proxy/ models skip HTTP(S)_PROXY (the UAT Windows server's
    # proxy cannot reach the gateway); false for OpenShift, where only the proxy reaches it (the gate checks).
    ai_bypass_proxy: bool = True

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
    # 2026-10-11): a control kept for a scenario (CONTROL_SIMILARITY_THRESHOLD, ScenarioOutputSettings); an
    # AI-proposed threat that IS a library threat or takes a library type; an attacker offered when a threat's
    # type links none (0 = no filter; none reaches it: the closest still acts, with a warning). Linked
    # attackers are never filtered: a curator chose them.
    threat_similarity_threshold: float = Field(
        default=75.0, ge=0, le=100, validation_alias="THREAT_SIMILARITY_THRESHOLD"
    )
    actor_similarity_threshold: float = Field(
        default=0.0, ge=0, le=100, validation_alias="ACTOR_SIMILARITY_THRESHOLD"
    )

    # External intelligence (CISA KEV, EPSS, MITRE ATT&CK, CISA ICS, NVD). ENABLED is the MASTER switch: false
    # means nothing is read, searched or shown, whatever an admin sets at run time (the run-time switch can
    # only turn it off, never on). OFF unless an environment says true: a deployment that forgets the line
    # stays the original TSG. Owner's names, without the CII_ prefix.
    external_intelligence_enabled: bool = Field(
        default=False, validation_alias="EXTERNAL_INTELLIGENCE_ENABLED"
    )
    # The lowest reranker score (0-100) at which an intelligence record counts as evidence for a threat. A
    # ranking score, not a probability, and provisional: calibrate per environment and per reranker model
    # (declared like THREAT_SIMILARITY_THRESHOLD, but on its own scale).
    evidence_similarity_threshold: float = Field(
        default=1.0, ge=0, le=100, validation_alias="EVIDENCE_SIMILARITY_THRESHOLD"
    )
    # Optional NVD key (a secret): raises NVD's rate limit from 5 to 50 requests per 30 s. Empty = unkeyed.
    nvd_api_key: SecretStr = SecretStr("")

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
        refuse_unset_evidence_threshold(self)
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


def refuse_unset_evidence_threshold(settings: Settings) -> None:
    """Outside dev, external intelligence on needs EVIDENCE_SIMILARITY_THRESHOLD set explicitly: each
    reranker model scores on its own scale, so no default is safe (a value left to the default is not in
    model_fields_set)."""
    if (
        settings.external_intelligence_enabled
        and "evidence_similarity_threshold" not in settings.model_fields_set
    ):
        raise ValueError(EvidenceSettingMessage.THRESHOLD_NOT_SET)


def _names(text: str) -> list[str]:
    """A comma-separated list, as written (order kept for messages), blanks dropped."""
    return [name.strip() for name in text.split(",") if name.strip()]


@singleton
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]  # values come from the environment / .env
