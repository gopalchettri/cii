"""AI tuning the owner changes in the ConfigMap, with only a rollout restart (owner 2026-10-29): the answer
room each task asks for, how much TSG asks at once, and what it does when the AI service says "too busy"
(429). Read once at start-up into the constants that use them (TUNING); Settings reads these too, so the env
files are checked against them (one class would be too long)."""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class AiTuningSettings(BaseSettings):
    """Defaults: the largest answer measured per task, times about 2 (owner 2026-10-29, 9,000+ calls); the
    rest are the values UAT ran with before 24 Oct."""

    model_config = SettingsConfigDict(
        env_prefix="CII_", env_file=".env", extra="ignore", env_ignore_empty=True
    )

    # Answer room, in tokens: the AI service counts it against its budget while the question runs. An answer
    # cut off at its room is asked once more with the model's full room (app/ai/chat.py).
    answer_tokens_relevance_gate: int = Field(default=4096, ge=256, le=32768)  # largest 3642: ~180 a threat
    answer_tokens_gap_fill: int = Field(default=1024, ge=256, le=32768)  # 97
    answer_tokens_threat_actions: int = Field(default=1024, ge=256, le=32768)  # 29
    answer_tokens_write_scenario: int = Field(default=3072, ge=256, le=32768)  # 1681
    answer_tokens_repair_scenario: int = Field(default=3072, ge=256, le=32768)  # 577
    answer_tokens_plan_check: int = Field(default=2048, ge=256, le=32768)  # 1028
    answer_tokens_remediation_plan: int = Field(default=8192, ge=256, le=32768)  # ~140 a control: ~50 fit
    answer_tokens_service_mapper: int = Field(default=4096, ge=256, le=32768)  # 1997
    # How much TSG asks at once.
    threat_questions_at_once: int = Field(default=8, ge=1, le=64)  # per threat-finding run
    threats_per_question: int = Field(default=10, ge=1, le=50)  # threats one relevance question judges
    scenarios_written_at_once: int = Field(default=6, ge=1, le=64)  # per scenario-writing job
    reranks_at_once: int = Field(default=6, ge=1, le=64)  # remote reranker calls per worker
    # "Too busy" (HTTP 429).
    ai_busy_max_wait_seconds: int = Field(default=60, ge=1, le=600)  # longest one wait, TSG's steps too
    ai_busy_total_wait_seconds: int = Field(default=60, ge=1, le=600)  # all waits (4 at most), then backup
    ai_model_cool_down_seconds: int = Field(default=120, ge=0, le=3600)  # a refused model is asked last
    ai_busy_limit_floor: int = Field(default=4, ge=1, le=64)  # the fewest questions at once after a 429
    ai_busy_limit_seconds: int = Field(default=180, ge=1, le=3600)  # that slow-down lasts this long


#: The tuning this process started with: the constants (app/core/constants) take their values from it.
TUNING = AiTuningSettings()
