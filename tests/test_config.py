"""Settings refuse what is only acceptable on a laptop, everywhere but dev; the laptop log file."""

import json
import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest
import structlog
from pydantic import ValidationError

from app.ai.module_chat import module_chat
from app.core.ai_tuning_settings import AiTuningSettings
from app.core.chat_settings import ChatModelSettings
from app.core.config import Settings, get_settings
from app.core.constants import ChatModule, Env, LogEvent
from app.core.logging import configure_logging

REPO = Path(__file__).resolve().parents[1]
#: Keys an env file may hold besides the Settings fields: the laptop monitoring script reads this one.
EXTRA_ENV_KEYS = {"GRAFANA_ADMIN_PASSWORD"}


def _settings(**changes: object) -> Settings:
    return Settings.model_validate({**get_settings().model_dump(), **changes})


def _env_name(field_name: str) -> str:
    """The environment name a setting is read from: its own name when the owner chose one without the CII_
    prefix (TOTAL_SCENARIO_COUNT), else CII_<FIELD>."""
    alias = Settings.model_fields[field_name].validation_alias
    return alias if isinstance(alias, str) else f"CII_{field_name.upper()}"


def _env_keys(path: Path) -> set[str]:
    """The key NAMES set in an env file; values are never read out."""
    lines = path.read_text(encoding="utf-8").splitlines()
    return {
        line.split("=", 1)[0].strip() for line in lines if "=" in line and not line.lstrip().startswith("#")
    }


@pytest.mark.parametrize("name", [".env.example", ".env", ".env.uat"])
def test_env_files_match_settings(name: str) -> None:
    """Owner, 2026-10-09: .env and config.py stay in sync. Every setting has a line (with its value even when
    it equals the default), and no file keeps a key the app does not read (CII_PUBLIC_URL and
    CII_REDIS_CELERY_RESULT_BACKEND_URL were left in .env from v1). Only key names are compared."""
    path = REPO / name
    if not path.exists():
        pytest.skip(f"{name} is git-ignored and not present here")
    settings = {_env_name(name) for name in Settings.model_fields}
    keys = _env_keys(path)
    # Grafana's own settings (owner, 2026-10-09): a file lists only the ones the owner sets; a missing line
    # means Grafana's own default. .env.example documents the useful ones.
    grafana = {key for key in keys if key.startswith("GF_")}
    missing, unknown = sorted(settings - keys), sorted(keys - settings - EXTRA_ENV_KEYS - grafana)
    assert (missing, unknown) == ([], []), f"{name}: missing {missing}, not read by the app {unknown}"


def test_each_module_reads_its_own_chat_lines_and_a_missing_one_stops_start_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Owner 2026-10-28: no shared chat lines; each module's are its own, the same or a different model per
    module. URL, key and model are required. A module's fallback lines count only with a fallback model."""
    glm, kimi = "litellm_proxy/glm-5.3", "litellm_proxy/kimi-k2.5"
    monkeypatch.setenv("CII_REMEDIATION_CHAT_MODEL", glm)
    monkeypatch.setenv("CII_REMEDIATION_CHAT_MODEL_THINKING", "true")
    monkeypatch.setenv("CII_REMEDIATION_CHAT_REQUESTS_PER_MINUTE", "30")
    monkeypatch.setenv("CII_REMEDIATION_CHAT_FALLBACK_MODEL", kimi)
    monkeypatch.setenv("CII_REMEDIATION_MAX_CONCURRENT_FALLBACK_CALLS", "3")
    monkeypatch.setenv("CII_SERVICE_MAPPER_CHAT_FALLBACK_MODEL", "")
    monkeypatch.setenv("CII_SERVICE_MAPPER_MAX_CONCURRENT_FALLBACK_CALLS", "3")  # no fallback model: none
    settings = Settings()  # type: ignore[call-arg]
    scenario, remediation, mapper = (module_chat(settings, module) for module in ChatModule)
    assert (remediation.model, remediation.model_thinking, remediation.requests_per_minute) == (glm, True, 30)
    assert (remediation.fallback_model, remediation.max_concurrent_fallback_calls) == (kimi, 3)
    assert (
        scenario.model == settings.scenario_chat_model != glm
    )  # remediation's lines are remediation's alone
    assert (mapper.fallback_model, mapper.max_concurrent_fallback_calls) == ("", 0)
    without_model = settings.model_dump()
    del without_model["service_mapper_chat_model"]  # its line missing, or blank (a blank line is no line)
    with pytest.raises(ValidationError, match="service_mapper_chat_model"):
        Settings(_env_file=None, **without_model)  # type: ignore[call-arg]


def test_every_setting_in_env_example_says_what_it_does() -> None:
    """Owner 2026-10-29: a plain comment above every setting (or above the group it opens), so .env.example
    explains itself; a setting added without one fails here."""
    lines = (REPO / ".env.example").read_text(encoding="utf-8").splitlines()
    unexplained = []
    for number, line in enumerate(lines):
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        above = number - 1
        while above >= 0 and "=" in lines[above] and not lines[above].lstrip().startswith("#"):
            above -= 1  # a group of settings under one comment
        if above < 0 or not lines[above].lstrip().startswith("#"):
            unexplained.append(line.split("=", 1)[0])
    assert unexplained == []


def test_the_ai_tuning_defaults_are_the_values_env_example_shows() -> None:
    """config.py and .env.example agree: each AI tuning setting's default is the value .env.example writes,
    and each module's model limits are blank there (the model's own, app/ai/profiles.py)."""
    lines = (REPO / ".env.example").read_text(encoding="utf-8").splitlines()
    written = {
        key: value for key, _, value in (line.partition("=") for line in lines if line.startswith("CII_"))
    }
    for field, info in AiTuningSettings.model_fields.items():
        assert written[f"CII_{field.upper()}"] == str(info.default), field
    limits = [f for f in ChatModelSettings.model_fields if f.endswith(("_tokens", "_timeout_seconds"))]
    limits = [f for f in limits if not f.endswith("tokens_per_minute")]
    assert len(limits) == 18
    assert all(written[f"CII_{f.upper()}"] == "" and Settings.model_fields[f].default is None for f in limits)


def test_a_configmap_ai_value_reaches_the_code_and_a_bad_one_stops_start_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Changed in the ConfigMap, then a rollout restart: no new image. A fresh process, as a restarted pod."""
    changed = {
        "CII_THREAT_QUESTIONS_AT_ONCE": "3",
        "CII_THREATS_PER_QUESTION": "5",
        "CII_SCENARIOS_WRITTEN_AT_ONCE": "2",
        "CII_RERANKS_AT_ONCE": "2",
        "CII_ANSWER_TOKENS_RELEVANCE_GATE": "2048",
        "CII_AI_BUSY_MAX_WAIT_SECONDS": "20",
        "CII_AI_BUSY_TOTAL_WAIT_SECONDS": "30",
        "CII_AI_MODEL_COOL_DOWN_SECONDS": "45",
        "CII_AI_BUSY_LIMIT_FLOOR": "2",
        "CII_AI_BUSY_LIMIT_SECONDS": "90",
    }
    probe = (
        "import json; from app.core.constants import AiLimits as L, AiTask, CHAT_MAX_OUTPUT_TOKENS as C, "
        "Generation as G, RerankGateLimits as R, ThreatFinding as T; from app.domain.scenario import plan; "
        "print(json.dumps([T.AI_BATCHES_AT_ONCE, plan.GATE_BATCH_SIZE, G.WRITER_BATCH, R.RERANKS_AT_ONCE, "
        "C[AiTask.RELEVANCE_GATE], L.RATE_LIMITED_MAX_WAIT_SECONDS, L.RATE_LIMITED_TOTAL_WAIT_SECONDS, "
        "L.MODEL_COOL_DOWN_SECONDS, L.ADAPTIVE_LIMIT_FLOOR, L.ADAPTIVE_LIMIT_TTL_SECONDS]))"
    )
    restarted = subprocess.run(  # noqa: S603 - our own probe
        [sys.executable, "-c", probe], cwd=REPO, env=os.environ | changed, capture_output=True, text=True
    )
    assert json.loads(restarted.stdout.strip().splitlines()[-1]) == [int(v) for v in changed.values()]
    monkeypatch.setenv("CII_THREAT_QUESTIONS_AT_ONCE", "0")
    with pytest.raises(ValidationError, match="threat_questions_at_once"):
        AiTuningSettings()


def test_the_plan_version_cap_is_configurable_within_one_to_forty(monkeypatch: pytest.MonkeyPatch) -> None:
    """REGENERATIONS_MAX_VERSION_COUNT: 1 to 40 versions per plan (40 keeps a record under 16 MB)."""
    monkeypatch.setenv("REGENERATIONS_MAX_VERSION_COUNT", "25")
    assert Settings().regenerations_max_version_count == 25  # type: ignore[call-arg]
    for refused in ("0", "41"):
        monkeypatch.setenv("REGENERATIONS_MAX_VERSION_COUNT", refused)
        with pytest.raises(ValidationError, match="regenerations_max_version_count|REGENERATIONS"):
            Settings()  # type: ignore[call-arg]


def test_service_mapper_counts_come_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SERVICE_MAPPER_UPSTREAM_TOTAL_COUNT", "7")
    monkeypatch.setenv("SERVICE_MAPPER_DOWNSTREAM_TOTAL_COUNT", "0")  # 0 turns a direction off
    settings = Settings()  # type: ignore[call-arg]
    assert (settings.service_mapper_upstream_total_count, settings.service_mapper_downstream_total_count) == (
        7,
        0,
    )


def test_service_mapper_runs_per_mapping_default_to_5_and_0_means_no_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Owner 2026-10-28: SERVICE_MAPPER_MAX_GENERATIONS, the first run included; 0 = no limit."""
    assert Settings.model_fields["service_mapper_max_generations"].default == 5
    monkeypatch.setenv("SERVICE_MAPPER_MAX_GENERATIONS", "0")
    assert Settings().service_mapper_max_generations == 0  # type: ignore[call-arg]
    monkeypatch.setenv("SERVICE_MAPPER_MAX_GENERATIONS", "-1")
    with pytest.raises(ValidationError, match="SERVICE_MAPPER_MAX_GENERATIONS"):
        Settings()  # type: ignore[call-arg]


def test_operational_limits_come_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CII_MAX_REQUEST_MB", "3")
    monkeypatch.setenv("CII_MAX_CONCURRENT_AI_CALLS", "0")  # 0 = no limit
    settings = Settings()  # type: ignore[call-arg]  # the rest comes from .env
    assert (settings.max_request_mb, settings.max_concurrent_ai_calls) == (3, 0)
    monkeypatch.setenv("CII_MAX_REQUEST_MB", "0")
    with pytest.raises(ValidationError, match="max_request_mb"):
        Settings()  # type: ignore[call-arg]


def test_in_prod_a_wildcard_cors_origin_stops_start_up() -> None:
    with pytest.raises(ValidationError, match="CII_CORS_ORIGINS"):
        _settings(env=Env.PROD, cors_origins="*", admin_api_key="a" * 40)


def test_uat_accepts_a_wildcard_cors_origin() -> None:
    assert _settings(env=Env.UAT, cors_origins="*", admin_api_key="a" * 40).cors_origin_list == ["*"]


def test_outside_dev_a_short_admin_key_stops_start_up() -> None:
    with pytest.raises(ValidationError, match="CII_ADMIN_API_KEY"):
        _settings(env=Env.UAT, cors_origins="https://platform.example", admin_api_key="short")


def test_dev_accepts_laptop_settings() -> None:
    assert _settings(env=Env.DEV, cors_origins="*", admin_api_key="short").env is Env.DEV


def test_the_tests_never_write_into_the_log_folder_grafana_reads() -> None:
    """Before: with CII_LOG_DIR=logs in .env, the tests' simulated outages (refused, NOPERM, read-only
    replica) landed in logs\\api.log and showed in Grafana as if the real app could not reach Redis."""
    repo_logs = (Path(__file__).resolve().parents[1] / "logs").resolve()
    used = Path(get_settings().log_dir).resolve()
    assert used != repo_logs and repo_logs not in used.parents


def test_a_log_dir_also_writes_json_lines_to_the_role_file_once(tmp_path: Path) -> None:
    """The laptop's Loki reads <log_dir>/api.log: lines must be JSON, and a second start-up in the same
    process must not add a second writer (every line twice)."""
    settings = _settings(log_dir=str(tmp_path))
    root = logging.getLogger()
    before = list(root.handlers)
    try:
        configure_logging(settings, "api")
        configure_logging(settings, "api")
        structlog.get_logger("test").warning(LogEvent.AUDIT_WRITE_FAILED, action="key.minted")
        for handler in root.handlers:
            handler.flush()
        lines = (tmp_path / "api.log").read_text(encoding="utf-8").splitlines()
        assert [json.loads(line)["event"] for line in lines] == [LogEvent.AUDIT_WRITE_FAILED]
    finally:
        for handler in set(root.handlers) - set(before):
            root.removeHandler(handler)
            handler.close()


def test_a_library_error_with_a_traceback_is_one_json_line_with_its_level(tmp_path: Path) -> None:
    """Before: Celery's own lines ("Task … raised unexpected" and its traceback) were plain text, so Loki gave
    them no level and no error view on the dashboard showed them."""
    root = logging.getLogger()
    before = list(root.handlers)
    try:
        configure_logging(_settings(log_dir=str(tmp_path)), "worker-test")
        try:
            raise RuntimeError("boom")
        except RuntimeError:
            logging.getLogger("celery.app.trace").exception("Task %s raised unexpected", "tsg_reap")
        for handler in root.handlers:
            handler.flush()
        [line] = [
            json.loads(text)
            for text in (tmp_path / "worker-test.log").read_text(encoding="utf-8").splitlines()
        ]
        assert (line["level"], line["logger"], line["event"]) == (
            "error",
            "celery.app.trace",
            "Task tsg_reap raised unexpected",
        )
        assert line["exception"].startswith("Traceback") and "RuntimeError: boom" in line["exception"]
    finally:
        for handler in set(root.handlers) - set(before):
            root.removeHandler(handler)
            handler.close()


def test_a_laptop_log_file_rolls_over_and_keeps_three_old_copies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Before: never rotated, so logs/*.log grew for ever (owner, 2026-10-23: cap them)."""
    monkeypatch.setattr("app.core.logging._LOG_FILE_MAX_BYTES", 300)
    root = logging.getLogger()
    before = list(root.handlers)
    try:
        configure_logging(_settings(log_dir=str(tmp_path)), "api")
        for line in range(40):
            logging.getLogger("app.test").warning("line %d", line)
        assert sorted(path.name for path in tmp_path.iterdir()) == [
            "api.log",
            "api.log.1",
            "api.log.2",
            "api.log.3",
        ]
        assert all(path.stat().st_size <= 300 for path in tmp_path.iterdir())
    finally:
        for handler in set(root.handlers) - set(before):
            root.removeHandler(handler)
            handler.close()


def test_a_deployment_that_forgets_cii_env_gets_production_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    """Before: CII_ENV defaulted to dev, so a UAT or production Secret without it ran with no checks."""
    monkeypatch.delenv("CII_ENV", raising=False)
    values = {key: value for key, value in get_settings().model_dump().items() if key != "env"}
    unsafe = {**values, "cors_origins": "*", "admin_api_key": "a" * 40}
    with pytest.raises(ValidationError, match="CII_CORS_ORIGINS"):
        Settings(_env_file=None, **unsafe)  # no .env: the laptop's says dev


def test_total_scenario_count_reads_the_owners_unprefixed_name(monkeypatch: pytest.MonkeyPatch) -> None:
    """G106: the count is a setting, never a code constant; 0 = every valid path."""
    monkeypatch.setenv("TOTAL_SCENARIO_COUNT", "12")
    assert Settings().total_scenario_count == 12  # type: ignore[call-arg]
    monkeypatch.setenv("TOTAL_SCENARIO_COUNT", "0")
    assert Settings().total_scenario_count == 0  # type: ignore[call-arg]


@pytest.mark.parametrize("value", ["-1", "1.5", "abc", "true"])
def test_total_scenario_count_refuses_negative_decimal_and_text(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv("TOTAL_SCENARIO_COUNT", value)
    with pytest.raises(ValidationError, match="TOTAL_SCENARIO_COUNT"):
        Settings()  # type: ignore[call-arg]


@pytest.mark.parametrize("name", ["INITIAL_SET_SIZE", "NEXT_SET_SIZE"])
def test_set_sizes_read_the_owners_names_and_refuse_zero_negative_and_text(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    """G196 (owner 2026-10-11): the owner's unprefixed names; a set is at least one scenario."""
    monkeypatch.setenv(name, "3")
    assert getattr(Settings(), name.lower()) == 3  # type: ignore[call-arg]
    for value in ("0", "-1", "abc"):
        monkeypatch.setenv(name, value)
        with pytest.raises(ValidationError, match=name):
            Settings()  # type: ignore[call-arg]


def test_required_property_lists_parse_and_refuse_always_used_names(monkeypatch: pytest.MonkeyPatch) -> None:
    """G203 (owner 2026-10-11): comma lists, spaces allowed, any column name (a new procedure column too);
    an always-used name (id, name, category_code, alias) stops start-up, naming the setting."""
    monkeypatch.setenv("ASSET_PROPERTIES_REQUIRED", " location , recovery_notes ")
    monkeypatch.setenv("SYSTEM_PROPERTIES_REQUIRED", "technology_used")
    settings = Settings()  # type: ignore[call-arg]
    assert settings.required_asset_properties == {"location", "recovery_notes"}
    assert settings.required_system_properties == {"technology_used"}
    monkeypatch.setenv("SYSTEM_PROPERTIES_REQUIRED", "technology_used, alias")
    with pytest.raises(ValidationError, match=r"SYSTEM_PROPERTIES_REQUIRED names \['alias'\]"):
        Settings()  # type: ignore[call-arg]


@pytest.mark.parametrize("name", ["CONTROL_SIMILARITY_THRESHOLD", "THREAT_SIMILARITY_THRESHOLD"])
def test_similarity_thresholds_read_the_owners_names_on_one_0_to_100_scale(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    """One scale, the reranker's 0-100, for controls and threats."""
    monkeypatch.setenv(name, "42.5")
    assert getattr(Settings(), name.lower()) == 42.5  # type: ignore[call-arg]
    for value in ("-1", "100.5", "high"):
        monkeypatch.setenv(name, value)
        with pytest.raises(ValidationError, match=name):
            Settings()  # type: ignore[call-arg]


@pytest.mark.parametrize("proxy", ["10.61.192.2:8080", "socks5://10.61.192.2:1080", "ftp://proxy"])
def test_a_proxy_url_without_http_or_https_stops_start_up(proxy: str) -> None:
    with pytest.raises(ValidationError, match="CII_PROXY_URL"):
        _settings(proxy_url=proxy)


def test_no_proxy_url_is_the_default_and_an_http_one_is_kept_secret() -> None:
    assert _settings().proxy_url.get_secret_value() == ""
    configured = _settings(proxy_url="http://ops:pw@10.61.192.2:8080")
    assert configured.proxy_url.get_secret_value() == "http://ops:pw@10.61.192.2:8080"
    assert "pw@" not in repr(configured)  # a proxy address can carry a password: never in a log or repr
