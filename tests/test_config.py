"""Settings refuse what is only acceptable on a laptop, everywhere but dev; the laptop log file."""

import json
import logging
from pathlib import Path

import pytest
import structlog
from pydantic import ValidationError

from app.core.config import Settings, get_settings
from app.core.constants import Env, LogEvent
from app.core.logging import configure_logging

REPO = Path(__file__).resolve().parents[1]
#: Keys an env file may hold besides the Settings fields: the laptop monitoring script reads this one.
EXTRA_ENV_KEYS = {"GRAFANA_ADMIN_PASSWORD"}


def _settings(**changes: object) -> Settings:
    return Settings.model_validate({**get_settings().model_dump(), **changes})


def _env_name(field_name: str) -> str:
    """The environment name a setting is read from: its own name when the owner chose one without the CII_
    prefix (DEBUG_STEP_OUTPUT), else CII_<FIELD>."""
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


def test_the_plan_version_cap_is_configurable_within_one_to_forty(monkeypatch: pytest.MonkeyPatch) -> None:
    """REGENERATIONS_MAX_VERSION_COUNT: 1 to 40 versions per plan (40 keeps a record under 16 MB)."""
    monkeypatch.setenv("REGENERATIONS_MAX_VERSION_COUNT", "25")
    assert Settings().regenerations_max_version_count == 25  # type: ignore[call-arg]
    for refused in ("0", "41"):
        monkeypatch.setenv("REGENERATIONS_MAX_VERSION_COUNT", refused)
        with pytest.raises(ValidationError, match="regenerations_max_version_count|REGENERATIONS"):
            Settings()  # type: ignore[call-arg]


def test_operational_limits_come_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CII_MAX_REQUEST_MB", "3")
    monkeypatch.setenv("CII_MAX_CONCURRENT_AI_CALLS", "0")  # 0 = no limit
    settings = Settings()  # type: ignore[call-arg]  # the rest comes from .env
    assert (settings.max_request_mb, settings.max_concurrent_ai_calls) == (3, 0)
    monkeypatch.setenv("CII_MAX_REQUEST_MB", "0")
    with pytest.raises(ValidationError, match="max_request_mb"):
        Settings()  # type: ignore[call-arg]


@pytest.mark.parametrize("env", [Env.UAT, Env.PROD])
def test_outside_dev_a_wildcard_cors_origin_stops_start_up(env: Env) -> None:
    with pytest.raises(ValidationError, match="CII_CORS_ORIGINS"):
        _settings(env=env, cors_origins="*", admin_api_key="a" * 40)


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


def test_a_deployment_that_forgets_cii_env_gets_production_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    """Before: CII_ENV defaulted to dev, so a UAT or production Secret without it ran with no checks."""
    monkeypatch.delenv("CII_ENV", raising=False)
    values = {key: value for key, value in get_settings().model_dump().items() if key != "env"}
    unsafe = {**values, "cors_origins": "*", "admin_api_key": "a" * 40}
    with pytest.raises(ValidationError, match="CII_CORS_ORIGINS"):
        Settings(_env_file=None, **unsafe)  # no .env: the laptop's says dev


def test_step_tracing_reads_the_owners_unprefixed_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEBUG_STEP_OUTPUT", "true")
    assert Settings().debug_step_output is True  # type: ignore[call-arg]
    monkeypatch.setenv("DEBUG_STEP_OUTPUT", "false")
    assert Settings().debug_step_output is False  # type: ignore[call-arg]
    monkeypatch.setenv("DEBUG_STEP_OUTPUT", "maybe")
    with pytest.raises(ValidationError, match="DEBUG_STEP_OUTPUT"):
        Settings()  # type: ignore[call-arg]


def test_step_detail_reads_the_owners_unprefixed_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEBUG_STEP_DETAIL", "true")
    assert Settings().debug_step_detail is True  # type: ignore[call-arg]
    monkeypatch.setenv("DEBUG_STEP_DETAIL", "false")
    assert Settings().debug_step_detail is False  # type: ignore[call-arg]
    monkeypatch.setenv("DEBUG_STEP_DETAIL", "maybe")
    with pytest.raises(ValidationError, match="DEBUG_STEP_DETAIL"):
        Settings()  # type: ignore[call-arg]


def test_step_top_reads_the_owners_name_and_keeps_1_to_40(monkeypatch: pytest.MonkeyPatch) -> None:
    """A ranked inner record keeps 1 to 40 entries: 40 is the most one logged mapping shows."""
    for value in (1, 40):
        monkeypatch.setenv("DEBUG_STEP_TOP", str(value))
        assert Settings().debug_step_top == value  # type: ignore[call-arg]
    for text in ("0", "41", "abc"):
        monkeypatch.setenv("DEBUG_STEP_TOP", text)
        with pytest.raises(ValidationError, match="DEBUG_STEP_TOP"):
            Settings()  # type: ignore[call-arg]


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
