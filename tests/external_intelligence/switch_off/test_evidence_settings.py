"""EVIDENCE_SIMILARITY_THRESHOLD is per environment (each reranker scores on its own scale): outside dev, with
external intelligence on, start-up refuses a threshold nobody set. The UAT file is dormant (feature off),
names only models that have a profile, and the feature code names no model."""

import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.ai.profiles import (
    CHAT_MODEL_PROFILES,
    EMBEDDING_MODEL_PROFILES,
    RERANK_MODEL_PROFILES,
    find_model_profile,
)
from app.core.config import Settings
from app.core.constants import Env, EvidenceSettingMessage

REPO = Path(__file__).resolve().parents[3]
KEY = "a" * 40


_OWN_KEYS = (
    "CII_ENV",
    "EXTERNAL_INTELLIGENCE_ENABLED",
    "EVIDENCE_SIMILARITY_THRESHOLD",
    "CII_CORS_ORIGINS",
    "CII_ADMIN_API_KEY",
)


def _settings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    env: Env,
    enabled: bool | None,
    threshold: str | None = None,
) -> Settings:
    """Settings read the way the app reads them (an env file): a threshold line left out is not 'set'."""
    source = REPO / ".env"
    if not source.exists():
        pytest.skip(".env is git-ignored and not present here")
    kept = [
        line
        for line in source.read_text(encoding="utf-8").splitlines()
        if line.split("=")[0] not in _OWN_KEYS
    ]
    own = [f"CII_ENV={env}"]
    own += [] if enabled is None else [f"EXTERNAL_INTELLIGENCE_ENABLED={str(enabled).lower()}"]
    own += [f"EVIDENCE_SIMILARITY_THRESHOLD={threshold}"] if threshold else []
    path = tmp_path / "test.env"
    lines = [*kept, *own, "CII_CORS_ORIGINS=https://platform.example"]
    path.write_text(chr(10).join(lines), encoding="utf-8")
    for name in ("CII_ENV", "EXTERNAL_INTELLIGENCE_ENABLED", "EVIDENCE_SIMILARITY_THRESHOLD"):
        monkeypatch.delenv(name, raising=False)  # the suite's own values must not stand in for the file's
    monkeypatch.setenv("CII_ADMIN_API_KEY", KEY)
    monkeypatch.setenv("CII_CORS_ORIGINS", "https://platform.example")
    return Settings(_env_file=path)  # type: ignore[call-arg]


@pytest.mark.parametrize("env", [Env.UAT, Env.PROD])
def test_outside_dev_an_enabled_feature_needs_an_explicit_threshold(
    env: Env, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(ValidationError, match="EVIDENCE_SIMILARITY_THRESHOLD must be set"):
        _settings(tmp_path, monkeypatch, env, True)
    assert _settings(tmp_path, monkeypatch, env, True, "50").evidence_similarity_threshold == 50


@pytest.mark.parametrize("env", [Env.UAT, Env.PROD])
def test_outside_dev_a_disabled_feature_needs_no_threshold(
    env: Env, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path, monkeypatch, env, False)
    assert settings.external_intelligence_enabled is False and settings.env is env


@pytest.mark.parametrize("env", [Env.DEV, Env.UAT, Env.PROD])
def test_a_deployment_that_forgets_the_master_switch_stays_the_original_tsg(
    env: Env, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Default OFF: no EXTERNAL_INTELLIGENCE_ENABLED line anywhere means off, in every environment (and so
    no threshold is demanded either)."""
    assert _settings(tmp_path, monkeypatch, env, None).external_intelligence_enabled is False


def test_the_dev_file_turns_it_on_explicitly_and_the_example_file_documents_the_default() -> None:
    assert _env_lines(".env")["EXTERNAL_INTELLIGENCE_ENABLED"] == "true"
    text = (REPO / ".env.example").read_text(encoding="utf-8")
    assert _env_lines(".env.example")["EXTERNAL_INTELLIGENCE_ENABLED"] == "false" and "Default when" in text


def test_dev_needs_no_explicit_threshold(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert _settings(tmp_path, monkeypatch, Env.DEV, True).evidence_similarity_threshold == 1.0


def _env_lines(name: str) -> dict[str, str]:
    path = REPO / name
    if not path.exists():
        pytest.skip(f"{name} is git-ignored and not present here")
    pairs = (line.split("=", 1) for line in path.read_text(encoding="utf-8").splitlines() if "=" in line)
    return {key.strip(): value.strip() for key, value in pairs if not key.lstrip().startswith("#")}


def test_the_uat_file_is_on_with_an_explicit_provisional_threshold() -> None:
    """Owner 2026-10-13: UAT runs with external intelligence on (it shipped dormant until then); its cut-off
    stays the explicit provisional 50, marked not calibrated."""
    lines = _env_lines(".env.uat")
    assert lines["EXTERNAL_INTELLIGENCE_ENABLED"] == "true"
    assert float(lines["EVIDENCE_SIMILARITY_THRESHOLD"]) == 50
    assert "CII_NVD_API_KEY" in lines  # a secret: any value
    text = (REPO / ".env.uat").read_text(encoding="utf-8")
    assert "NOT calibrated" in text.replace("NOT CALIBRATED", "NOT calibrated") and "To test in UAT" in text


def test_the_uat_file_passes_the_start_up_rule_on_and_switched_off(monkeypatch: pytest.MonkeyPatch) -> None:
    lines = _env_lines(".env.uat")
    for name in ("CII_ENV", "EXTERNAL_INTELLIGENCE_ENABLED", "EVIDENCE_SIMILARITY_THRESHOLD"):
        monkeypatch.delenv(name, raising=False)  # the suite's own values must not stand in for the file's
    monkeypatch.setenv("CII_ADMIN_API_KEY", KEY)
    monkeypatch.setenv("CII_CORS_ORIGINS", "https://platform.example")
    enabled = Settings(_env_file=REPO / ".env.uat")  # type: ignore[call-arg]
    assert enabled.env is Env.UAT and enabled.external_intelligence_enabled is True
    assert enabled.evidence_similarity_threshold == float(lines["EVIDENCE_SIMILARITY_THRESHOLD"])
    monkeypatch.setenv("EXTERNAL_INTELLIGENCE_ENABLED", "false")  # switched off again: nothing else to change
    dormant = Settings(_env_file=REPO / ".env.uat")  # type: ignore[call-arg]
    assert dormant.external_intelligence_enabled is False
    assert EvidenceSettingMessage.THRESHOLD_NOT_SET.value  # the refusal has its words


def test_every_model_the_uat_file_names_has_a_profile() -> None:
    lines = _env_lines(".env.uat")
    for key, profiles in (
        ("CII_CHAT_MODEL", CHAT_MODEL_PROFILES),
        ("CII_CHAT_FALLBACK_MODEL", CHAT_MODEL_PROFILES),
        ("CII_EMBEDDING_MODEL", EMBEDDING_MODEL_PROFILES),
        ("CII_RERANK_MODEL", RERANK_MODEL_PROFILES),
    ):
        if lines.get(key):
            assert find_model_profile(profiles, lines[key]) is not None, key


def test_the_feature_code_names_no_model() -> None:
    tables = (CHAT_MODEL_PROFILES, EMBEDDING_MODEL_PROFILES, RERANK_MODEL_PROFILES)
    names = {name.rsplit("/", 1)[-1] for table in tables for name in table}
    names |= {"kimi", "qwen3", "bge-reranker", "glm-5", "gpt-"}
    sources = [
        source
        for source in (REPO / "app").rglob("*.py")
        if "external_intelligence" in source.parts or source.name == "evidence_story.py"
    ]
    named = []
    for source in sources:
        text = source.read_text(encoding="utf-8").lower()
        named += [f"{source.name}: {name}" for name in names if re.search(re.escape(name.lower()), text)]
    # the one place that records which reranker was calibrated is a table of model names by design
    assert [item for item in named if not item.startswith("evidence_story.py")] == []
