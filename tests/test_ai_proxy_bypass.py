"""CII_AI_BYPASS_PROXY (v1's TSG_LITELLM_BYPASS_PROXY), set in the env file only: the UAT Windows server's
proxy cannot reach the LiteLLM gateway, so its host goes on NO_PROXY; no other host does. The AI key never
reaches a log."""

import json
import logging
import os
import subprocess
import sys
import urllib.request
from pathlib import Path

import httpcore
import httpx
import pytest
from pydantic import SecretStr
from structlog.testing import capture_logs

import app.ai  # noqa: F401  # caps the library loggers on import
from app.ai.common import apply_proxy_settings, merged_no_proxy
from app.core.config import Settings, get_settings
from app.core.constants import LogEvent

GATEWAY = "https://llmapi.example:443/v1"
COMPANY_PROXY = "http://proxy.test:8080"  # what Windows' own proxy setting (Internet Options) names
_PROXY_VARIABLES = ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")


def _settings(bypass: bool, proxy_url: str = "") -> Settings:
    return get_settings().model_copy(
        update={
            "ai_bypass_proxy": bypass,
            "proxy_url": SecretStr(proxy_url),
            "chat_model": "litellm_proxy/chat",
            "chat_base_url": GATEWAY,
            "chat_fallback_model": "",
            "embedding_model": "litellm_proxy/embed",
            "embedding_base_url": "llmapi.example",  # no scheme: still read as a host
            "rerank_model": "openai/rerank",  # not a LiteLLM gateway model: its host keeps the proxy
            "rerank_base_url": "https://other-provider.example",
        }
    )


@pytest.fixture(autouse=True)
def _proxy_env(monkeypatch: pytest.MonkeyPatch) -> None:
    # Windows reads env names without case (one variable); Linux has two: clear both, then set one.
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.setenv("NO_PROXY", "localhost")
    for name in _PROXY_VARIABLES:  # empty (ignored by Python), and put back as it was after the test
        monkeypatch.setenv(name, "")
    _windows_proxy_setting(monkeypatch, {})  # never this laptop's own setting


def _windows_proxy_setting(monkeypatch: pytest.MonkeyPatch, found: dict[str, str]) -> None:
    monkeypatch.setattr(urllib.request, "getproxies_registry", lambda: found, raising=False)


def test_the_gateway_goes_on_no_proxy_once_and_keeps_what_was_there() -> None:
    apply_proxy_settings(_settings(True))
    apply_proxy_settings(_settings(True))  # a second call adds no host twice
    assert os.environ["NO_PROXY"] == "localhost,llmapi.example"
    assert os.environ["no_proxy"].split(",")[-1] == "llmapi.example"  # Linux tools read the lowercase one


def test_off_leaves_the_proxy_in_charge() -> None:
    apply_proxy_settings(_settings(False))
    assert os.environ["NO_PROXY"] == "localhost"
    assert "llmapi.example" not in os.environ.get("no_proxy", "")


def test_every_other_host_keeps_the_windows_proxy_once_the_gateway_is_on_no_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # G263 (UAT, 2026-10-16): Python reads Windows' proxy setting only while no *_PROXY variable is set, so
    # the NO_PROXY written for the gateway sent every intel feed straight to the firewall ("did not answer").
    _windows_proxy_setting(monkeypatch, {"http": COMPANY_PROXY, "https": COMPANY_PROXY})
    apply_proxy_settings(_settings(True))
    found = urllib.request.getproxies()  # what httpx reads (trust_env)
    assert found["https"] == found["http"] == COMPANY_PROXY
    assert not urllib.request.proxy_bypass_environment("www.cisa.gov", found)  # a feed: through the proxy
    assert urllib.request.proxy_bypass_environment("llmapi.example", found)  # the gateway: direct


def test_a_proxy_variable_already_set_wins_over_the_windows_setting(monkeypatch: pytest.MonkeyPatch) -> None:
    _windows_proxy_setting(monkeypatch, {"https": COMPANY_PROXY})
    monkeypatch.setenv("HTTPS_PROXY", "http://chosen.test:3128")
    apply_proxy_settings(_settings(True))
    assert urllib.request.getproxies()["https"] == "http://chosen.test:3128"


def test_nothing_is_copied_when_the_bypass_is_off_or_not_on_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    _windows_proxy_setting(monkeypatch, {"https": COMPANY_PROXY})
    apply_proxy_settings(_settings(False))
    assert not any(os.environ.get(name) for name in _PROXY_VARIABLES)
    monkeypatch.delattr(urllib.request, "getproxies_registry")  # Linux, OpenShift: no Windows setting
    apply_proxy_settings(_settings(True))
    assert not any(os.environ.get(name) for name in _PROXY_VARIABLES)


CONFIGURED_PROXY = "http://configured.test:3128"  # CII_PROXY_URL


def test_the_configured_proxy_carries_every_other_host_and_wins_over_the_rest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Owner 2026-10-16: the proxy is set in the env file, like CII_AI_BYPASS_PROXY.
    _windows_proxy_setting(monkeypatch, {"https": COMPANY_PROXY})
    monkeypatch.setenv("HTTPS_PROXY", "http://chosen.test:3128")
    apply_proxy_settings(_settings(True, CONFIGURED_PROXY))
    found = urllib.request.getproxies()
    assert found["https"] == found["http"] == CONFIGURED_PROXY
    assert not urllib.request.proxy_bypass_environment("www.cisa.gov", found)  # a feed: through it
    assert urllib.request.proxy_bypass_environment("llmapi.example", found)  # the gateway still skips it


def test_with_the_bypass_off_the_ai_calls_use_the_configured_proxy_too() -> None:
    apply_proxy_settings(_settings(False, CONFIGURED_PROXY))
    found = urllib.request.getproxies()
    assert found["https"] == CONFIGURED_PROXY
    assert not urllib.request.proxy_bypass_environment("llmapi.example", found)


def test_importing_the_ai_layer_never_copies_the_env_file_into_the_environment(tmp_path: Path) -> None:
    # G263: litellm loaded ./.env into os.environ on import. CII_AI_BYPASS_PROXY then read as a proxy variable
    # (its name ends in _PROXY), so Windows' proxy setting was ignored from start-up; every key went along.
    (tmp_path / ".env").write_text("CII_AI_BYPASS_PROXY=true\nCII_CHAT_API_KEY=must-stay-in-the-file\n")
    probe = (
        "import json, os, urllib.request, app.ai; "
        "print(json.dumps([sorted(k for k in os.environ if k.upper().startswith('CII_')), "
        "sorted(urllib.request.getproxies())]))"
    )
    keep = {k: v for k, v in os.environ.items() if not k.upper().startswith(("CII_", "LITELLM_MODE"))}
    fresh = subprocess.run(  # noqa: S603  # our own probe; a fresh process: litellm loads once per process
        [sys.executable, "-c", probe],
        cwd=tmp_path,
        env={**keep, "PYTHONPATH": str(Path(__file__).resolve().parents[1])},
        capture_output=True,
        text=True,
        check=True,
    )
    in_environment, proxy_kinds = json.loads(fresh.stdout.strip().splitlines()[-1])
    assert in_environment == [] and "cii_ai_bypass" not in proxy_kinds


POD_PROXY = "http://10.61.192.2:8080"  # what the UAT pods' HTTPS_PROXY names
POD_NO_PROXY = "localhost,127.0.0.1,.svc,.cluster.local"


def _route(url: str) -> str:
    """The route the HTTP client litellm builds (httpx, reading the environment) gives `url`."""
    pool = httpx.Client()._transport_for_url(httpx.URL(url))._pool  # type: ignore[attr-defined]
    return "proxy" if isinstance(pool, httpcore.HTTPProxy) else "direct"


@pytest.mark.parametrize(("bypass", "gateway"), [(True, "direct"), (False, "proxy")])
def test_the_http_client_sends_the_gateway_direct_and_everything_else_as_the_pod_says(
    monkeypatch: pytest.MonkeyPatch, bypass: bool, gateway: str
) -> None:
    """UAT, 2026-10-21: the corporate proxy never answers for the gateway. With the bypass the client the AI
    calls use goes direct to it; the pod's own NO_PROXY entries stay direct; an intel feed takes the proxy."""
    monkeypatch.setenv("HTTPS_PROXY", POD_PROXY)
    monkeypatch.setenv("NO_PROXY", POD_NO_PROXY)
    apply_proxy_settings(_settings(bypass))
    assert _route(GATEWAY) == gateway
    assert _route("https://redis.tsg.svc") == _route("https://localhost") == "direct"
    assert _route("https://www.cisa.gov") == "proxy"


@pytest.mark.parametrize(
    ("environment", "merged"),
    [
        ({"NO_PROXY": POD_NO_PROXY, "no_proxy": ""}, f"{POD_NO_PROXY},llmapi.example"),
        ({"NO_PROXY": "a, b", "no_proxy": "b,c"}, "a,b,c,llmapi.example"),
        ({"NO_PROXY": "llmapi.example"}, "llmapi.example"),
        ({}, "llmapi.example"),
    ],
    ids=["pod-uppercase-only", "both-spellings", "already-listed", "none"],
)
def test_both_spellings_are_merged_so_the_gateway_never_hides_the_pods_entries(
    environment: dict[str, str], merged: str
) -> None:
    """Linux has NO_PROXY and no_proxy apart, and Python reads the lowercase one alone: the gateway written
    into it alone hid the pod's localhost, .svc and .cluster.local (Windows has one variable, so this is
    checked on the merge itself)."""
    assert merged_no_proxy(environment, {"llmapi.example"}) == merged


def test_each_gateway_route_is_logged_once_without_the_proxy_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://tsg:secret@proxy.test:8080")
    with capture_logs() as logs:
        apply_proxy_settings(_settings(True))
    routes = {
        e["host"]: (e["route"], e.get("proxy")) for e in logs if e["event"] == LogEvent.AI_GATEWAY_ROUTE
    }
    assert routes == {
        "llmapi.example": ("direct", None),
        "other-provider.example": ("proxy", "proxy.test:8080"),
    }
    assert "secret" not in str(logs)


def test_the_openai_client_cannot_log_the_ai_key() -> None:
    # At DEBUG it logs each request's headers, the gateway key among them (UAT log, 2026-10-15).
    assert logging.getLogger("openai").getEffectiveLevel() >= logging.WARNING
