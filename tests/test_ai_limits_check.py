"""The AI limits check (scripts/ai_limits_check.py) on a fake LiteLLM gateway: the team's budget found, the
key and team id never printed, the setting suggested; a 429's budget read from its text."""

import importlib
import sys
from pathlib import Path

import httpx

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
try:
    check = importlib.import_module("ai_limits_check")
finally:
    sys.path.remove(str(REPO / "scripts"))

KEY, TEAM = "sk-secret-key", "team-efd5f7f8"


def _gateway(chat: httpx.Response, refused: tuple[str, ...] = ()) -> httpx.Client:
    """A LiteLLM gateway whose key has no limits, whose team has 200,000 tokens a minute; `refused` paths
    answer 403."""
    answers = {
        "/key/info": {"key": "hashed", "info": {"team_id": TEAM, "tpm_limit": None, "rpm_limit": None}},
        "/team/info": {"team_id": TEAM, "team_info": {"tpm_limit": 200_000, "rpm_limit": None}},
        "/model/info": {"data": [{"model_name": "kimi-k2.5", "model_info": {"max_input_tokens": 114_688}}]},
    }

    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/chat/completions":
            return chat
        if request.url.path in refused:
            return httpx.Response(403, json={"error": "not allowed"})
        return httpx.Response(200, json=answers[request.url.path])

    return httpx.Client(
        base_url="https://gw.test",
        headers={"Authorization": f"Bearer {KEY}"},
        transport=httpx.MockTransport(handle),
    )


def test_team_budget_found_and_setting_suggested() -> None:
    chat = httpx.Response(200, json={}, headers={"x-ratelimit-limit-tokens": "250000"})
    report = "\n".join(check.report_lines(_gateway(chat), "litellm_proxy/kimi-k2.5", ["scenario"]))
    assert "team    tpm_limit 200000, rpm_limit none set" in report
    assert "model   model_info.max_input_tokens 114688" in report
    assert "x-ratelimit-limit-tokens 250000" in report
    assert "set CII_SCENARIO_CHAT_TOKENS_PER_MINUTE to about 180,000" in report
    assert KEY not in report and TEAM not in report


def test_429_budget_read_and_split_between_modules() -> None:
    text = f"Rate limit exceeded for team: {TEAM}. Limit type: tokens. Current limit: 150000, Remaining: 0."
    chat = httpx.Response(429, text=text, headers={"rate_limit_type": "tokens", "retry-after": "12"})
    users = ["remediation", "service_mapper", "scenario fallback"]
    report = "\n".join(check.report_lines(_gateway(chat), "litellm_proxy/kimi-k2.5", users, sharing=2))
    assert "'limit_scope': 'team', 'limit': 150000" in report
    assert "CII_REMEDIATION_CHAT_TOKENS_PER_MINUTE to about 67,500" in report  # 150,000 x 0.9 / 2
    assert "CII_SERVICE_MAPPER_CHAT_TOKENS_PER_MINUTE to about 67,500" in report
    assert "SCENARIO" not in report and TEAM not in report


def test_uat_key_info_refused_organization_budget_from_headers() -> None:
    """UAT 2026-10-29: /key/info 403, the organization's 25,000 tokens a minute only in the headers."""
    headers = {
        "x-ratelimit-organization-limit-tokens": "25000",
        "x-ratelimit-team-limit-tokens": "2000000",
        "x-ratelimit-limit-requests": "600",
    }
    chat = httpx.Response(200, json={}, headers=headers)
    report = "\n".join(
        check.report_lines(_gateway(chat, refused=("/key/info",)), "litellm_proxy/kimi-k2.5", ["x"])
    )
    assert "key     HTTP 403: this key may not read it" in report
    assert "team    not known: the key's info was not read" in report
    assert "lowest tokens-a-minute found: 25,000" in report
