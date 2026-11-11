"""The AI capacity report (scripts/ai_capacity_report.py) on a fake /v1/ai-usage: per-step averages, a
request's busiest minute as the gateway counts it (a chat call holds its prompt and whole answer cap while it
runs), its calls at once, and what 10 users starting it together need. Each test names the mutation it
catches."""

import importlib
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
try:
    report = importlib.import_module("ai_capacity_report")
finally:
    sys.path.remove(str(REPO / "scripts"))

CAPS = {"relevance_gate": 10_240, "write_scenario": 6_144, "plan_check": 3_072}
T0 = datetime(2026, 10, 30, 9, 0, tzinfo=UTC)


def _row(
    task: str, start: float, seconds: float, tokens: tuple[int, int] = (0, 0), outcome: str = "ok"
) -> dict:
    """A report-4 row: noted as its attempt ends."""
    end = (T0 + timedelta(seconds=start + seconds)).isoformat()
    model = "litellm_proxy/qwen3-embedding-8b" if task == "embed" else "litellm_proxy/kimi-k2.5"
    return {"task": task, "model": model, "outcome": outcome, "created_at": end, "seconds": seconds,
            "tokens_in": tokens[0], "tokens_out": tokens[1]}  # fmt: skip


#: One create_scenario request: the embed (100 held), the gate (5,000 + its 10,240 cap) overlapping the writer
#: (3,000 + 6,144), a refused writer try, a reused answer, and the plan check (1,000 + 3,072) 50 s in.
ROWS = [
    _row("embed", 0, 1, (100, 0)),
    _row("relevance_gate", 1, 20, (5_000, 2_000)),
    _row("write_scenario", 10, 30, (3_000, 1_500)),
    _row("write_scenario", 69.5, 0.5, outcome="unavailable"),
    {
        "task": "write_scenario",
        "model": "litellm_proxy/kimi-k2.5",
        "outcome": "reused",
        "created_at": T0.isoformat(),
    },
    _row("plan_check", 50, 10, (1_000, 200)),
]


def _client() -> httpx.Client:
    """The two report routes; the calls come in two pages, as report 4 pages them."""

    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/requests"):
            item = {"request_id": "r1", "module": "threat_scenarios", "api": "create_scenario",
                    "api_label": "Create scenario", "first_at": T0.isoformat()}  # fmt: skip
            return httpx.Response(200, json={"items": [item], "next": None})
        assert request.url.params["request_id"] == "r1"
        if request.url.params.get("after") == "page2":
            return httpx.Response(200, json={"items": ROWS[3:], "next": None})
        return httpx.Response(200, json={"items": ROWS[:3], "next": "page2"})

    return httpx.Client(base_url="http://tsg.test", transport=httpx.MockTransport(handle))


def _lines() -> list[str]:
    return report.report_lines(_client(), T0.isoformat(), per_api=20, users=10, caps=CAPS)


def test_each_step_per_request_with_refused_tries_apart() -> None:
    """Mutation: count a refused try as sent, or the cap not held."""
    rows = {line.split()[0]: line.split()[1:] for line in _lines() if line.startswith("  ")}
    assert rows["write_scenario"] == ["kimi-k2.5", "1.0", "1.0", "3,000", "1,500", "9,144", "30.0"]
    assert rows["relevance_gate"] == ["kimi-k2.5", "1.0", "0.0", "5,000", "2,000", "15,240", "20.0"]
    assert rows["embed"] == ["qwen3-embedding-8b", "1.0", "0.0", "100", "0", "100", "1.0"]


def test_busiest_minute_counts_running_calls_at_their_hold_and_finished_ones_at_their_use() -> None:
    """As the writer starts (10 s), the embed has finished (100 used), the gate still runs (15,240 held), and
    the writer holds 9,144: 24,484. As the plan check starts (50 s) all four started within the minute, but
    the rest have finished: 100 + 7,000 + 4,500 + 4,072 = 15,672. Mutation: a finished call kept at its hold
    (28,556), the cap not added (11,600), a 30 s window (3 calls), or calls at once counted one by one."""
    text = "\n".join(_lines())
    assert "busiest minute of one request: 24,484 tokens counted, 4 calls" in text
    assert "most at once: 2" in text
    assert "10 users at once: 244,840 tokens a minute, 40 requests a minute, 20 calls at once" in text


def test_headline_names_the_gateway_ask_and_the_modules_settings() -> None:
    """The module's chat pacing leaves the embedding out: 15,240 + 9,144 = 24,384 per user."""
    text = "\n".join(_lines())
    assert (
        "tokens a minute:   at least 244,840  (threat_scenarios / create_scenario - Create scenario)" in text
    )
    assert "requests a minute: at least 40" in text
    assert (
        "CII_SCENARIO_MAX_CONCURRENT_AI_CALLS >= 20; CII_SCENARIO_CHAT_TOKENS_PER_MINUTE 0 or >= 243,840"
        in text
    )
