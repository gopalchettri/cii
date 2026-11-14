"""TSG's biggest Create scenario request of the day (scripts/tsg_scenario_request.py), on a fake MongoDB: the
biggest by input tokens plus answer cap, rebuilt with its system prompt and checked against its stored
fingerprint, sent with TSG's own request options. Each test names the mutation it catches."""

import importlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from bson import ObjectId

from app.ai.chat_messages import build_conversation, prompt_hash
from app.core.config import get_settings
from app.core.constants import CHAT_MAX_OUTPUT_TOKENS, THINKING_OFF_TEMPLATE_KWARGS, AiTask
from app.domain.scenario.plan import _PLANNER_SYSTEM
from app.domain.scenario.write import build_writer_system_prompt

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
try:
    extract = importlib.import_module("tsg_scenario_request")
finally:
    sys.path.remove(str(REPO / "scripts"))

MODEL = "litellm_proxy/kimi-k2.5"


class _Collection:
    """A collection's rows; what `find` was asked is kept."""

    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows, self.asked = rows, []

    def find(self, query: dict, projection: dict, max_time_ms: int) -> list[dict[str, Any]]:
        self.asked.append(query)
        return list(self.rows)

    def find_one(self, query: dict, max_time_ms: int) -> dict[str, Any] | None:
        return next((row for row in self.rows if row["_id"] == query["_id"]), None)


def _call(
    task: AiTask, tokens_in: int, system: str, model: str = MODEL, reask: bool = False
) -> tuple[dict, dict]:
    """A usage row and its stored copy: the system prompt kept as its hash, the conversation's fingerprint."""
    messages = build_conversation(system, f"QUESTION of {tokens_in:,} tokens")
    if reask:
        messages += [{"role": "assistant", "content": "{}"}, {"role": "user", "content": "Again."}]
    stored = [{"role": "system", "content_sha256": "hash"}, *messages[1:]]
    at, call_id = datetime(2026, 10, 30, 14, 2, 31, tzinfo=UTC), ObjectId()
    row = {"_id": call_id, "task": task, "tokens_in": tokens_in, "tokens_out": 6980}
    text = {
        "_id": call_id,
        "task": task,
        "model": model,
        "created_at": at,
        "prompt": stored,
        "prompt_hash": prompt_hash(messages),
    }
    return row, text


def _run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *calls: tuple[dict, dict]
) -> tuple[dict, list[dict]]:
    """main() on these calls: the body it saved, and what tsg_ai_usage was asked."""
    usage, texts = _Collection([row for row, _ in calls]), _Collection([text for _, text in calls])
    database = {extract.USAGE: usage, extract.TEXTS: texts}

    class Client:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def __getitem__(self, name: str) -> dict:
            return database

        def close(self) -> None:
            pass

    monkeypatch.setattr(extract, "MongoClient", Client)
    monkeypatch.setattr(get_settings(), "scenario_chat_model", MODEL)
    monkeypatch.setattr(get_settings(), "scenario_chat_model_thinking", False)
    out = tmp_path / "request.json"
    assert extract.main(["--out", str(out)]) == 0
    return json.loads(out.read_text(encoding="utf-8")), usage.asked


def test_the_biggest_first_ask_is_rebuilt_as_tsg_sent_it(monkeypatch, tmp_path, capsys) -> None:
    """A relevance check of 5,000 input tokens asks for 15,240 with its 10,240 answer cap: more than a writer
    call of 9,000 and its 6,144. Mutation: calls ranked by input alone, a re-ask, another model's call or
    one whose system prompt is not found taken, the fingerprint not checked, TSG's options not sent, litellm's
    own options left in the body, not today's Create scenario rows read."""
    unknown = "A system prompt TSG no longer has."
    body, asked = _run(
        monkeypatch,
        tmp_path,
        _call(AiTask.WRITE_SCENARIO, 9_000, build_writer_system_prompt()),
        _call(AiTask.RELEVANCE_GATE, 5_000, _PLANNER_SYSTEM),
        _call(AiTask.RELEVANCE_GATE, 20_000, _PLANNER_SYSTEM, reask=True),
        _call(AiTask.RELEVANCE_GATE, 30_000, _PLANNER_SYSTEM, model="litellm_proxy/glm-5.3"),
        _call(AiTask.RELEVANCE_GATE, 25_000, unknown),
    )
    assert body == {
        "model": "kimi-k2.5",
        "messages": build_conversation(_PLANNER_SYSTEM, "QUESTION of 5,000 tokens"),
        "max_tokens": CHAT_MAX_OUTPUT_TOKENS[AiTask.RELEVANCE_GATE],
        "stream": False,
        "response_format": {"type": "json_object"},
        "temperature": 0.0,
        "reasoning_effort": "none",
        "chat_template_kwargs": THINKING_OFF_TEMPLATE_KWARGS,
    }
    today = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    assert asked == [
        {
            "created_at": {"$gte": today},
            "module": "threat_scenarios",
            "api": "create_scenario",
            "outcome": "ok",
            "tokens_in": {"$gt": 0},
        }
    ]
    said = " ".join(capsys.readouterr().out.split())
    assert 'at 14:02:31 UTC, in its "Relevance check" step' in said and "its fingerprint matches" in said
    assert "TSG recorded 5,000 input tokens for it and an answer of 6,980 tokens" in said


def test_nothing_to_rebuild_says_so(monkeypatch, tmp_path) -> None:
    """Mutation: a body saved from a call that cannot be rebuilt."""
    with pytest.raises(SystemExit, match="No Create scenario request from today could be rebuilt"):
        _run(monkeypatch, tmp_path, _call(AiTask.RELEVANCE_GATE, 5_000, "Not a prompt of TSG's."))
    assert not (tmp_path / "request.json").exists()
