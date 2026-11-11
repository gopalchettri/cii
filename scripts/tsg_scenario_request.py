"""The biggest request a TSG Create scenario sent the AI today, rebuilt exactly as TSG sent it, saved as a
JSON request body for scripts/ai_limit_proof.py. Read-only on MongoDB: the usage rows (tsg_ai_usage) say which
call was biggest (its input tokens plus its answer cap), its stored copy (tsg_ai_call_texts) gives its
messages, its system prompt (stored as a hash) is found among TSG's own scenario prompts, and the whole
conversation is checked against the fingerprint TSG stored when it sent it. Only a first ask (system prompt
and question) is taken, and only one the module's own model answered. Runs where the app runs: an API pod, in
/app.

  python scripts/tsg_scenario_request.py --out /tmp/tsg_request.json

"""

from __future__ import annotations

import argparse
import importlib
import json
import pkgutil
import sys
import textwrap
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path.cwd()))  # the project folder, or /app in a pod

from pymongo import MongoClient  # noqa: E402
from pymongo.database import Database  # noqa: E402

import app.domain.scenario as scenario_code  # noqa: E402
from app.ai.chat import _profile_of  # noqa: E402, PLC2701 - the profile TSG's own chat model is built with
from app.ai.chat_messages import build_request_options, prompt_hash  # noqa: E402
from app.ai.module_chat import module_chat  # noqa: E402
from app.core.config import get_settings  # noqa: E402
from app.core.constants import CHAT_MAX_OUTPUT_TOKENS, AiOutcome, AiTask, ChatModule  # noqa: E402
from app.core.constants.ai_activities import ACTIVITY_INFO  # noqa: E402
from app.core.constants.job_modules import Module  # noqa: E402
from app.models.ai.module_chat import ModuleChat  # noqa: E402

USAGE, TEXTS = "tsg_ai_usage", "tsg_ai_call_texts"
READ_MS = 60_000  # one MongoDB read's longest time
LOOKED_AT = 20  # the biggest calls tried, for one that can be rebuilt
NOT_SENT = ("timeout", "allowed_openai_params")  # litellm's own options: not in the request body
STEPS = {str(task): about for (_, task), about in ACTIVITY_INFO.items()}  # 'relevance_gate' -> (name, what)
WIDTH = 100


def biggest_calls(database: Database, since: datetime) -> list[dict[str, Any]]:
    """Since `since`, the answered Create scenario chat calls, biggest first: input tokens plus answer cap."""
    asked = {
        "created_at": {"$gte": since},
        "module": Module.THREAT_SCENARIOS,
        "api": "create_scenario",
        "outcome": AiOutcome.OK,
        "tokens_in": {"$gt": 0},
    }
    rows = database[USAGE].find(asked, {"task": 1, "tokens_in": 1, "tokens_out": 1}, max_time_ms=READ_MS)
    return sorted(
        rows, key=lambda row: row["tokens_in"] + CHAT_MAX_OUTPUT_TOKENS.get(row["task"], 0), reverse=True
    )


def system_prompts() -> list[str]:
    """Every text constant of TSG's scenario code, and the writer's system prompt with its word limits."""
    modules = [
        importlib.import_module(f"{scenario_code.__name__}.{found.name}")
        for found in pkgutil.iter_modules(scenario_code.__path__)
    ]
    texts = [value for module in modules for value in vars(module).values() if isinstance(value, str)]
    return [*texts, importlib.import_module(f"{scenario_code.__name__}.write").build_writer_system_prompt()]


def rebuilt(stored: dict[str, Any], prompts: list[str]) -> list[dict[str, Any]] | None:
    """The call's messages as sent: its stored copy with its system prompt put back, when one of `prompts`
    gives the fingerprint TSG stored; None otherwise."""
    for text in prompts:
        messages = [
            {"role": "system", "content": text} if "content_sha256" in message else message
            for message in stored["prompt"]
        ]
        if prompt_hash(messages) == stored.get("prompt_hash"):
            return messages
    return None


def request_body(stored: dict[str, Any], messages: list[dict[str, Any]], chat: ModuleChat) -> dict[str, Any]:
    """The request body TSG sends for this call: the model as the gateway names it, the messages, and the
    options TSG's scenario chat model sends for its task."""
    profile = _profile_of(chat.model, chat.max_input_tokens, chat.max_output_tokens, chat.timeout_seconds)
    options = build_request_options(profile, AiTask(stored["task"]), chat.model, chat.model_thinking)
    extra = options.pop("extra_body", {})  # the OpenAI client puts these in the body itself
    body = {"model": chat.model.split("/", 1)[-1], "messages": messages, **options, **extra}
    return {name: value for name, value in body.items() if name not in NOT_SENT}


def about(row: dict[str, Any], stored: dict[str, Any], body: dict[str, Any]) -> list[str]:
    """Which call this is, in plain words."""
    name, what = STEPS.get(stored["task"], (stored["task"], ""))
    said = (
        "TSG'S REQUEST: the biggest one a Create scenario sent the AI today, at "
        f'{stored["created_at"]:%H:%M:%S} UTC, in its "{name}" step: {what}. Rebuilt from TSG\'s '
        "stored copy of it (tsg_ai_call_texts); its fingerprint matches the one TSG stored when it sent it. "
        f"TSG recorded {row['tokens_in']:,} input tokens for it and an answer of "
        f"{row.get('tokens_out') or 0:,} tokens; TSG asks for an answer of up to {body['max_tokens']:,} "
        "tokens for this step."
    )
    return textwrap.wrap(said, WIDTH, initial_indent=" ", subsequent_indent=" ")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="The biggest request a Create scenario sent today, as sent.")
    parser.add_argument("--out", required=True, help="where to write the request body (JSON)")
    args = parser.parse_args(argv)
    settings = get_settings()
    chat = module_chat(settings, ChatModule.SCENARIO)
    today = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    client: MongoClient[dict] = MongoClient(
        settings.mongo_url, tz_aware=True, serverSelectionTimeoutMS=10_000
    )
    try:
        database, prompts = client[settings.mongo_db], system_prompts()
        for row in biggest_calls(database, today)[:LOOKED_AT]:
            stored = database[TEXTS].find_one({"_id": row["_id"]}, max_time_ms=READ_MS)
            if not stored or stored.get("model") != chat.model or len(stored["prompt"]) != 2:
                continue
            if messages := rebuilt(stored, prompts):
                body = request_body(stored, messages, chat)
                Path(args.out).write_text(json.dumps(body), encoding="utf-8")
                print("\n".join(about(row, stored, body)))
                return 0
    finally:
        client.close()
    raise SystemExit("No Create scenario request from today could be rebuilt: run a Create scenario first.")


if __name__ == "__main__":
    sys.exit(main())
