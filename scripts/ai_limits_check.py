"""AI limits check: each module's chat model's tokens- and requests-a-minute limits, as its gateway tells
them (answer headers; a LiteLLM gateway also /key/info, /team/info and /model/info), and the
CII_<MODULE>_CHAT_TOKENS_PER_MINUTE to set. Read-only: one 5-token question per model; never prints the key
or whose it is.

From the project folder: python scripts/ai_limits_check.py [--env-file .env.uat]
Inside a pod (its env already set): oc exec -i <pod> -- python - < scripts/ai_limits_check.py"""

from __future__ import annotations

import argparse
import os
import sys
from collections import Counter
from collections.abc import Mapping
from pathlib import Path

import httpx
from dotenv import dotenv_values

sys.path.insert(0, str(Path.cwd()))  # the project folder, or /app in a pod
from app.ai.retry_waits import gateway_limit  # noqa: E402
from app.core.constants import ChatModule  # noqa: E402

LITELLM_PREFIX = "litellm_proxy/"
LIMIT_WORDS = ("tpm", "rpm", "max_parallel", "max_input_tokens")  # the JSON fields that are limits
HEADER_WORDS = ("ratelimit", "retry-after", "rate_limit_type")  # the answer headers that are limits
SAFETY_SHARE = 0.9  # our own pacing a little below the gateway's limit
TIMEOUT_SECONDS = 60
NOTHING_FOUND = "no tokens-a-minute limit found: a 429 names it (oc logs <pod> | findstr limit_scope)"


def gateways(env: Mapping[str, str | None]) -> dict[tuple[str, str, str], list[str]]:
    """Each distinct (gateway, key, model) the modules use -> who uses it: 'scenario', 'scenario fallback'."""
    found: dict[tuple[str, str, str], list[str]] = {}
    for module in ChatModule:
        base, key, model, fallback = (
            (env.get(f"CII_{module.upper()}_CHAT_{name}") or "").strip()
            for name in ("BASE_URL", "API_KEY", "MODEL", "FALLBACK_MODEL")
        )
        if not (base and key and model):
            print(f"Skipped {module}: its chat URL, key or model is not set.", file=sys.stderr)
            continue
        for used, user in ((model, str(module)), (fallback, f"{module} fallback")):
            if used:
                found.setdefault((base.rstrip("/"), key, used), []).append(user)
    return found


def limit_fields(answer: object, path: str = "") -> list[tuple[str, object]]:
    """Every field of a JSON answer whose name holds a LIMIT_WORDS word, as (dotted path, value)."""
    if isinstance(answer, list):
        return [field for item in answer for field in limit_fields(item, path)]
    if not isinstance(answer, dict):
        return []
    found: list[tuple[str, object]] = []
    for name, value in answer.items():
        where = f"{path}.{name}" if path else str(name)
        if any(word in str(name) for word in LIMIT_WORDS):
            found.append((where, value))
        else:
            found += limit_fields(value, where)
    return found


def read_json(client: httpx.Client, path: str, params: dict[str, str] | None = None) -> object:
    """A gateway's JSON answer, or why there is none, in words."""
    try:
        answer = client.get(path, params=params)
    except httpx.HTTPError as exc:
        return f"not reached: {type(exc).__name__}"
    if answer.status_code in (401, 403):
        return f"HTTP {answer.status_code}: this key may not read it"
    if answer.is_error:
        return f"HTTP {answer.status_code}"
    try:
        return answer.json()
    except ValueError:
        return "answered, but not with JSON"


def litellm_sections(client: httpx.Client, name: str) -> list[tuple[str, object]]:
    """(label, JSON or why not) for the key, its team and the model, on a LiteLLM gateway."""
    key = read_json(client, "/key/info")
    key_info = key.get("info", key) if isinstance(key, dict) else key
    team_id = key_info.get("team_id") if isinstance(key_info, dict) else None
    if team_id:
        team = read_json(client, "/team/info", {"team_id": team_id})
    else:  # a key whose own info is refused may still have a team: its budget shows in the answer headers
        team = (
            "the key has no team" if isinstance(key_info, dict) else "not known: the key's info was not read"
        )
    models = read_json(client, "/model/info")
    if isinstance(models, dict):
        models = [entry for entry in models.get("data", []) if entry.get("model_name") == name]
    return [
        ("key", key_info),
        ("team", team.get("team_info", team) if isinstance(team, dict) else team),  # not its members' keys
        ("model", models),
    ]


def section_line(label: str, answer: object) -> tuple[str, list[int]]:
    """'  team    tpm_limit 200000, rpm_limit none set' and the tokens-a-minute limits in it."""
    if isinstance(answer, str):
        return f"  {label:7} {answer}", []
    fields = limit_fields(answer)
    shown = ", ".join(f"{path} {'none set' if value is None else value}" for path, value in fields)
    tokens = [
        value
        for path, value in fields
        if "tpm" in path.rsplit(".", 1)[-1] and isinstance(value, int) and value > 0
    ]
    return f"  {label:7} {shown or 'no limit fields'}", tokens


def answer_lines(client: httpx.Client, name: str) -> tuple[list[str], list[int]]:
    """One 5-token question: the limit headers of its answer, and a 429's budget."""
    question = {"model": name, "messages": [{"role": "user", "content": "hi"}], "max_tokens": 5}
    try:
        answer = client.post("/chat/completions", json=question)
    except httpx.HTTPError as exc:
        return [f"  answer  not reached: {type(exc).__name__}"], []
    limits = {
        header.lower(): value
        for header, value in answer.headers.items()
        if any(word in header.lower() for word in HEADER_WORDS)
    }
    shown = ", ".join(f"{header} {value}" for header, value in sorted(limits.items())) or "no limit headers"
    lines = [f"  answer  HTTP {answer.status_code}", f"  headers {shown}"]
    tokens = [
        int(value) for header, value in limits.items() if header.endswith("limit-tokens") and value.isdigit()
    ]
    if answer.status_code == 429:
        budget = gateway_limit(RuntimeError(answer.text))  # its scope and numbers only, never whose
        lines.append(f"  429     {budget or 'names no budget'}")
        if budget and limits.get("rate_limit_type") == "tokens":
            tokens.append(int(budget["limit"]))
    return lines, tokens


def report_lines(client: httpx.Client, model: str, users: list[str], sharing: int = 1) -> list[str]:
    """One model on one gateway: every limit found, then the CII_..._TOKENS_PER_MINUTE to set, the lowest
    limit split between the `sharing` modules on this key."""
    name = model.split("/", 1)[-1]  # litellm_proxy/kimi-k2.5 -> kimi-k2.5, as the gateway names it
    lines, tokens = [f"{' / '.join(users)}  {name} @ {client.base_url.host}"], []
    if model.startswith(LITELLM_PREFIX):
        for label, answer in litellm_sections(client, name):
            line, found = section_line(label, answer)
            lines.append(line)
            tokens += found
    asked, found = answer_lines(client, name)
    lines += asked
    tokens += found
    if not tokens:
        return [*lines, f"  {NOTHING_FOUND}", ""]
    lowest = min(tokens)
    lines.append(f"  lowest tokens-a-minute found: {lowest:,}, shared by the {sharing} module(s) on this key")
    # ponytail: split by key, so a team budget over several keys is not seen; the 429 log shows it.
    each = round(lowest * SAFETY_SHARE / sharing)
    for user in users:
        if not user.endswith("fallback"):  # a fallback has no tokens-a-minute setting of its own
            lines.append(f"  -> set CII_{user.upper()}_CHAT_TOKENS_PER_MINUTE to about {each:,}")
    return [*lines, ""]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Each module's chat model limits, as its gateway says.")
    parser.add_argument("--env-file", help="read the CII_ lines from this file (default: the environment)")
    env_file = parser.parse_args(argv).env_file
    if env_file and not Path(env_file).is_file():
        raise SystemExit(f"No such file: {env_file}")
    env: Mapping[str, str | None] = dotenv_values(env_file) if env_file else os.environ
    found = gateways(env)
    sharing = Counter(key for (_, key, _), users in found.items() for user in users if "fallback" not in user)
    for (base, key, model), users in found.items():
        auth = {"Authorization": f"Bearer {key}"}
        with httpx.Client(base_url=base, headers=auth, timeout=TIMEOUT_SECONDS) as client:
            print("\n".join(report_lines(client, model, users, max(sharing[key], 1))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
