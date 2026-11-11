"""AI budget evidence: whether the AI gateway's token budget is what slows threat scenario runs. Reads the AI
usage rows (tsg_ai_usage) and the sessions' run times (tsg_sessions) read-only, asks each model TSG uses
(chat, embedding, rerank) one tiny question for the limits its gateway states (scripts/ai_limits_check.py;
never assumed), and with --logs reads the pods' 429 and job log lines. Writes a Markdown report for the
gateway's support team: whether the key's token limit is the bottleneck, what the key may use and what threat
scenarios need in one minute, the proof, then the detail of each session (scripts/ai_budget_sessions.py). It
measures with scripts/ai_budget_measures.py and writes with scripts/ai_budget_report.py. By default it reads
today's runs: from 00:00 UTC to now.

In UAT, one command from the UAT Windows server with oc logged in (it runs this script in an API pod with
today's worker logs, and saves ai_budget_<date>_UTC.md here):
  python scripts/uat_ai_budget_run.py
From the project folder:
  python scripts/ai_budget_evidence.py --env-file .env.uat
      [--since <time>] [--until <time>] [--logs worker1.log worker2.log] [--users 5] [--budget 25000]
      [--out evidence.md]
Inside an API pod (its env already set), with the scripts folder copied in:
  oc cp scripts <pod>:/tmp/scripts
  oc exec <pod> -- python /tmp/scripts/ai_budget_evidence.py > evidence.md
Logs, once per worker pod: oc logs <worker pod> --since=24h > worker1.log"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from ai_budget_measures import USERS, Evidence, attempts_of, minutes_of, sessions_of
from ai_budget_report import report_lines
from ai_limits_check import limit_lines
from dotenv import dotenv_values
from pymongo import MongoClient
from pymongo.database import Database

USAGE, SESSIONS = "tsg_ai_usage", "tsg_sessions"
READ_MS = 120_000  # one MongoDB read's longest time
TIMEOUT_SECONDS = 60
CONNECT_MS = 20_000
ROW_FIELDS = ("created_at", "seconds", "tokens_in", "tokens_out", "task", "model", "outcome", "error_type",
              "module", "api", "request_id", "session_id", "ask_id", "job_task", "attempt")  # fmt: skip
LOG_EVENTS = (
    "ai.call_unavailable",
    "job.not_claimed",
    "ai.slots_busy",
    "ai.request_rate_busy",
    "ai.limit_cut",
)
MODULES = ("SCENARIO", "REMEDIATION", "SERVICE_MAPPER")
SEARCH_MODELS = ("embedding", "rerank")  # CII_EMBEDDING_* and CII_RERANK_*: asked their own kind of question
MODULE_SETTINGS = (
    "CHAT_MODEL",
    "CHAT_TOKENS_PER_MINUTE",
    "CHAT_REQUESTS_PER_MINUTE",
    "MAX_CONCURRENT_AI_CALLS",
)
SHARED_SETTINGS = (
    "CII_AI_BUSY_MAX_WAIT_SECONDS",
    "CII_AI_BUSY_TOTAL_WAIT_SECONDS",
    "CII_MAX_CONCURRENT_AI_CALLS",
)
NO_BUDGET = (
    "The gateway named no tokens-a-minute limit (its answers are above); give the budget with --budget."
)
NO_MONGO = "CII_MONGO_URL is not set: run inside an API pod, or pass --env-file .env.uat."


def read_store(
    database: Database, since: datetime, until: datetime
) -> tuple[list[dict], dict[str, dict[str, float]]]:
    """The usage rows in [since, until), and each session's latest action's stage seconds by its request.
    Read-only: finds with projections."""
    window = {"created_at": {"$gte": since, "$lt": until}}
    rows = list(database[USAGE].find(window, dict.fromkeys(ROW_FIELDS, 1), max_time_ms=READ_MS))
    ids = sorted({row["session_id"] for row in rows if row.get("session_id")})
    fields = {"job.request_id": 1, "timings": 1}
    sessions = database[SESSIONS].find({"_id": {"$in": ids}}, fields, max_time_ms=READ_MS)
    return rows, {
        session["job"]["request_id"]: session["timings"]
        for session in sessions
        if (session.get("job") or {}).get("request_id") and session.get("timings")
    }


def read_logs(paths: list[str]) -> list[dict]:
    """The LOG_EVENTS lines of saved pod logs, one JSON object a line (PowerShell's UTF-16 too)."""
    found = []
    for path in paths:
        raw = Path(path).read_bytes()
        text = (
            raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("utf-8", "replace")
        )
        for line in text.splitlines():
            try:  # `oc logs --timestamps` puts the time before the object
                entry = json.loads(line[line.index("{") :])
            except ValueError:
                continue
            if isinstance(entry, dict) and entry.get("event") in LOG_EVENTS:
                found.append(entry)
    return found


def gateways(env: Mapping[str, str | None]) -> dict[tuple[str, str, str], list[str]]:
    """Each distinct (gateway, key, model) TSG uses -> who uses it: 'scenario', 'scenario fallback',
    'embedding', 'rerank'."""
    sys.path.insert(0, str(Path.cwd()))  # the project folder, or /app in a pod
    from app.core.constants import ChatModule  # noqa: PLC0415

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
    for search in SEARCH_MODELS:  # on a gateway they share its limits too; a local model has no base URL
        base, key, model = ((env.get(f"CII_{search.upper()}_{name}") or "").strip()
                            for name in ("BASE_URL", "API_KEY", "MODEL"))  # fmt: skip
        if base and key and model:
            found.setdefault((base.rstrip("/"), key, model), []).append(search)
    return found


def origin(base: str) -> str:
    """'https://llmapi.govai.ae' of a base URL: its scheme, host and port, never a path or a password."""
    parts = urlsplit(base)
    return f"{parts.scheme}://{parts.hostname}" + (f":{parts.port}" if parts.port else "")


def live_limits(env: Mapping[str, str | None]) -> tuple[list[str], dict[str, list], datetime]:
    """The limits each model's gateway states now: its answers as lines, each model (its gateway and the
    modules using it) -> its ai_limits_check.Limit list, and when it was asked."""
    checked = datetime.now(UTC)
    lines, found = [f"{checked:%Y-%m-%d %H:%M:%S} UTC  limits check, the gateway's answers:"], {}
    for (base, key, model), users in gateways(env).items():
        name, where = model.split("/", 1)[-1], origin(base)  # litellm_proxy/kimi-k2.5 -> kimi-k2.5
        kind = next((user for user in users if user in SEARCH_MODELS), "chat")
        auth = {"Authorization": f"Bearer {key}"}
        with httpx.Client(base_url=base, headers=auth, timeout=TIMEOUT_SECONDS) as client:
            asked, stated = limit_lines(client, name, kind)
        lines += [f"{' / '.join(users)}  {name} @ {where}", *asked]
        found[f"{name} @ {where} ({', '.join(users)})"] = stated
    return lines, found, checked


def answer_caps(env: Mapping[str, str | None]) -> dict[str, int]:
    """Each chat task's answer cap (CII_ANSWER_TOKENS_<TASK>), as the pods read it."""
    os.environ.update({k: v for k, v in env.items() if k.startswith("CII_ANSWER_TOKENS_") and v})
    sys.path.insert(0, str(Path.cwd()))  # the project folder, or /app in a pod
    from app.core.constants import CHAT_MAX_OUTPUT_TOKENS  # noqa: PLC0415

    return {str(task): cap for task, cap in CHAT_MAX_OUTPUT_TOKENS.items()}


def settings_lines(env: Mapping[str, str | None], caps: dict[str, int]) -> list[str]:
    """TSG's own pacing, slots, 429 waits and answer caps."""
    names = [f"CII_{module}_{name}" for module in MODULES for name in MODULE_SETTINGS] + list(SHARED_SETTINGS)
    return [f"{name}={env.get(name) or '(not set)'}" for name in names] + [
        f"answer cap {task}: {cap:,}" for task, cap in caps.items()
    ]


def utc_time(text: str) -> datetime:
    """An ISO time; one without a zone is UTC."""
    moment = datetime.fromisoformat(text)
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Whether the gateway's token budget slows scenario runs.")
    now = datetime.now(UTC)
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    parser.add_argument("--since", type=utc_time, default=today, help="ISO time (default: today, 00:00 UTC)")
    parser.add_argument("--until", type=utc_time, default=now, help="ISO time (default: now)")
    parser.add_argument("--logs", nargs="+", default=None, help="saved `oc logs` of the worker pods")
    parser.add_argument("--users", type=int, default=USERS, help=f"users at once, for the capacity ({USERS})")
    parser.add_argument("--budget", type=int, help="tokens a minute, only when the gateway names none")
    parser.add_argument("--env-file", help="read the CII_ lines from this file (default: the environment)")
    parser.add_argument("--out", help="also write the report to this file (UTF-8)")
    args = parser.parse_args(argv)
    for path in [args.env_file, *(args.logs or [])]:
        if path and not Path(path).is_file():
            raise SystemExit(f"No such file: {path}")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    env: Mapping[str, str | None] = dotenv_values(args.env_file) if args.env_file else dict(os.environ)
    if not env.get("CII_MONGO_URL"):
        raise SystemExit(NO_MONGO)
    caps = answer_caps(env)
    gateway, limits, checked = live_limits(env)
    stated = [lim.value for found in limits.values() for lim in found if lim.kind == "tokens" and lim.value]
    budget = min(stated, default=None) or args.budget
    if not budget:
        print("\n".join(gateway), file=sys.stderr)
        raise SystemExit(NO_BUDGET)
    client: MongoClient[dict] = MongoClient(env["CII_MONGO_URL"], tz_aware=True,
                                            readPreference="secondaryPreferred",
                                            serverSelectionTimeoutMS=CONNECT_MS)  # fmt: skip
    try:
        rows, ui = read_store(client[env.get("CII_MONGO_DB") or "cii_tsg"], args.since, args.until)
    finally:
        client.close()
    attempts = attempts_of(rows, caps)
    minutes = minutes_of(attempts)
    sessions = sessions_of(attempts, minutes, budget, ui)
    logs = read_logs(args.logs) if args.logs else None
    found = (bool(stated), checked, limits, gateway, logs, settings_lines(env, caps))
    evidence = Evidence(args.since, args.until, attempts, minutes, sessions, budget, *found, args.users)
    text = "\n".join(report_lines(evidence))
    print(text)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
