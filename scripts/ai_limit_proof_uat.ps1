<#
.SYNOPSIS
    Proof, for the support team, that the UAT AI gateway's token limit refuses TSG's own Create scenario
    requests when several users send them at once.

.DESCRIPTION
    One file: it carries two scripts inside it and runs both in the UAT api pod, with TSG's own scenario key
    (the key is never copied; only its last 4 characters are shown).
    1. tsg_scenario_request.py picks the biggest request a Create scenario sent the AI today and rebuilds it
       exactly as TSG sent it, from TSG's stored copy (checked against the fingerprint TSG stored with it).
    2. ai_limit_proof.py reads the key's tokens-a-minute limit from the gateway's answer, sends that request
       5 times at the same moment (as 5 users clicking Create scenario at once), waits a minute, sends it once
       alone, and shows every request and response word for word.
    Each answered request is real work on the shared budget: run it when nobody else is using UAT.
    Run a Create scenario in UAT first, today. Log in first: oc login.
    Shows the screen and saves it to ai_limit_proof_<time>.txt in the current folder.

.EXAMPLE
    .\ai_limit_proof_uat.ps1
#>

$Namespace = 'ai-threatgen'
$Gateway = 'https://llmapi.govai.ae'
$Body = '/tmp/tsg_request.json'

# tsg_scenario_request.py, word for word (tests/test_ai_limit_proof.py keeps the two the same).
$Request = @'
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
    return [*texts, importlib.import_module(f"{scenario_code.__name__}.write").writer_system_prompt()]


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
'@

# ai_limit_proof.py, word for word (tests/test_ai_limit_proof.py keeps the two the same).
$Proof = @'
"""Proof that an AI gateway enforces an API key's tokens-a-minute limit on a real request, as evidence anyone
can check. One small request reads the limit from the response headers. Then the request in --body (a JSON
request body, such as one an application sent) goes 5 times at the same moment, as 5 users sending it at once
would; a minute after the last answer it goes once more, alone. The screen shows a summary, then every request
and the gateway's whole response, word for word: the request body in full the first time, and for each other
request its fingerprint, the same. Hidden, and the screen says where: the key (all but its last 4 characters),
whose budget a 429 names, and cookie values. Each request the gateway answers is real work for the model, on
the shared budget: run it when nobody else is using the gateway. Stdlib only; plain ASCII, so PowerShell can
pipe it into a pod.

  python ai_limit_proof.py --base-url https://gateway.example.com --body request.json --key-env MY_KEY

The key is read from the environment variable --key-env names, never from the command line. Exit code: 0 the
gateway refused a request with HTTP 429, 1 it refused none, 2 no token limit was read."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import textwrap
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple

TRIES = 5  # the request sent this many times at the same moment
SMALL = {"messages": [{"role": "user", "content": "Reply with OK."}], "max_tokens": 5}  # reads the limit
MINUTE_SECONDS = 61  # waited after the last answer: the request alone starts on a new minute
#: Whose budget a LiteLLM 429 names: the name after the colon is replaced on screen.
WHOSE = re.compile(r"(Rate limit exceeded for \w+:)\s*[^.\s\"]+")
LIMIT_HEADER = re.compile(r"^x-ratelimit-(?:(\w+)-)?limit-tokens$")
LEFT_HEADER = re.compile(r"^x-ratelimit-(?:(\w+)-)?remaining-tokens$")
HIDDEN_HEADERS = ("set-cookie",)  # the gateway's session cookies: their values are not evidence
TIMEOUT_SECONDS = 180
WIDTH = 100
INDENT = "    "
ROW = " {:>2}  {:<12}  {:<9}  {:<26}  {:>12}  {:>11}  {:>8}"  # the summary table's columns


class Exchange(NamedTuple):
    """One HTTP request to the gateway and its response, as sent and received."""

    url: str
    sent: bytes  # the request body, byte for byte
    sent_at: datetime
    seconds: float
    status: int  # 0: no response
    reason: str
    headers: list[tuple[str, str]]  # the response's, in the gateway's own order and spelling
    text: str  # the response body, or why there is none


def ask(base: str, key: str, body: dict) -> Exchange:
    """One POST to the gateway's chat page, timed."""
    url, data = f"{base.rstrip('/')}/chat/completions", json.dumps(body).encode()
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    request = urllib.request.Request(url, data, headers, method="POST")  # noqa: S310 - main() takes http(s)
    sent_at, started = datetime.now(timezone.utc), time.monotonic()  # noqa: UP017 - datetime.UTC needs 3.11
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as answer:  # noqa: S310 - the gateway
            status, reason, got, raw = answer.status, answer.reason, answer.headers.items(), answer.read()
    except urllib.error.HTTPError as refused:
        status, reason, got, raw = refused.code, refused.reason, refused.headers.items(), refused.read()
    except (urllib.error.URLError, OSError) as exc:
        return Exchange(url, data, sent_at, time.monotonic() - started, 0, "", [], f"not reached: {exc}")
    text = raw.decode("utf-8", "replace")
    return Exchange(url, data, sent_at, time.monotonic() - started, status, str(reason), list(got), text)


def ask_together(base: str, key: str, body: dict) -> list[Exchange]:
    """The request TRIES times at the same moment, each on its own thread, in the order they were sent."""
    answers: list[Exchange] = []
    threads = [threading.Thread(target=lambda: answers.append(ask(base, key, body))) for _ in range(TRIES)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return sorted(answers, key=lambda exchange: exchange.sent_at)


def stated(headers: list[tuple[str, str]], pattern: re.Pattern[str]) -> dict[str, int]:
    """Each number the headers state that `pattern` names, by whose it is ('model' when none is named)."""
    found = {}
    for header, value in headers:
        named = pattern.match(header.lower())
        if named and value.isdigit():
            found[named.group(1) or "model"] = int(value)
    return found


def prompt_tokens(exchange: Exchange) -> int | None:
    """The input tokens the model counted for an answered request; None when it gave no count."""
    try:
        return int(json.loads(exchange.text)["usage"]["prompt_tokens"])
    except (ValueError, KeyError, TypeError):
        return None


def masked(key: str) -> str:
    """The key as shown: all but its last 4 characters hidden."""
    return f"<hidden, ends ...{key[-4:]}>" if len(key) > 12 else "<hidden>"


def block(text: str) -> list[str]:
    """Text indented, each of its lines whole: nothing added, nothing cut (the console wraps it on screen)."""
    return [INDENT + line for line in text.splitlines() or [""]]


def exchange_lines(title: str, key: str, exchange: Exchange, repeat: bool = False) -> list[str]:
    """One request as sent and the gateway's response as received: status, every header, the whole body. A
    `repeat` of REQUEST 1 shows its body as its size and fingerprint."""
    sent, size = f"{exchange.sent_at:%Y-%m-%d %H:%M:%S.%f}"[:-3], f"{len(exchange.sent):,} bytes"
    fingerprint = f"SHA-256 {hashlib.sha256(exchange.sent).hexdigest()}"
    body = (
        [f"{INDENT}Body: the same {size} as REQUEST 1 ({fingerprint})"]
        if repeat
        else [f"{INDENT}Body, exactly as sent ({size}, {fingerprint}):", *block(exchange.sent.decode())]
    )
    lines = [
        f" {title}: REQUEST sent {sent} UTC",
        f"{INDENT}POST {exchange.url}",
        f"{INDENT}Authorization: Bearer {masked(key)}",
        f"{INDENT}Content-Type: application/json",
        *body,
    ]
    if exchange.status == 0:
        return [*lines, f" {title}: NO RESPONSE after {exchange.seconds:.2f} s", *block(exchange.text), ""]
    text = WHOSE.sub(r"\1 <id hidden>", exchange.text)
    note = " (whose budget replaced with <id hidden>)" if text != exchange.text else ""
    shown = [(h, "<value hidden>" if h.lower() in HIDDEN_HEADERS else v) for h, v in exchange.headers]
    return [
        *lines,
        f" {title}: RESPONSE after {exchange.seconds:.2f} s",
        f"{INDENT}HTTP {exchange.status} {exchange.reason}",
        *(f"{INDENT}{header}: {value}" for header, value in shown),
        f"{INDENT}Body, word for word{note}:",
        *block(text),
        "",
    ]


def summary_row(number: int, how: str, exchange: Exchange) -> str:
    """One request in the summary table."""
    answer = f"HTTP {exchange.status} {exchange.reason}" if exchange.status else "no response"
    counted, left = prompt_tokens(exchange), stated(exchange.headers, LEFT_HEADER)
    return ROW.format(
        str(number),
        f"{exchange.sent_at:%H:%M:%S.%f}"[:-3],
        how,
        answer[:26],
        f"{counted:,}" if counted else "-",
        f"{min(left.values()):,}" if left else "-",
        f"{exchange.seconds:.2f} s",
    )


def size_lines(limit: int, body: dict, sent: list[Exchange]) -> tuple[int, list[str]]:
    """The tokens one request asks for (its input, as the model counted it, plus its answer cap), in words."""
    counted = next((tokens for tokens in map(prompt_tokens, sent) if tokens), None)
    tokens, how = (counted, "the model counted") if counted else (len(sent[0].sent) // 4, "about (est.)")
    cap = int(body.get("max_tokens") or 0)
    said = (
        f" One request: {len(sent[0].sent):,} bytes; {how} {tokens:,} input tokens, and it asks for an "
        f"answer of up to {cap:,}: {tokens + cap:,} tokens, {(tokens + cap) / limit:.0%} of the {limit:,} "
        f"the key may use in a minute. {TRIES} sent at once ask for {TRIES * (tokens + cap):,}, "
        f"{TRIES * (tokens + cap) / limit:.1f} times that limit."
    )
    return tokens + cap, textwrap.wrap(said, WIDTH, subsequent_indent=" ")


def result(limit: int, whose: str, need: int, together: list[Exchange], alone: Exchange) -> list[str]:
    """What the requests show, in plain words."""
    refused, answered = (sum(e.status == code for e in together) for code in (429, 200))
    if not refused and alone.status != 429:
        said = (
            f"NOT SHOWN. The gateway refused none of the {TRIES + 1} requests, so this run does not show the "
            "limit being enforced."
        )
    else:
        why = (
            "one request alone asks for more than the limit"
            if need > limit
            else "others were using the budget"
        )
        later = {200: "answered", 429: f"refused too ({why})"}.get(
            alone.status, f"not answered ({alone.status})"
        )
        failed = TRIES - refused - answered
        otherwise = f", and {failed} failed otherwise" if failed else ""
        said = (
            f"ENFORCED. Of {TRIES} requests sent at the same moment, the gateway answered {answered} and "
            f"refused {refused} with HTTP 429{otherwise}. This key may use {limit:,} tokens a minute (the "
            f"{whose} limit). Sent alone a minute later, the same request was {later}."
        )
    return textwrap.wrap(f" RESULT  {said}", WIDTH, subsequent_indent=" " * 9)


def proof(
    base: str, key: str, body: dict, sleep: Callable[[float], None] = time.sleep
) -> tuple[list[str], int]:
    """The whole screen, and the exit code."""
    rule = "=" * WIDTH
    head = [
        rule,
        " PROOF: the AI gateway enforces this API key's token limit",
        f" Gateway {base}   Model {body['model']}",
    ]
    first = ask(base, key, {"model": body["model"], **SMALL})
    limits = {whose: value for whose, value in stated(first.headers, LIMIT_HEADER).items() if value}
    if not limits:
        why = " RESULT  The response stated no tokens-a-minute limit, so the request was not sent."
        return [*head, rule, why, rule, *exchange_lines("LIMIT CHECK", key, first)], 2
    whose, limit = min(limits.items(), key=lambda item: item[1])
    together = ask_together(base, key, body)
    sleep(MINUTE_SECONDS)
    sent = [*together, ask(base, key, body)]
    need, table = summary_lines(limit, whose, body, sent)
    details = [
        *exchange_lines("LIMIT CHECK", key, first),
        *(line for n, e in enumerate(sent, 1) for line in exchange_lines(f"REQUEST {n}", key, e, n > 1)),
    ]
    screen = [*head, rule, *table, rule, *result(limit, whose, need, together, sent[-1]), rule]
    screen += [" EVERY REQUEST AND RESPONSE, WORD FOR WORD", rule, *details, rule]
    return screen, 0 if any(e.status == 429 for e in sent) else 1


def summary_lines(limit: int, whose: str, body: dict, sent: list[Exchange]) -> tuple[int, list[str]]:
    """The tokens one request asks for, and the summary: the limit, the request's size and the table."""
    need, sizes = size_lines(limit, body, sent)
    hows = ["at once"] * TRIES + ["alone"]
    return need, [
        f" Limit read from the gateway: {limit:,} tokens a minute (the {whose} limit, the lowest stated).",
        *sizes,
        f" Sent the request {TRIES} times at the same moment; {MINUTE_SECONDS} s after the last "
        "answer, sent it once alone.",
        "",
        ROW.format("#", "Sent (UTC)", "Sent", "Gateway's answer", "Input tokens", "Tokens left", "Took"),
        *(summary_row(n, how, e) for n, (how, e) in enumerate(zip(hows, sent, strict=True), 1)),
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Proof that the AI gateway enforces a key's token limit.")
    parser.add_argument("--base-url", required=True, help="the gateway's OpenAI-compatible address")
    parser.add_argument("--body", required=True, help="the request to send: a JSON chat request body")
    parser.add_argument(
        "--key-env", default="AI_GATEWAY_KEY", help="the environment variable holding the key"
    )
    args = parser.parse_args(argv)
    if not args.base_url.startswith(("https://", "http://")):
        raise SystemExit(f"Not a gateway address: {args.base_url} (it starts https:// or http://).")
    key = (os.environ.get(args.key_env) or "").strip()
    if not key:
        raise SystemExit(f"No key: set {args.key_env}.")
    body = json.loads(Path(args.body).read_text(encoding="utf-8"))
    if not isinstance(body, dict) or not body.get("model") or not body.get("messages"):
        raise SystemExit(f"Not a chat request body: {args.body} (it needs a model and messages).")
    lines, code = proof(args.base_url, key, body)
    print("\n".join(line.replace(key, masked(key)) for line in lines))
    return code


if __name__ == "__main__":
    sys.exit(main())
'@

$Pod = oc get pods -n $Namespace --field-selector=status.phase=Running -o name |
    Where-Object { $_ -like 'pod/api-*' } | Select-Object -First 1
if (-not $Pod) {
    "No running api pod: check 'oc login' and that 'oc get pods -n $Namespace' lists one."
    exit 1
}
$About = $Request | oc exec -i -n $Namespace $Pod -- sh -c "cd /app && python - --out $Body"
if ($LASTEXITCODE -ne 0) {
    "TSG's Create scenario request could not be read (the reason is above). Run a Create scenario first, today."
    exit 1
}
$Screen = $Proof | oc exec -i -n $Namespace $Pod -- python - --base-url $Gateway --body $Body `
    --key-env CII_SCENARIO_CHAT_API_KEY
$Code = $LASTEXITCODE
oc exec -n $Namespace $Pod -- rm -f $Body | Out-Null
if ($Code -gt 2 -or -not $Screen) {
    $Screen = @($Screen) + "(the proof did not run: the reason is above)"
}
$Screen = @('=' * 100) + @($About) + @($Screen)
$File = "ai_limit_proof_$(Get-Date -Format yyyyMMdd_HHmmss).txt"
$Screen | Out-File $File -Encoding utf8
$Screen
"Saved to $((Resolve-Path $File).Path)"
