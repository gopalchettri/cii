"""UAT AI gateway check: what the gateway says about each AI model's limits, whether reranks count toward the
token budget, and how the reranker and the embedding model answer when many calls go at once. The key is never
printed. UAT's reranker works best at 8 calls at once and drops connections above about 10, with no 429 (the
owner's probe, litellm_probe_oc.py, 16 Nov 2026); this script stops its load only at a 429, so on UAT pass
--steps 1,4,8. TSG itself caps the reranker and embedding calls at 8 (CII_MAX_CONCURRENT_AI_CALLS).

Run it where TSG runs, so it uses TSG's own settings (the CII_* names) and key:
  UAT Windows server, in the TSG folder (it reads .env):  python uat_gateway_check.py
  OpenShift api pod (PowerShell, after oc login):
    Get-Content uat_gateway_check.py -Raw | oc exec -i -n ai-threatgen deploy/api -- python -
Options: --steps 1,10,30,60 (calls at once, a minute apart), --pause 60, --env-file .env, --no-load.
The default steps take about 8 minutes and may use about a million tokens: run it when UAT is quiet.
Python 3.8+, standard library only. Prints the report and saves it as gateway_check_<UTC time>.txt."""

from __future__ import annotations

import argparse
import json
import os
import re
import ssl
import statistics
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import NamedTuple

MODULES = (  # (kind, setting prefix): TSG's own setting names, the same in .env and in the pods
    ("chat", "CII_SCENARIO_CHAT"),
    ("chat", "CII_REMEDIATION_CHAT"),
    ("chat", "CII_SERVICE_MAPPER_CHAT"),
    ("embedding", "CII_EMBEDDING"),
    ("rerank", "CII_RERANK"),
)
TIMEOUT_SECONDS = 120  # TSG's own for qwen3-reranker-8b and qwen3-embedding-8b (app/ai/profiles.py)
DOCUMENTS = 40  # CONTROL_CANDIDATES: the library controls one control search reranks
#: Answer headers that state a limit; LiteLLM's rerank route sends only x-litellm-key-* (rpm/tpm-limit).
LIMIT_WORDS = ("ratelimit", "retry-after", "rate_limit", "x-litellm-key-")
#: The fields of a gateway page that are limits.
FIELD = re.compile(r"rpm|tpm|limit|parallel|max_(input_|output_)?tokens|budget")
SCENARIO = (
    "Scenario {tag}: an attacker sends a phishing e-mail to a finance clerk, captures the clerk's "
    "password and MFA session token through a fake sign-in page, then uses the trusted session to read "
    "company e-mail, adds a mailbox forwarding rule and asks for a supplier payment to a bank account the "
    "attacker controls."
)
CONTROL = (
    "Control {tag}-{i}: {topic}. The organisation defines, documents and applies this control on every "
    "system that stores or processes sensitive information, reviews it at least once a year and after "
    "each major change, names an owner who checks that it works as intended, and keeps evidence of every "
    "review."
)
TOPICS = (
    "multi-factor authentication for remote and privileged access",
    "filtering of phishing e-mail and malicious links",
    "security awareness training on phishing for all staff",
    "conditional access and session token protection",
    "monitoring of mailbox rules and unusual sign-ins",
    "approval of supplier bank account changes by a second person",
    "least privilege for finance and payment systems",
    "logging and alerting of administrator actions",
    "incident response plan for account compromise",
    "backup and recovery of business e-mail",
)
QUERY_INSTRUCTION = "Instruct: Given a threat scenario, retrieve the security controls that reduce it\nQuery:"
KEYS: list[str] = []  # every key read, hidden from all output


class Gateway(NamedTuple):
    base: str
    key: str
    header: str  # CII_AI_KEY_HEADER: the gateway reads the key from it, as TSG sends it

    def api(self, path: str) -> str:
        root = self.base.rstrip("/")
        return (root if root.endswith("/v1") else root + "/v1") + path

    def page(self, path: str) -> str:
        root = self.base.rstrip("/")
        return (root[:-3] if root.endswith("/v1") else root) + path


class Target(NamedTuple):
    kind: str
    model: str  # as the gateway names it
    gateway: Gateway


class Answer(NamedTuple):
    status: int  # 0: no answer (timeout, refused, TLS)
    headers: dict
    body: object
    text: str  # the start of the answer, or why there was none
    seconds: float


def tls() -> ssl.SSLContext:
    """The pods' certifi bundle when there is one and no SSL_CERT_FILE; else the system's own store."""
    try:
        import certifi  # noqa: PLC0415 - optional

        return ssl.create_default_context(cafile=None if os.environ.get("SSL_CERT_FILE") else certifi.where())
    except ImportError:
        return ssl.create_default_context()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect comes back as its own status: urllib would send the key headers on to the new host."""

    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


# ponytail: always direct, as TSG goes (CII_AI_BYPASS_PROXY: the UAT server's proxy cannot reach the gateway)
OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=tls()), NoRedirect()
)


def hide(text: str) -> str:
    """`text` with every key, and anything shaped like one, replaced by ***."""
    for key in sorted(set(KEYS), key=len, reverse=True):
        text = text.replace(key, "***")
    return re.sub(r"sk-[A-Za-z0-9_\-]{6,}", "sk-***", text)


def read_all(error: urllib.error.HTTPError) -> bytes:
    try:
        return error.read()
    except Exception:  # noqa: BLE001 - the status alone still says what happened
        return b""


def send(gateway: Gateway, url: str, body: dict | None = None) -> Answer:
    """One call; never raises."""
    data = json.dumps(body).encode() if body else None
    request = urllib.request.Request(url, data=data)  # noqa: S310 - https URLs from TSG's own settings
    request.add_header("Authorization", "Bearer " + gateway.key)
    if gateway.header:
        request.add_header(gateway.header, gateway.key)
    if body:
        request.add_header("Content-Type", "application/json")
    started = time.perf_counter()
    try:
        with OPENER.open(request, timeout=TIMEOUT_SECONDS) as answer:
            status, headers, raw = answer.status, answer.headers, answer.read()
    except urllib.error.HTTPError as exc:
        status, headers, raw = exc.code, exc.headers, read_all(exc)
    except Exception as exc:  # noqa: BLE001 - a timeout, a refused connection or TLS: the report says which
        return Answer(0, {}, None, f"{type(exc).__name__}: {exc}"[:200], time.perf_counter() - started)
    seconds = time.perf_counter() - started
    text = raw.decode("utf-8", "replace")
    try:
        parsed = json.loads(text)
    except ValueError:
        parsed = None
    start = " ".join(text[:4000].split())[:1000]  # one line, even of an HTML error page
    return Answer(status, {k.lower(): v for k, v in (headers or {}).items()}, parsed, start, seconds)


def question(target: Target, tag: str, tiny: bool) -> tuple[str, dict]:
    """The page and body of one call: tiny for the limits, TSG-sized for the load (`tag` makes it unique)."""
    if target.kind == "chat":
        hello = [{"role": "user", "content": "hi"}]
        return "/chat/completions", {"model": target.model, "messages": hello, "max_tokens": 5}
    query = "hi" if tiny else SCENARIO.format(tag=tag)
    if target.kind == "embedding":
        return "/embeddings", {"model": target.model, "input": [query if tiny else QUERY_INSTRUCTION + query]}
    documents = ["hi"] if tiny else [
        CONTROL.format(tag=tag, i=i, topic=TOPICS[i % len(TOPICS)]) for i in range(DOCUMENTS)]  # fmt: skip
    return "/rerank", {"model": target.model, "query": query, "documents": documents, "top_n": len(documents)}


def call(target: Target, tag: str, tiny: bool) -> Answer:
    path, body = question(target, tag, tiny)
    return send(target.gateway, target.gateway.api(path), body)


def tokens(answer: Answer) -> int:
    """The tokens the gateway counted for one answer, 0 when it says none."""
    body = answer.body if isinstance(answer.body, dict) else {}
    usage = body.get("usage") or {}
    meta = body.get("meta") or {}
    found = usage.get("total_tokens") or (meta.get("billed_units") or {}).get("total_tokens")
    return int(found or (meta.get("tokens") or {}).get("input_tokens") or 0)


def is_whole(answer: Answer, kind: str) -> bool:
    """A 200 with every score (rerank) or a vector (embedding)."""
    body = answer.body if isinstance(answer.body, dict) else {}
    if answer.status != 200:
        return False
    if kind == "rerank":
        return len(body.get("results") or []) in (1, DOCUMENTS)
    if kind == "embedding":
        return bool((body.get("data") or [{}])[0].get("embedding"))
    return True


def message(answer: Answer) -> str:
    """An error answer's own message (a LiteLLM 429 names its limit only here), else the answer's start."""
    body = answer.body if isinstance(answer.body, dict) else {}
    error = body.get("error")
    said = error.get("message") if isinstance(error, dict) else error or body.get("detail")
    return " ".join(str(said).split())[:500] if said else answer.text[:500]


def outcome(answer: Answer) -> str:
    if not answer.status:
        return f"no answer after {answer.seconds:.1f} s: {answer.text}"
    said = f"HTTP {answer.status} in {answer.seconds:.1f} s"
    return (
        f"{said}, {tokens(answer):,} tokens counted" if answer.status == 200 else f"{said}: {message(answer)}"
    )


def limit_headers(answer: Answer) -> dict:
    return {h: v for h, v in answer.headers.items() if any(word in h for word in LIMIT_WORDS)}


def limits_section(targets: list[Target]) -> list[str]:
    lines = ["1. What each model's answer says about its limits (one tiny call each)"]
    for target in targets:
        answer = call(target, "limits", tiny=True)
        lines.append(f"  {target.model} ({target.kind}): {outcome(answer)}")
        shown = [f"      {h} {v}" for h, v in sorted(limit_headers(answer).items())]
        lines += shown or ["      no limit headers"]
    return lines + [""]


def limit_fields(data: object, path: str = "") -> list[str]:
    """'info.tpm_limit 200000' for each field of a gateway page that is a limit."""
    if isinstance(data, list):
        return [field for item in data for field in limit_fields(item, path)]
    if not isinstance(data, dict):
        return []
    found = []
    for name, value in data.items():
        where = f"{path}.{name}" if path else str(name)
        if FIELD.search(str(name)) and (value is None or isinstance(value, (int, float, dict))):
            found.append(f"{where} {json.dumps(value)}")
        elif isinstance(value, (dict, list)):
            found += limit_fields(value, where)
    return found


def read_page(gateway: Gateway, path: str) -> tuple[str, object]:
    """('', the page's JSON), or (why there is none, None)."""
    answer = send(gateway, gateway.page(path))
    if answer.status == 200:
        return "", answer.body
    refused = answer.status in (401, 403)
    return (f"HTTP {answer.status}: this key may not read it" if refused else outcome(answer)), None


def fields_text(data: object) -> str:
    return "; ".join(limit_fields(data)) or "no limit fields"


def pages_section(targets: list[Target]) -> list[str]:
    lines = ["2. The key's own settings on the gateway (LiteLLM pages)"]
    names = {target.model for target in targets}
    for gateway in dict.fromkeys(target.gateway for target in targets):
        why, key = read_page(gateway, "/key/info")
        info = key.get("info", key) if isinstance(key, dict) else key
        lines.append(f"  {'/key/info':28} {why or fields_text(info)}")
        team = info.get("team_id") if isinstance(info, dict) else None
        if team:
            why, body = read_page(gateway, "/team/info?team_id=" + urllib.parse.quote(str(team)))
            lines.append(f"  {'/team/info':28} {why or fields_text(body)}")
        why, body = read_page(gateway, "/model/info")
        data = body.get("data") if isinstance(body, dict) else None
        ours = [e for e in data or [] if isinstance(e, dict) and e.get("model_name") in names]
        if why or not ours:
            lines.append(f"  {'/model/info':28} {why or 'lists none of these models'}")
        lines += [f"  /model/info, {entry['model_name']}: {fields_text(entry)}" for entry in ours]
    return lines + [""]


def remaining_tokens(answer: Answer) -> dict:
    found = {h: v for h, v in answer.headers.items() if h.endswith("remaining-tokens") and v.isdigit()}
    return {h: int(v) for h, v in found.items()}


def token_section(targets: list[Target]) -> list[str]:
    lines = ["3. Do reranks count toward the token budget? (tiny chat, one TSG-sized rerank, tiny chat)"]
    chat = next((t for t in targets if t.kind == "chat"), None)
    rerank = next((t for t in targets if t.kind == "rerank"), None)
    if not (chat and rerank):
        return lines + ["  skipped: needs a chat and a rerank setting", ""]
    before = call(chat, "before", tiny=True)
    middle = call(rerank, "tokens", tiny=False)
    time.sleep(3)  # the gateway counts an answer's tokens just after it is sent
    after = call(chat, "after", tiny=True)
    lines.append(f"  tiny chat before ({chat.model}): {outcome(before)}")
    lines.append(f"  the rerank ({DOCUMENTS} documents): {outcome(middle)}")
    shown = [f"      {h} {v}" for h, v in sorted(limit_headers(middle).items())]
    lines += shown or ["      the rerank's answer has no limit headers"]
    lines.append(f"  tiny chat after: {outcome(after)}")
    was, now = remaining_tokens(before), remaining_tokens(after)
    if not was:
        return lines + ["  the chat answers state no tokens left, so this cannot be told here", ""]
    for header, value in sorted(was.items()):
        left = now.get(header)
        drop = "" if left is None else f" (down {value - left:,})"
        shown = "not stated" if left is None else f"{left:,}"
        lines.append(f"  {header}: {value:,} before, {shown} after{drop}")
    lines.append("  A drop of about the rerank's tokens: reranks count. Others' calls add to it; a new "
                 "minute between the two chats resets it.")  # fmt: skip
    return lines + [""]


def burst(target: Target, count: int, tag: str) -> tuple[list[Answer], float]:
    """`count` TSG-sized calls sent at the same moment; their answers and the seconds until the last one."""
    start = threading.Barrier(count)

    def one(i: int) -> Answer:
        path, body = question(target, f"{tag}-{i}", tiny=False)
        start.wait()
        return send(target.gateway, target.gateway.api(path), body)

    began = time.perf_counter()
    with ThreadPoolExecutor(max_workers=count) as pool:
        answers = list(pool.map(one, range(count)))
    return answers, time.perf_counter() - began


def step_lines(count: int, answers: list[Answer], wall: float, kind: str) -> list[str]:
    whole = [a for a in answers if is_whole(a, kind)]
    refused = [a for a in answers if a.status == 429]
    lost = [a for a in answers if not a.status]
    other = len(answers) - len(whole) - len(refused) - len(lost)
    seconds = sorted(a.seconds for a in whole) or [0.0]
    counted = sum(tokens(a) for a in whole)
    numbers = f"{len(whole):5} {len(refused):5} {other:6} {len(lost):10} {statistics.median(seconds):9.1f}"
    lines = [f"  {count:8} {numbers} {seconds[-1]:9.1f} {wall:7.1f} {counted:10,}"]
    if refused:
        waits = sorted({a.headers.get("retry-after", "none") for a in refused})
        lines.append(f"      429 retry-after {', '.join(waits)}; first: {message(refused[0])}")
        lines += [f"      429 {h} {v}" for h, v in sorted(limit_headers(refused[0]).items())]
    for bad in {a.status: a for a in answers if a not in whole and a.status != 429}.values():
        lines.append(f"      {outcome(bad)[:240]}")
    lows: dict = {}
    for answer in whole:
        for h, v in answer.headers.items():
            if "remaining" in h and v.isdigit():
                lows[h] = min(lows.get(h, int(v)), int(v))
    lines += [f"      lowest {h} {v:,}" for h, v in sorted(lows.items())]
    return lines


def load_section(targets: list[Target], steps: list[int], pause: float) -> list[str]:
    lines = ["4. Many TSG-sized calls at once (a fresh minute before each step)"]
    first = True
    for kind, size in (("rerank", f"{DOCUMENTS} documents"), ("embedding", "one query")):
        target = next((t for t in targets if t.kind == kind), None)
        if not target:
            lines += [f"  {kind}: skipped, no setting", ""]
            continue
        columns = "  at once    ok   429  other  no answer  median s  slowest s  step s     tokens"
        lines += [f"  {target.model} ({size} a call)", columns]
        for count in steps:
            if not first:
                progress(f"waiting {pause:.0f} s for a fresh minute")
                time.sleep(pause)
            first = False
            progress(f"{kind}: {count} at once")
            answers, wall = burst(target, count, f"{kind}{count}")
            lines += step_lines(count, answers, wall, kind)
            if any(a.status == 429 for a in answers):  # the gateway is shared: no more load at all
                return lines + [
                    "      stopped here: a limit was reached (429), so no more calls were sent",
                    "",
                ]
            if not any(is_whole(a, kind) for a in answers):
                lines.append("      stopped here: no call worked")
                break
        lines.append("")
    return lines


def read_env_file(path: str) -> dict:
    """KEY=VALUE lines of a .env file; {} when there is none."""
    values: dict = {}
    if not os.path.isfile(path):
        return values
    with open(path, encoding="utf-8-sig") as lines:
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            name, value = (part.strip() for part in line.split("=", 1))
            name = name[7:].strip() if name.startswith("export ") else name
            if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]:
                value = value[1:-1]
            else:
                value = value.split(" #", 1)[0].strip()
            values[name] = value
    return values


def find_targets(settings: dict) -> tuple[list[Target], list[str]]:
    """Each AI model TSG's settings name, once; and the settings that are missing."""
    targets: list[Target] = []
    missing: list[str] = []
    for kind, prefix in MODULES:
        base, model, key = (
            settings.get(f"{prefix}_{part}", "").strip() for part in ("BASE_URL", "MODEL", "API_KEY")
        )
        if not (base and model and key):
            missing.append(prefix)
            continue
        KEYS.append(key)
        name = model[len("litellm_proxy/") :] if model.startswith("litellm_proxy/") else model
        target = Target(kind, name, Gateway(base, key, settings.get("CII_AI_KEY_HEADER", "").strip()))
        if all((t.kind, t.model, t.gateway) != target for t in targets):
            targets.append(target)
    return targets, missing


def progress(text: str) -> None:
    print(f"[{datetime.now(timezone.utc):%H:%M:%S}] {text}", file=sys.stderr, flush=True)  # noqa: UP017 - 3.8


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="TSG's AI gateway limits and speed under load, in UAT.")
    parser.add_argument("--env-file", default=".env", help="TSG's settings file when not in the environment")
    parser.add_argument("--steps", default="1,10,30,60", help="calls at once for each load step")
    parser.add_argument("--pause", type=float, default=60, help="seconds between steps (a fresh minute)")
    parser.add_argument("--no-load", action="store_true", help="only the limits: no many-at-once steps")
    args = parser.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):  # a Windows console cannot show every character a gateway sends
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    steps = [int(step) for step in args.steps.split(",") if step.strip().isdigit()]
    if not steps or not all(1 <= step <= 200 for step in steps):
        parser.error("--steps: whole numbers from 1 to 200, such as 1,10,30,60")
    settings = {**read_env_file(args.env_file), **os.environ}  # the environment wins, as in TSG
    targets, missing = find_targets(settings)
    if not targets:
        print(f"No AI settings (CII_*_BASE_URL, _MODEL, _API_KEY) in the environment or {args.env_file}: "
              "run it in the TSG folder, or pass --env-file.", file=sys.stderr)  # fmt: skip
        return 2
    now = datetime.now(timezone.utc)  # noqa: UP017 - datetime.UTC needs 3.11
    gateways = ", ".join(sorted({t.gateway.base for t in targets}))
    header = sorted({t.gateway.header or "Authorization only" for t in targets})
    models = ", ".join(f"{t.model} ({t.kind})" for t in targets)
    report = [f"TSG AI gateway check, {now:%Y-%m-%d %H:%M:%S} UTC",
              f"Gateway: {gateways} (key header: {', '.join(header)})", f"Models: {models}"]  # fmt: skip
    report += [f"Not set, so not checked: {', '.join(missing)}"] if missing else []
    progress("reading the limits")
    report += ["", *limits_section(targets), *pages_section(targets), *token_section(targets)]
    if not args.no_load:
        report += load_section(targets, steps, args.pause)
    report.append("Send this whole report back.")
    text = hide("\n".join(report))
    print(text)
    save(text, f"gateway_check_{now:%Y%m%d_%H%M%S}.txt")
    return 0


def save(text: str, name: str) -> None:
    """The report as a file in the current folder; a pod's read-only folder only says so."""
    try:
        with open(name, "w", encoding="utf-8") as out:
            out.write(text + "\n")
        print(f"Saved to {os.path.abspath(name)}", file=sys.stderr)
    except OSError as exc:
        print(f"Not saved ({exc.strerror}): copy the text above.", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
