"""API key limits: how many tokens and requests one API key may use in one minute on an OpenAI-compatible AI
gateway, and which limit sets it: the model's own capacity, the key's own limit, and those of the user, team
and organisation the key belongs to (a LiteLLM gateway states these in its answers' headers and on /key/info,
/team/info, /organization/info and /model/info). Asks each model the smallest question of its kind (a chat
model 5 answer tokens, an embedding model one word, a rerank model one word and one document); reads nothing
else. Never prints the key, or whose it is. Prints one Markdown table per model, then the gateway's answers
word for word.

  python ai_limits_check.py --base-url https://gateway.example.com --model kimi-k2.5 [--model glm-5.3]
      [--embedding-model qwen3-embedding-8b] [--rerank-model qwen3-reranker-8b]
      [--key-env AI_GATEWAY_KEY] [--env-file keys.env]

The key is read from the environment variable --key-env names (from --env-file when given), never from the
command line."""

from __future__ import annotations

import argparse
import os
import re
import sys
import textwrap
from datetime import UTC, datetime
from pathlib import Path
from typing import NamedTuple

import httpx
from dotenv import dotenv_values

LIMIT_KINDS = {"tokens": "tpm", "requests": "rpm"}  # a minute's limit -> the word its JSON field holds
PER_REQUEST = {  # a request's own limit -> the word its JSON field holds
    "prompt tokens": "max_input_tokens",
    "answer tokens": "max_output_tokens",
    "requests at once": "max_parallel_requests",
}
HEADER_WORDS = ("ratelimit", "retry-after", "rate_limit_type")  # the answer headers that are limits
#: Whose limit it is, by the scope word of a LiteLLM header (x-ratelimit-<scope>-limit-tokens); a header
#: naming no scope is the model's own (its provider's, passed through).
SCOPES = {
    "api_key": "key",
    "model_per_key": "key",
    "user": "user",
    "end_user": "user",
    "team": "team",
    "model_per_team": "team",
    "organization": "organisation",
    "model_per_organization": "organisation",
}
#: Each level a limit is set at: its name, and who shares it.
LEVELS = {
    "model": ("The model's own capacity", "shared by every caller of the model"),
    "key": ("This key's own limit", "for this key alone"),
    "user": ("The key's user", "shared by every key of that user"),
    "team": ("The key's team", "shared by every key of that team"),
    "organisation": ("The key's organisation", "shared by every key of that organisation"),
}
REFUSED = "this key may not read it"
#: A LiteLLM 429's text: whose budget, its size and what was left (the name after the colon is dropped).
REFUSAL = re.compile(r"Rate limit exceeded for (\w+):.*?Current limit: (\d+), Remaining: (\d+)", re.S)
#: The smallest question for each kind of model: its page, and what it sends with the model's name.
QUESTIONS: dict[str, tuple[str, dict[str, object]]] = {
    "chat": ("/chat/completions", {"messages": [{"role": "user", "content": "hi"}], "max_tokens": 5}),
    "embedding": ("/embeddings", {"input": "hi"}),
    "rerank": ("/rerank", {"query": "hi", "documents": ["hi"]}),
}
TIMEOUT_SECONDS = 60
HEADER = ["Per minute, unless said", "Tokens", "Requests", "Notes"]
PLAIN_HEADER = ["What was checked", "Result", "What it means"]
PLAIN_WIDTHS = (28, 22, 64)  # characters per column of the plain table; longer text wraps
WORDS_PER_TOKEN = 0.75  # a token is about three quarters of an English word


class Limit(NamedTuple):
    """One limit a gateway states, and where it states it."""

    scope: str  # whose: model, key, user, team or organisation
    kind: str  # tokens or requests a minute, "tokens left" or "requests left" of it, or a PER_REQUEST kind
    value: int | None  # None: the gateway sets none, or would not say (its source tells which)
    source: str  # the header or field and its value, word for word
    window: int | None = None  # seconds, when the gateway states them


def field_kind(path: str) -> str | None:
    """The kind of limit a JSON field holds, by its own name; None for none."""
    name = path.rsplit(".", 1)[-1]
    return next((kind for kind, word in {**LIMIT_KINDS, **PER_REQUEST}.items() if word in name), None)


def limit_fields(answer: object, path: str = "") -> list[tuple[str, object]]:
    """Every field of a JSON answer that is a limit, as (dotted path, value)."""
    if isinstance(answer, list):
        return [field for item in answer for field in limit_fields(item, path)]
    if not isinstance(answer, dict):
        return []
    found: list[tuple[str, object]] = []
    for name, value in answer.items():
        where = f"{path}.{name}" if path else str(name)
        found += [(where, value)] if field_kind(where) else limit_fields(value, where)
    return found


def read_json(client: httpx.Client, path: str, params: dict[str, str] | None = None) -> object:
    """A gateway's JSON answer, or why there is none, in words."""
    try:
        answer = client.get(path, params=params)
    except httpx.HTTPError as exc:
        return f"not reached: {type(exc).__name__}"
    if answer.status_code in (401, 403):
        return f"HTTP {answer.status_code}: {REFUSED}"
    if answer.status_code == 404:
        return "HTTP 404: this gateway has no such page"
    if answer.is_error:
        return f"HTTP {answer.status_code}"
    try:
        return answer.json()
    except ValueError:
        return "answered, but not with JSON"


def own_budget(organisation: object) -> object:
    """An organisation's own limits: its budget table, never its teams' or members' (their own limits)."""
    if not isinstance(organisation, dict):
        return organisation
    plain = {name: value for name, value in organisation.items() if not isinstance(value, dict | list)}
    return organisation.get("litellm_budget_table") or plain


def gateway_sections(client: httpx.Client, name: str) -> list[tuple[str, str, object]]:
    """(level, page, JSON or why not) of the key, its team, its organisation and the model, as a LiteLLM
    gateway gives them; another gateway has none of these pages."""
    key = read_json(client, "/key/info")
    info = key.get("info", key) if isinstance(key, dict) else key
    owned = info if isinstance(info, dict) else {}
    unknown = "not known: the key's own settings were not read"
    team = (
        read_json(client, "/team/info", {"team_id": owned["team_id"]})
        if owned.get("team_id")
        else ("the key names no team" if isinstance(info, dict) else unknown)
    )
    organisation = (
        read_json(client, "/organization/info", {"organization_id": owned["organization_id"]})
        if owned.get("organization_id")
        else ("the key names no organisation" if isinstance(info, dict) else unknown)
    )
    models = read_json(client, "/model/info")
    if isinstance(models, dict):
        models = [entry for entry in models.get("data", []) if entry.get("model_name") == name]
    return [
        ("key", "/key/info", info),
        ("team", "/team/info", team.get("team_info", team) if isinstance(team, dict) else team),
        ("organisation", "/organization/info", own_budget(organisation)),
        ("model", "/model/info", models),
    ]


def section_line(label: str, page: str, answer: object) -> tuple[str, list[Limit]]:
    """'  /team/info  tpm_limit 200000, rpm_limit none set' and the limits in it: a field set to none, and a
    page the key may not read, as limits with no value."""
    if isinstance(answer, str):
        refused = [Limit(label, kind, None, f"{page} {answer}") for kind in LIMIT_KINDS]
        return f"  {page:19} {answer}", refused if REFUSED in answer else []
    fields = limit_fields(answer)
    shown = ", ".join(f"{path} {'none set' if value is None else value}" for path, value in fields)
    found = [
        Limit(label, kind, value or None, f"{page} {path} {'none set' if value is None else value}")
        for path, value in fields
        if (kind := field_kind(path)) and (value is None or isinstance(value, int))
    ]
    return f"  {page:19} {shown or 'no limit fields'}", found


def header_limits(headers: dict[str, str]) -> list[Limit]:
    """The limits an answer's headers state, x-ratelimit-[<scope>-]limit-<kind>, and what was left of each,
    x-ratelimit-[<scope>-]remaining-<kind>; the model's own headers give their window too."""
    found = []
    for header, value in headers.items():
        for kind in LIMIT_KINDS:
            for word, named in (("limit", kind), ("remaining", f"{kind} left")):
                if not (header.endswith(f"{word}-{kind}") and value.isdigit()):
                    continue
                scope = header.removeprefix("llm_provider-").removeprefix("x-ratelimit-")
                scope = scope.removesuffix(f"{word}-{kind}").rstrip("-")
                window = "" if scope else headers.get(f"x-ratelimit-renewalperiod-{kind}", "")
                whose, seconds = (
                    SCOPES.get(scope, scope or "model"),
                    int(window) if window.isdigit() else None,
                )
                found.append(Limit(whose, named, int(value), f"{header} {value}", seconds))
    return found


def answer_lines(client: httpx.Client, name: str, kind: str = "chat") -> tuple[list[str], list[Limit]]:
    """The smallest question of the model's `kind`: the limit headers of its answer, and a 429's budget."""
    page, question = QUESTIONS[kind]
    try:
        answer = client.post(page, json={"model": name, **question})
    except httpx.HTTPError as exc:
        return [f"  {'answer':19} not reached: {type(exc).__name__}"], []
    limits = {
        header.lower(): value
        for header, value in answer.headers.items()
        if any(word in header.lower() for word in HEADER_WORDS)
    }
    shown = ", ".join(f"{header} {value}" for header, value in sorted(limits.items())) or "no limit headers"
    lines = [f"  {'answer':19} HTTP {answer.status_code}", f"  {'headers':19} {shown}"]
    found = header_limits(limits)
    refused = REFUSAL.search(answer.text) if answer.status_code == 429 else None
    if refused:
        scope, limit, left = refused.groups()
        refused_kind = limits.get("rate_limit_type") or ""
        lines.append(
            f"  {'429 names':19} {scope}: limit {limit}, remaining {left}, limit type {refused_kind}"
        )
        if refused_kind in LIMIT_KINDS:
            whose = SCOPES.get(scope, scope)
            found.append(Limit(whose, refused_kind, int(limit), f"429: {scope} limit {limit}"))
            found.append(Limit(whose, f"{refused_kind} left", int(left), f"429: {scope} remaining {left}"))
    return lines, found


def limit_lines(client: httpx.Client, name: str, kind: str = "chat") -> tuple[list[str], list[Limit]]:
    """One model on one gateway: the gateway's answers as lines, and every limit in them."""
    lines: list[str] = []
    found: list[Limit] = []
    for label, page, answer in gateway_sections(client, name):
        line, limits = section_line(label, page, answer)
        lines.append(line)
        found += limits
    asked, limits = answer_lines(client, name, kind)
    return lines + asked, found + limits


def amount(limits: list[Limit], kind: str) -> str:
    """A level's limit of `kind`: its number, 'none set', 'not readable (HTTP 403)' or 'not stated'."""
    values = [limit.value for limit in limits if limit.kind == kind and limit.value]
    if values:
        return f"{min(values):,}"
    notes = " ".join(limit.source for limit in limits if limit.kind == kind)
    refused = re.search(r"HTTP \d+", notes)
    if "none set" in notes:
        return "none set"
    return f"not readable ({refused.group()})" if refused else "not stated"


def lowest(limits: list[Limit], kind: str) -> Limit | None:
    """The lowest limit of `kind` stated at any level; None for none."""
    stated = [limit for limit in limits if limit.kind == kind and limit.value]
    return min(stated, key=lambda limit: limit.value or 0, default=None)


def level_rows(found: list[Limit]) -> list[list[str]]:
    """A row for each level that limits the key: the model's and the key's own always, any other the gateway
    names a number at."""
    named = {limit.scope for limit in found if limit.value and limit.kind in LIMIT_KINDS}
    scopes = [scope for scope in LEVELS if scope in named | {"model", "key"}] + sorted(named - set(LEVELS))
    rows = []
    for scope in scopes:
        own = [limit for limit in found if limit.scope == scope]
        name, shares = LEVELS.get(scope, (f"The key's {scope}", f"shared by every key of that {scope}"))
        rows.append([name, amount(own, "tokens"), amount(own, "requests"), shares])
    return rows


def minute_rows(found: list[Limit]) -> list[list[str]]:
    """The most the key can use in one minute, what was left of it at the check, the least it is sure of."""
    most = [lowest(found, kind) for kind in LIMIT_KINDS]
    left = []
    for kind, limit in zip(LIMIT_KINDS, most, strict=True):
        values = [lim.value for lim in found if lim.kind == f"{kind} left" and lim.value is not None]
        if not values:
            left.append("not stated")
            continue
        values += [limit.value] if limit and limit.value else []
        left.append(f"{min(values):,}")
    whose = [
        f"{kind}: {LEVELS.get(lim.scope, (lim.scope,))[0].lower()}"
        for kind, lim in zip(LIMIT_KINDS, most, strict=True)
        if lim
    ]
    return [
        [
            "**Most this key can use in one minute**",
            *(f"**{lim.value:,}**" if lim else "not stated" for lim in most),
            "the lowest above; " + ("; ".join(whose) or "none stated"),
        ],
        ["Left of it in the minute of this check", *left, "after this check's own tiny request"],
        [
            "Least this key is sure to get in one minute",
            "0",
            "0",
            "a limit caps use; none reserves any for it",
        ],
    ]


def request_rows(found: list[Limit]) -> list[list[str]]:
    """Each request's own limits (its most prompt and answer tokens, how many may run at once), the window."""
    prompt, answer, at_once = (amount(found, kind) for kind in PER_REQUEST)
    windows = sorted({limit.window for limit in found if limit.window})
    window = ", ".join(f"{seconds} s, as the gateway states it" for seconds in windows)
    return [
        ["Most tokens in one request: prompt / answer", f"{prompt} / {answer}", "-", "per request"],
        ["Most requests at once (in parallel)", "-", at_once, "per key"],
        ["How long 'one minute' is", "-", "-", window or "not stated by the gateway"],
    ]


def key_table(found: list[Limit]) -> list[list[str]]:
    """One model's table: each level, the most, left and least a minute, and each request's own limits."""
    return [*level_rows(found), *minute_rows(found), *request_rows(found)]


def table(header: list[str], rows: list[list[str]], align: str = "lrrl") -> list[str]:
    """A Markdown table padded to read as text too: 'l' or 'r' aligns each column."""
    widths = [max(len(row[column]) for row in [header, *rows]) for column in range(len(header))]

    def line(cells: list[str]) -> str:
        padded = (
            cell.ljust(w) if side == "l" else cell.rjust(w)
            for cell, w, side in zip(cells, widths, align, strict=True)
        )
        return "| " + " | ".join(padded) + " |"

    sides = zip(widths, align, strict=True)
    rule = "|" + "".join(("-" * (w + 1) + ":" if side == "r" else "-" * (w + 2)) + "|" for w, side in sides)
    return [line(header), rule, *(line(row) for row in rows), ""]


def whose_words(limit: Limit) -> str:
    """'the key's organisation (shared by every key of that organisation)' for a limit."""
    name, shares = LEVELS.get(limit.scope, (f"The key's {limit.scope}", "shared"))
    return f"{name[0].lower()}{name[1:]} ({shares})"


def higher_budget(found: list[Limit], tokens: Limit) -> Limit | None:
    """The largest token limit stated at another level: a budget the lowest one keeps out of reach."""
    others = [lim for lim in found if lim.kind == "tokens" and lim.value and lim.scope != tokens.scope]
    return max(others, key=lambda limit: limit.value or 0, default=None)


def token_rows(found: list[Limit], tokens: Limit) -> list[list[str]]:
    """The token budget in everyday words: its size, who sets it, what is left, what it keeps out of reach."""
    words = int(tokens.value * WORDS_PER_TOKEN)  # type: ignore[operator]
    rows = [
        [
            "Tokens this key may use in one minute",
            f"{tokens.value:,}",
            "AI text is counted in tokens (a token is about 3/4 of a word). Everything sent to the AI and "
            f"everything it writes back counts, so this is about {words:,} words a minute in and out "
            f"together. It is set by {whose_words(tokens)}.",
        ]
    ]
    left = [lim.value for lim in found if lim.kind == "tokens left" and lim.value is not None]
    if left:
        rows.append(["Tokens left when checked", f"{min(left):,}", "What the shared budget still held "
                     "in that minute; other users of the same budget lower it."])  # fmt: skip
    prompt = lowest(found, "prompt tokens")
    if prompt and prompt.value and prompt.value > tokens.value:  # type: ignore[operator]
        times = prompt.value / tokens.value  # type: ignore[operator]
        rows.append(["Largest question the AI model accepts", f"{prompt.value:,} tokens",
                     f"{times:.1f} times this key's whole minute: the model can take far more than this "
                     "key is allowed to send, so the key, not the model, is the limit."])  # fmt: skip
    above = higher_budget(found, tokens)
    if above and above.value and above.value > tokens.value:  # type: ignore[operator]
        share = 100 * tokens.value / above.value  # type: ignore[operator]
        rows.append([f"Budget of {LEVELS.get(above.scope, (above.scope,))[0].lower()}",
                     f"{above.value:,}", f"Allowed, but out of reach: the {tokens.value:,} cap is hit "
                     f"first, so this key can use only {share:.2f}% of it."])  # fmt: skip
    return rows


def plain_rows(found: list[Limit]) -> list[list[str]]:
    """The key's limits for a reader who is not technical: each result, and why it matters."""
    tokens, requests = (lowest(found, kind) for kind in LIMIT_KINDS)
    rows = token_rows(found, tokens) if tokens else [
        ["Tokens this key may use in one minute", "not stated",
         "The gateway did not say; see its own answers at the end."]]  # fmt: skip
    if requests and tokens:
        each = tokens.value // requests.value  # type: ignore[operator]
        rows.append(["Questions this key may send in one minute", f"{requests.value:,}",
                     f"Not the problem: {requests.value:,} questions sharing {tokens.value:,} tokens "
                     f"could average only {each:,} tokens (about {int(each * WORDS_PER_TOKEN)} words) "
                     "each."])  # fmt: skip
    own = amount([lim for lim in found if lim.scope == "key"], "tokens")
    own_meaning = (
        "The gateway refused to show this key's own settings, so they cannot be checked."
        if "not readable" in own
        else "The key has no limit of its own; the shared one applies."
    )
    rows.append(["This key's own setting", own, own_meaning])
    rows.append(["Tokens guaranteed to this key", "0", "Nothing is set aside for it: when others use the "
                 "shared budget first, this key's questions wait or are refused (HTTP 429)."])  # fmt: skip
    return rows


def verdict(found: list[Limit], lines: list[str]) -> str:
    """One sentence: how small the token budget is, or why no limit could be read."""
    tokens = lowest(found, "tokens")
    if not tokens:
        unreached = any("not reached" in line for line in lines)
        why = "the gateway could not be reached from this machine" if unreached else "the gateway stated none"
        return f"In short: no token limit could be read, because {why}."
    said = f"In short: this key may use at most {tokens.value:,} tokens a minute, shared with others"
    prompt, above = lowest(found, "prompt tokens"), higher_budget(found, tokens)
    if prompt and prompt.value and prompt.value > tokens.value:  # type: ignore[operator]
        said += f"; that is less than one full-size question ({prompt.value:,} tokens)"
    if above and above.value and above.value > tokens.value:  # type: ignore[operator]
        said += f", and a small part of the {above.value:,} its team is allowed"
    return said + "."


def boxed(header: list[str], rows: list[list[str]], widths: tuple[int, ...] = PLAIN_WIDTHS) -> list[str]:
    """A plain-text table whose long cells wrap inside their column, for a console or a .txt file."""
    rule = "+" + "+".join("-" * (width + 2) for width in widths) + "+"

    def row_lines(cells: list[str]) -> list[str]:
        wrapped = [textwrap.wrap(cell, width) or [""] for cell, width in zip(cells, widths, strict=True)]
        height = max(len(cell) for cell in wrapped)
        return [
            "| " + " | ".join((cell[i] if i < len(cell) else "").ljust(width)
                              for cell, width in zip(wrapped, widths, strict=True)) + " |"
            for i in range(height)
        ]  # fmt: skip

    body = [line for row in rows for line in [*row_lines(row), rule]]
    return [rule, *row_lines(header), rule.replace("-", "="), *body, ""]


def model_report(client: httpx.Client, name: str, kind: str = "chat") -> list[str]:
    """One model's plain summary, its detailed table, then the gateway's answers word for word."""
    lines, found = limit_lines(client, name, kind)
    return [
        f"## {name} ({kind} model) @ {client.base_url.host}",
        "",
        verdict(found, lines),
        "",
        *boxed(PLAIN_HEADER, plain_rows(found)),
        "In detail:",
        "",
        *table(HEADER, key_table(found)),
        "The gateway's answers, word for word:",
        "",
        "```",
        *lines,
        "```",
        "",
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="How many tokens and requests an API key may use a minute.")
    parser.add_argument("--base-url", required=True, help="the gateway's OpenAI-compatible address")
    parser.add_argument("--model", action="append", default=[], help="a chat model, as the gateway names it")
    parser.add_argument("--embedding-model", action="append", default=[], help="an embedding model")
    parser.add_argument("--rerank-model", action="append", default=[], help="a rerank model")
    parser.add_argument(
        "--key-env", default="AI_GATEWAY_KEY", help="the environment variable holding the key"
    )
    parser.add_argument("--env-file", help="read --key-env from this file instead of the environment")
    parser.add_argument(
        "--out", help="also save the report to this .txt file (default: ai_limits_<time>.txt)"
    )
    args = parser.parse_args(argv)
    models = [(name, "chat") for name in args.model] + [(name, "embedding") for name in args.embedding_model]
    models += [(name, "rerank") for name in args.rerank_model]
    if not models:
        parser.error("name at least one model: --model, --embedding-model or --rerank-model")
    if args.env_file and not Path(args.env_file).is_file():
        raise SystemExit(f"No such file: {args.env_file}")
    env = dotenv_values(args.env_file) if args.env_file else os.environ
    key = (env.get(args.key_env) or "").strip()
    if not key:
        raise SystemExit(f"No key: set {args.key_env}, or pass --env-file with it.")
    now = datetime.now(UTC)
    checked = f"Checked {now:%Y-%m-%d %H:%M:%S} UTC with one tiny request to each model."
    lines = ["# API key limits", "", checked, ""]
    auth = {"Authorization": f"Bearer {key}"}
    with httpx.Client(base_url=args.base_url.rstrip("/"), headers=auth, timeout=TIMEOUT_SECONDS) as client:
        for name, kind in models:
            lines += model_report(client, name, kind)
    report = "\n".join(lines)
    print(report)
    saved = Path(args.out or f"ai_limits_{now:%Y%m%d_%H%M%S}.txt")
    saved.write_text(report + "\n", encoding="utf-8", newline="\n")
    print(f"Saved to {saved.resolve()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
