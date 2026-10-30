"""AI capacity report: for each API that starts AI work, each step's AI calls and tokens per request
(read from the no-key /v1/ai-usage reports), the busiest minute as the gateway counts it, and what N users
starting it at the same moment need with no waiting: tokens a minute, requests a minute and calls at once.
Read-only.

From the project folder:
  python scripts/ai_capacity_report.py --base http://localhost:8000 --since 2026-10-30T09:00:00Z
      [--users 10] [--per-api 20] [--env-file .env.uat]
Inside an API pod (its env already set):
  oc exec -i <pod> -- python - --base http://localhost:8000 --since <time> < scripts/ai_capacity_report.py"""

from __future__ import annotations

import argparse
import os
import statistics
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
from dotenv import dotenv_values

USAGE = "/v1/ai-usage"
PAGE_SIZE = 500  # the reports' largest page
WINDOW_SECONDS = 60  # the gateway's tokens- and requests-a-minute window
REFUSED = "unavailable"  # refused (429) or unreachable: no such call once the limit fits the load
NOT_SENT = "reused"  # an earlier answer used again: nothing was sent
SETTING_MODULES = {
    "threat_scenarios": "SCENARIO",
    "remediation": "REMEDIATION",
    "service_mapper": "SERVICE_MAPPER",
}
TIMEOUT_SECONDS = 60


@dataclass
class Call:
    """One AI attempt of a request, as the gateway sees it."""

    task: str
    model: str
    sent: bool  # answered by the model; a refused or unreachable attempt is not
    tokens_in: int
    tokens_out: int
    held: int  # tokens the gateway holds against its budget while the call runs
    start: float  # epoch seconds
    end: float

    @property
    def used(self) -> int:
        """What the gateway keeps counted once the call ends: the rest of its hold is given back."""
        return self.tokens_in + self.tokens_out


def calls_of(rows: list[dict], caps: dict[str, int]) -> list[Call]:
    """A request's report-4 rows as calls, oldest first. A chat call holds its prompt and its whole answer cap
    while it runs (LiteLLM refunds the rest at its end); a search call holds what it used."""
    calls = []
    for row in rows:
        if row["outcome"] == NOT_SENT:
            continue
        end = datetime.fromisoformat(row["created_at"]).timestamp()  # a row is noted as its attempt ends
        tokens_in, tokens_out = row.get("tokens_in") or 0, row.get("tokens_out") or 0
        cap = caps.get(row["task"], 0)
        held = tokens_in + max(cap, tokens_out) if tokens_in else tokens_out
        model = (row.get("model") or "").rsplit("/", 1)[-1]
        start = end - (row.get("seconds") or 0.0)
        calls.append(
            Call(row["task"], model, row["outcome"] != REFUSED, tokens_in, tokens_out, held, start, end)
        )
    return sorted(calls, key=lambda call: call.start)


def busiest_minute(calls: list[Call]) -> tuple[int, int]:
    """(tokens, calls) the gateway's window must allow so that no call is refused. As each call starts, the
    gateway counts the calls started in the WINDOW_SECONDS before it (its window at the worst alignment): a
    running call at its hold, a finished one at the tokens it used, and the new call at its hold."""
    sent = [call for call in calls if call.sent]
    tokens = calls_made = 0
    for new in sent:
        window = [call for call in sent if new.start - WINDOW_SECONDS < call.start <= new.start]
        counted = (call.held if call.end > new.start or call is new else call.used for call in window)
        tokens = max(tokens, sum(counted))
        calls_made = max(calls_made, len(window))
    return tokens, calls_made


def most_at_once(calls: list[Call]) -> int:
    """The most calls running at the same moment."""
    sent = [call for call in calls if call.sent]
    return max((sum(other.start <= call.start < other.end for other in sent) for call in sent), default=0)


def step_lines(requests: list[list[Call]]) -> list[str]:
    """Each step (task on a model) per request, averaged over the requests, in the order the steps run."""
    steps: dict[tuple[str, str], list[Call]] = {}
    for calls in sorted(requests, key=len, reverse=True):  # the fullest request sets the order
        for call in calls:
            steps.setdefault((call.task, call.model), []).append(call)
    count = len(requests)
    header = f"  {'step':18} {'model':22} {'calls':>6} {'refused':>7} {'tokens in':>10} {'tokens out':>10}"
    lines = [header + f" {'held while running':>18} {'s a call':>8}"]
    for (task, model), calls in [*steps.items(), (("per request", ""), [c for r in requests for c in r])]:
        sent = [call for call in calls if call.sent]
        seconds = statistics.fmean([call.end - call.start for call in sent]) if sent else 0.0
        tokens_in, tokens_out = sum(c.tokens_in for c in sent), sum(c.tokens_out for c in sent)
        lines.append(
            f"  {task:18} {model:22} {len(sent) / count:6.1f} {(len(calls) - len(sent)) / count:7.1f}"
            f" {tokens_in / count:10,.0f} {tokens_out / count:10,.0f}"
            f" {sum(c.held for c in sent) / count:18,.0f} {seconds:8.1f}"
        )
    return lines


@dataclass
class ApiNeed:
    """What `users` requests of one API started together need, worst of the sampled requests."""

    name: str
    module: str
    tokens: int
    calls: int
    at_once: int
    chat_tokens: int  # the module's own chat model: what CII_<MODULE>_CHAT_TOKENS_PER_MINUTE paces
    chat_at_once: int


def api_section(name: str, module: str, requests: list[list[Call]], users: int) -> tuple[list[str], ApiNeed]:
    """One API's report: its steps, one request's busiest minute and the need of `users` requests at once."""
    minutes = [busiest_minute(calls) for calls in requests]
    at_once = [most_at_once(calls) for calls in requests]
    chats = [[call for call in calls if call.task not in ("embed", "rerank")] for calls in requests]
    takes = statistics.median(max(call.end for call in calls) - calls[0].start for calls in requests)
    worst_tokens, worst_calls = max(m[0] for m in minutes), max(m[1] for m in minutes)
    need = ApiNeed(
        name,
        module,
        users * worst_tokens,
        users * worst_calls,
        users * max(at_once),
        users * max(busiest_minute(chat)[0] for chat in chats),
        users * max(most_at_once(chat) for chat in chats),
    )
    lines = [
        f"{name}  ({len(requests)} requests; one takes about {takes:.0f} s)",
        *step_lines(requests),
        f"  busiest minute of one request: {worst_tokens:,} tokens counted, {worst_calls} calls "
        f"(median {statistics.median(m[0] for m in minutes):,.0f} tokens); most at once: {max(at_once)}",
        f"  {users} users at once: {need.tokens:,} tokens a minute, {need.calls} requests a minute, "
        f"{need.at_once} calls at once",
        "",
    ]
    return lines, need


def headline(needs: list[ApiNeed], users: int) -> list[str]:
    """What to ask the gateway for and the app's own settings, for `users` users at once with no waiting."""
    heaviest = max(needs, key=lambda need: need.tokens)
    busiest = max(needs, key=lambda need: need.calls)
    lines = [
        f"For {users} users at once with no waiting (worst case: all start the heaviest API together):",
        f"  tokens a minute:   at least {heaviest.tokens:,}  ({heaviest.name})",
        f"  requests a minute: at least {busiest.calls}  ({busiest.name})",
        f"App settings for {users} users:",
    ]
    for module, setting in SETTING_MODULES.items():
        own = [need for need in needs if need.module == module]
        if own:
            at_once, tokens = max(n.chat_at_once for n in own), max(n.chat_tokens for n in own)
            lines.append(
                f"  CII_{setting}_MAX_CONCURRENT_AI_CALLS >= {at_once}; "
                f"CII_{setting}_CHAT_TOKENS_PER_MINUTE 0 or >= {tokens:,}"
            )
    lines.append(
        f"Not counted: worker processes ({users} jobs side by side need enough Celery workers) and other "
        "teams' use of the same organisation budget."
    )
    return lines


def all_pages(client: httpx.Client, path: str, params: dict[str, str]) -> list[dict]:
    """Every item of a paged report."""
    items: list[dict] = []
    after = None
    while True:
        page = client.get(
            path, params={**params, "limit": str(PAGE_SIZE), **({"after": after} if after else {})}
        )
        page.raise_for_status()
        body = page.json()
        items += body["items"]
        after = body.get("next")
        if not after:
            return items


def sampled_requests(client: httpx.Client, since: str, per_api: int) -> dict[tuple[str, str, str], list[str]]:
    """(module, api, its label) -> its newest `per_api` request ids since `since`."""
    found: dict[tuple[str, str, str], list[str]] = {}
    requests = all_pages(client, f"{USAGE}/requests", {"since": since})
    for request in sorted(requests, key=lambda request: request["first_at"], reverse=True):
        group = (request.get("module") or "", request.get("api") or "", request.get("api_label") or "")
        if group[1] and len(found.setdefault(group, [])) < per_api:
            found[group].append(request["request_id"])
    return found


def report_lines(
    client: httpx.Client, since: str, per_api: int, users: int, caps: dict[str, int]
) -> list[str]:
    """The whole report: one section per API, then the headline."""
    lines, needs = [f"AI capacity from requests since {since}, as the gateway counts them", ""], []
    for (module, api, label), ids in sorted(sampled_requests(client, since, per_api).items()):
        requests = [calls_of(all_pages(client, f"{USAGE}/calls", {"request_id": rid}), caps) for rid in ids]
        requests = [calls for calls in requests if any(call.sent for call in calls)]
        if requests:
            section, need = api_section(f"{module} / {api} - {label}", module, requests, users)
            lines += section
            needs.append(need)
    return lines + headline(needs, users) if needs else [*lines, "No AI calls recorded in this range."]


def answer_caps(env_file: str | None) -> dict[str, int]:
    """Each chat task's answer cap (CII_ANSWER_TOKENS_<TASK>): `env_file`'s values, else this process's."""
    if env_file:
        values = dotenv_values(env_file)
        os.environ.update({k: v for k, v in values.items() if k.startswith("CII_ANSWER_TOKENS_") and v})
    sys.path.insert(0, str(Path.cwd()))  # the project folder, or /app in a pod
    from app.core.constants import CHAT_MAX_OUTPUT_TOKENS

    return {str(task): cap for task, cap in CHAT_MAX_OUTPUT_TOKENS.items()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AI tokens and calls per API step, and what N users need.")
    parser.add_argument("--base", default="http://localhost:8000", help="the TSG API's address")
    yesterday = (datetime.now(UTC) - timedelta(days=1)).isoformat(timespec="seconds")
    parser.add_argument("--since", default=yesterday, help="ISO time with a zone (default: a day ago)")
    parser.add_argument("--users", type=int, default=10, help="users starting the same API at once")
    parser.add_argument("--per-api", type=int, default=20, help="newest requests sampled per API")
    parser.add_argument("--env-file", help="read the CII_ANSWER_TOKENS_ lines from this file")
    args = parser.parse_args(argv)
    if args.env_file and not Path(args.env_file).is_file():
        raise SystemExit(f"No such file: {args.env_file}")
    caps = answer_caps(args.env_file)
    with httpx.Client(base_url=args.base, timeout=TIMEOUT_SECONDS) as client:
        print("\n".join(report_lines(client, args.since, args.per_api, args.users, caps)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
