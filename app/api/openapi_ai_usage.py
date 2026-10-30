"""What the Swagger page (/docs) says about the AI usage reports (group 12): which report answers what, the
modules and their API calls, and per report its purpose, calls to copy, example answers and errors. Each
example answer is a real one, with the call that got it, from an end-to-end run
(openapi_ai_usage_examples.json). Text only: no behaviour lives here."""

import json
import re
from enum import StrEnum
from http import HTTPStatus
from pathlib import Path
from typing import Any

from app.api.errors import build_problem_body
from app.core.constants import (
    API_INFO,
    BUCKET_INFO,
    MODULE_BUCKETS,
    AiApi,
    AiUsageGroup,
    AiUsageLimits,
    AiUsageMessage,
    AiUsageOutcome,
    ErrorCode,
    ErrorMessage,
    Limits,
    Module,
    Problem,
)

#: Each report's examples, by name: {"call": the GET that got it, "answer": what it answered}.
EXAMPLES: dict[str, dict[str, dict[str, Any]]] = json.loads(
    Path(__file__).with_name("openapi_ai_usage_examples.json").read_text(encoding="utf-8")
)
EXAMPLE_ANSWERS = {
    report: {name: example["answer"] for name, example in named.items()} for report, named in EXAMPLES.items()
}
EXAMPLE_SESSION_ID = EXAMPLE_ANSWERS["requests"]["one_session"]["session_id"]
EXAMPLE_REQUEST_ID = EXAMPLE_ANSWERS["request"]["create_scenario"]["request_id"]
_ERROR_REQUEST_ID = "56589d66a1a742c5b6860e4a4259001f"  # the X-Request-Id an error answer carries
_REQUEST_ROUTE = "/v1/ai-usage/requests/{request_id}"

_LAG = f"up to {AiUsageLimits.ROLLUP_EVERY_SECONDS // 60} minutes behind"
_CACHED = f"an answer is kept {AiUsageLimits.REPORT_CACHE_SECONDS} seconds"

MODULE_API_TABLE = "\n".join(
    [
        "| module | api | name | what it starts |",
        "|---|---|---|---|",
        *(f"| `{module}` | `{api}` | {name} | {does} |" for (module, api), (name, does) in API_INFO.items()),
    ]
)
MODULE_PARTS_TABLE = "\n".join(
    [
        "| module | its parts of the work (`bucket`), in report order |",
        "|---|---|",
        *(
            f"| `{module}` | " + ", ".join(f"`{part}` ({BUCKET_INFO[part][0]})" for part in parts) + " |"
            for module, parts in MODULE_BUCKETS.items()
        ),
    ]
)
_BACKGROUND_MODULES = ", ".join(f"`{module}`" for module in Module if module not in MODULE_BUCKETS)

AI_USAGE_GROUP = f"""How many AI calls each module, API call, session and request made, per part of the work
and per model, successful and failed, with each activity's name and description. Counts only, never a prompt
or an answer. No key.

| You want to know | Use |
|---|---|
| AI calls over a time range, per module and API call (or per day, model, part …) | 1. `GET /v1/ai-usage` |
| One session's API calls (a run and its plans, or a mapping) | 2. `GET /v1/ai-usage/requests` |
| What one API call asked the AI to do, and on which models | 3. `GET /v1/ai-usage/requests/{{request_id}}` |
| Every AI attempt of an API call or a session, and why one failed | 4. `GET /v1/ai-usage/calls` |

**Modules and their API calls.** Pick them from the `module` and `api` lists; there is nothing to type.

{MODULE_API_TABLE}

{_BACKGROUND_MODULES} are background jobs with no API call. AI calls no request asked for (library and
evidence indexing) are counted in the part `shared`.

**Each module's parts of the work** (`bucket`; a report lists every part of the module, 0 when none):

{MODULE_PARTS_TABLE}
"""


def route_of(call: str) -> str:
    """The report route a call (path and query) goes to, as the OpenAPI document names it."""
    return re.sub(r"^/v1/ai-usage/requests/[^/?]+", _REQUEST_ROUTE, call.split("?")[0])


def _one_of(values: type[StrEnum]) -> str:
    """The message a query value outside `values` is refused with."""
    names = [f"'{value}'" for value in values]
    return f"Input should be {', '.join(names[:-1])} or {names[-1]}"


def _answers(report: str, labels: dict[str, str]) -> dict[str, Any]:
    """A report's 200: its real example answers, named, each with the call that got it."""
    examples = {
        name: {
            "summary": label,
            "description": f"`GET {EXAMPLES[report][name]['call']}`",
            "value": EXAMPLE_ANSWERS[report][name],
        }
        for name, label in labels.items()
    }
    # FastAPI leaves every null out of the OpenAPI document, the examples' too
    description = "The report. A field with no value is `null` in the answer; the examples leave it out."
    return {"description": description, "content": {"application/json": {"examples": examples}}}


def _problem(status: HTTPStatus, code: ErrorCode, detail: str, field: str = "", message: str = "") -> dict:
    """The problem body the API answers with; `field` (e.g. query.module) and `message` name a bad value."""
    errors = [{"field": field, "message": message}] if field else None
    return build_problem_body(status, code, detail, request_id=_ERROR_REQUEST_ID, errors=errors)


def _invalid(detail: str) -> dict[str, Any]:
    return _problem(HTTPStatus.UNPROCESSABLE_ENTITY, ErrorCode.VALIDATION_ERROR, detail)


def _invalid_value(field: str, message: str) -> dict[str, Any]:
    return _problem(
        HTTPStatus.UNPROCESSABLE_ENTITY,
        ErrorCode.VALIDATION_ERROR,
        ErrorMessage.FIELDS_INVALID,
        field,
        message,
    )


_TOO_LONG = _invalid(AiUsageMessage.SPAN_TOO_LONG.format(days=667, max_days=AiUsageLimits.MAX_SPAN_DAYS))
_LIMIT_TOO_SMALL = _invalid_value("query.limit", "Input should be greater than or equal to 1")
_LONG_RANGE = "since=2025-01-01T00:00:00Z&until=2026-10-30T00:00:00Z"  # 667 days
_MISSING_ID = "0000000000000000000000000000beef"

#: Each error example: (summary, the call that gets it, its answer). A route shows the ones its calls get;
#: tests make each call and compare.
ERROR_EXAMPLES: dict[str, tuple[str, str, dict[str, Any]]] = {
    "unknown_module": (
        "A module not in the list (a typo)",
        "/v1/ai-usage?module=threat_scenario",
        _invalid_value("query.module", _one_of(Module)),
    ),
    "unknown_time_zone": (
        "A time zone that does not exist",
        "/v1/ai-usage?tz=Mars/Base",
        _invalid(AiUsageMessage.TZ_UNKNOWN.format(tz="Mars/Base")),
    ),
    "half_hour_time_zone": (
        "A time zone that is not a whole number of hours from UTC",
        "/v1/ai-usage?tz=Asia/Kolkata",
        _invalid(AiUsageMessage.TZ_NOT_WHOLE_HOURS.format(tz="Asia/Kolkata")),
    ),
    "range_too_long": (
        f"A range over {AiUsageLimits.MAX_SPAN_DAYS} days",
        f"/v1/ai-usage?{_LONG_RANGE}",
        _TOO_LONG,
    ),
    "range_backwards": (
        "`since` after `until`",
        "/v1/ai-usage?since=2026-10-30T00:00:00Z&until=2026-10-01T00:00:00Z",
        _invalid(AiUsageMessage.SPAN_EMPTY),
    ),
    "requests_unknown_api": (
        "An API call not in the list (a typo)",
        "/v1/ai-usage/requests?api=create_scenarios",
        _invalid_value("query.api", _one_of(AiApi)),
    ),
    "requests_range_too_long": (
        f"A range over {AiUsageLimits.MAX_SPAN_DAYS} days",
        f"/v1/ai-usage/requests?{_LONG_RANGE}",
        _TOO_LONG,
    ),
    "requests_limit_too_small": (
        f"`limit` outside 1 to {AiUsageLimits.PAGE_SIZE_MAX}",
        "/v1/ai-usage/requests?limit=0",
        _LIMIT_TOO_SMALL,
    ),
    "requests_bad_cursor": (
        "An `after` that no page returned",
        f"/v1/ai-usage/requests?session_id={EXAMPLE_SESSION_ID}&after=not-a-cursor",
        _invalid(AiUsageMessage.BAD_CURSOR),
    ),
    "request_id_too_long": (
        "A `request_id` over 64 characters",
        "/v1/ai-usage/requests/" + "a" * 65,
        _invalid_value("path.request_id", "String should have at most 64 characters"),
    ),
    "request_not_found": (
        "A request with no AI call recorded",
        f"/v1/ai-usage/requests/{_MISSING_ID}",
        _problem(
            HTTPStatus.NOT_FOUND,
            ErrorCode.NOT_FOUND,
            AiUsageMessage.REQUEST_NOT_FOUND.format(request_id=_MISSING_ID),
        ),
    ),
    "calls_no_id": (
        "Neither `request_id` nor `session_id`",
        "/v1/ai-usage/calls",
        _invalid(AiUsageMessage.CALLS_NEED_SCOPE),
    ),
    "calls_bad_cursor": (
        "An `after` that no page returned",
        f"/v1/ai-usage/calls?session_id={EXAMPLE_SESSION_ID}&after=not-a-cursor",
        _invalid(AiUsageMessage.BAD_CURSOR),
    ),
    "calls_limit_too_small": (
        f"`limit` outside 1 to {AiUsageLimits.PAGE_SIZE_MAX}",
        f"/v1/ai-usage/calls?request_id={EXAMPLE_REQUEST_ID}&limit=0",
        _LIMIT_TOO_SMALL,
    ),
}


def _errors(route: str, status: HTTPStatus, description: str) -> dict[str, Any]:
    """A route's answer for an error status: the error examples whose call goes to it and gets that status."""
    named = {
        name: {"summary": summary, "description": f"`GET {call}`", "value": answer}
        for name, (summary, call, answer) in ERROR_EXAMPLES.items()
        if route_of(call) == route and answer["status"] == status
    }
    return {"description": description, "content": {Problem.MEDIA_TYPE: {"examples": named}}}


_UNAVAILABLE = {
    "description": "Busy, or MongoDB unreachable: try again after the `Retry-After` header's seconds "
    f"({Limits.RETRY_AFTER_SECONDS}).",
    "content": {
        Problem.MEDIA_TYPE: {
            "examples": {
                "busy": {
                    "summary": "Too many reports at once",
                    "value": _problem(
                        HTTPStatus.SERVICE_UNAVAILABLE, ErrorCode.UNAVAILABLE, AiUsageMessage.REPORTS_BUSY
                    ),
                },
                "database": {
                    "summary": "MongoDB unreachable, or a report over its time limit",
                    "value": _problem(
                        HTTPStatus.SERVICE_UNAVAILABLE, ErrorCode.UNAVAILABLE, ErrorMessage.MONGO_UNREACHABLE
                    ),
                },
            }
        }
    },
}
_INVALID = "A value is not allowed: `detail` says why; `errors` lists each value outside its list or limits."


def _error_answers(route: str) -> dict[int, Any]:
    """A route's error statuses: 422 and 404 from its error examples (those it has), and 503."""
    answers = {
        HTTPStatus.UNPROCESSABLE_ENTITY: _errors(route, HTTPStatus.UNPROCESSABLE_ENTITY, _INVALID),
        HTTPStatus.NOT_FOUND: _errors(
            route, HTTPStatus.NOT_FOUND, "No AI call is recorded for this request."
        ),
    }
    present = {
        int(status): answer
        for status, answer in answers.items()
        if answer["content"][Problem.MEDIA_TYPE]["examples"]
    }
    return present | {int(HTTPStatus.SERVICE_UNAVAILABLE): _UNAVAILABLE}


_GROUPS = ", ".join(AiUsageGroup)
_OUTCOMES = ", ".join(f"`{outcome}`" for outcome in AiUsageOutcome)
_FAILED = "{activity} {outcome} ({reason})".format(**EXAMPLE_ANSWERS["calls"]["a_failed_call"]["items"][0])

TOTALS_DOCS: dict[str, Any] = {
    "description": f"""**Use it for** dashboards and reports: AI calls added up over a time range, per
module and API call (the default) or per any mix of `group_by` ({_GROUPS}). Each row has its API call's
name, its counts, and each part of the work.

**Try it**
- Per module and API call, last {AiUsageLimits.DEFAULT_SPAN_DAYS} days: `GET /v1/ai-usage`
- Create scenario per day and per part, in Dubai time:
  `GET /v1/ai-usage?module=threat_scenarios&api=create_scenario&group_by=day&group_by=bucket&tz=Asia/Dubai`
- Per model in October:
  `GET /v1/ai-usage?group_by=model&since=2026-10-01T00:00:00Z&until=2026-11-01T00:00:00Z`

**Good to know**
- Counts come from hourly totals, {_LAG}; {_CACHED}.
- Whole hours: `since` rounds down, `until` rounds up; at most {AiUsageLimits.MAX_SPAN_DAYS} days.
- `requests` counts the API calls whose first AI call falls in the row; `total` adds up every row.
- Over {AiUsageLimits.MAX_GROUPS:,} rows, `truncated` is true: narrow the range or the filters.
- The modules and their API calls: see this group's notes above.""",
    "responses": {
        200: _answers(
            "totals",
            {"one_module": "Threat scenarios per API call", "per_day_and_part": "Per day and per part"},
        ),
        **_error_answers("/v1/ai-usage"),
    },
}

REQUESTS_DOCS: dict[str, Any] = {
    "description": f"""**Use it for** one session's API calls: which ones made AI calls, how many each, in
which parts and on which models, successful and failed. A session is a threat scenario run (with its
remediation plans) or a service mapping. Without `session_id`: every API call over a time range.

**Try it**
- One run: `GET /v1/ai-usage/requests?session_id={EXAMPLE_SESSION_ID}`
- Remediation plans of the last day: `GET /v1/ai-usage/requests?module=remediation`
- The next page: the same call with `after` set to the answer's `next`.

**Good to know**
- Newest API call first. Open one with report 3, by its `request_id`.
- With `session_id` the list is live, and `summary` adds up the whole session (every page).
- Without it: at most {AiUsageLimits.MAX_SPAN_DAYS} days (default the last day), {_LAG}; {_CACHED}.""",
    "responses": {
        200: _answers(
            "requests", {"one_session": "One run, 2 per page", "a_range": "Remediation plans, 2 per page"}
        ),
        **_error_answers("/v1/ai-usage/requests"),
    },
}

REQUEST_DOCS: dict[str, Any] = {
    "description": f"""**Use it for** one API call: what it asked the AI to do (each activity, with its
part, name, description and model), how many AI calls each took, and how many failed.

**Try it:** `GET /v1/ai-usage/requests/{EXAMPLE_REQUEST_ID}`

**Good to know**
- `request_id` is the `X-Request-Id` header the API call answered with, or a `request_id` from report 2.
- Live (not cached). 404 while the call has made no AI call (none needed, or still queued).""",
    "responses": {
        200: _answers("request", {"create_scenario": "One Create scenario call"}),
        **_error_answers(_REQUEST_ROUTE),
    },
}

CALLS_DOCS: dict[str, Any] = {
    "description": f"""**Use it for** every AI attempt of one API call or one session, newest first: when, the
activity, the model, the outcome and why it failed, its try within its ask, tokens and seconds. Use it to see
why calls failed or were retried.

**Try it**
- One API call: `GET /v1/ai-usage/calls?request_id={EXAMPLE_REQUEST_ID}&limit=20`
- One session: `GET /v1/ai-usage/calls?session_id={EXAMPLE_SESSION_ID}`

**Good to know**
- Give `request_id` or `session_id`. Live (not cached).
- The attempts of one ask share `ask_id`; `try_no` counts them from 1 (retries, a fallback model).
- `outcome`: one of {_OUTCOMES}; `reused` is an earlier answer used again (no attempt, `try_no` null).""",
    "responses": {
        200: _answers(
            "calls",
            {"first_page": "One API call, 2 per page", "a_failed_call": f"A failed attempt: {_FAILED}"},
        ),
        **_error_answers("/v1/ai-usage/calls"),
    },
}
