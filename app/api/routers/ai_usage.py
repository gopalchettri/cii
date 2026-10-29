"""AI usage reports, for dashboards: how many AI calls each module, API call, request and session made, in
which part of the work, on which model, and how many failed. No admin key and no API key (owner,
2026-10-29); counts only, never a prompt or an answer. Read from the top: totals, then a session's requests,
then one request's activities, then its every call. Report work runs on threads of its own (never the ones
the UI's routes or status streams use), at most AiUsageLimits.REPORTS_AT_ONCE reports computed and
KEPT_REPORTS_AT_ONCE read from Redis at a time per API process; one more waits REPORT_SLOT_WAIT_SECONDS for
a place, then answers 503. Each answer is also checked and written as JSON bytes on those threads: the event
loop every route shares only sends it. With no key, report load can never hold the UI's routes back."""

import asyncio
import contextvars
import functools
from collections.abc import AsyncIterator, Callable
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Path, Query, Response
from pydantic import BaseModel

from app.container import get_ai_usage_service
from app.core.constants import AiUsageLimits, AiUsageMessage, ApiTag
from app.core.exceptions import Unavailable
from app.models.ai_usage.usage_report import (
    RequestUsageDetail,
    RequestUsageList,
    RequestUsageQuery,
    UsageCallList,
    UsageCallQuery,
    UsageTotals,
    UsageTotalsQuery,
)
from app.services.ai_usage.ai_usage_service import AiUsageService

router = APIRouter(prefix="/v1/ai-usage", tags=[ApiTag.AI_USAGE])

Usage = Annotated[AiUsageService, Depends(get_ai_usage_service)]
#: The reports' own threads, one per place below: asyncio's default executor also runs the status streams'
#: reads, so report load there could stall them.
_THREADS = ThreadPoolExecutor(
    AiUsageLimits.REPORTS_AT_ONCE + AiUsageLimits.KEPT_REPORTS_AT_ONCE, thread_name_prefix="ai-usage-report"
)
#: Reports this process computes now, and reports it reads from Redis now (the API process's one event loop).
_REPORTS = asyncio.Semaphore(AiUsageLimits.REPORTS_AT_ONCE)
_KEPT_REPORTS = asyncio.Semaphore(AiUsageLimits.KEPT_REPORTS_AT_ONCE)


async def _report(
    shape: type[BaseModel],
    work: Callable[[], dict[str, Any]],
    kept: Callable[[], dict[str, Any] | None] | None = None,
) -> Response:
    """The report as `shape`'s JSON: the one Redis holds (`kept`), else `work`'s, each in a place of its own
    kind. Read, checked and written as JSON bytes on the reports' threads, never on the event loop."""
    if kept is not None:
        async with _place(_KEPT_REPORTS):
            body = await _on_report_thread(_rendered_if_kept, shape, kept)
        if body is not None:
            return Response(body, media_type="application/json")
    async with _place(_REPORTS):
        body = await _on_report_thread(lambda: _rendered(shape, work()))
    return Response(body, media_type="application/json")


@asynccontextmanager
async def _place(places: asyncio.Semaphore) -> AsyncIterator[None]:
    """One of `places`, waited for up to REPORT_SLOT_WAIT_SECONDS (503 after that), freed at the end."""
    try:
        async with asyncio.timeout(AiUsageLimits.REPORT_SLOT_WAIT_SECONDS):
            await places.acquire()
    except TimeoutError as exc:
        raise Unavailable(AiUsageMessage.REPORTS_BUSY) from exc
    try:
        yield
    finally:
        places.release()


async def _on_report_thread[Result](work: Callable[..., Result], *args: Any) -> Result:
    """`work` on one of the reports' own threads, with the request's context (its log fields)."""
    run = functools.partial(contextvars.copy_context().run, work, *args)
    return await asyncio.get_running_loop().run_in_executor(_THREADS, run)


def _rendered(shape: type[BaseModel], report: dict[str, Any]) -> bytes:
    """The report checked against `shape` and written as JSON, as FastAPI would write its response_model."""
    return shape.model_validate(report).model_dump_json().encode()


def _rendered_if_kept(shape: type[BaseModel], kept: Callable[[], dict[str, Any] | None]) -> bytes | None:
    report = kept()
    return None if report is None else _rendered(shape, report)


@router.get("", response_model=UsageTotals, summary="1. AI calls added up (dashboards)")
async def read_ai_usage_totals(query: Annotated[UsageTotalsQuery, Query()], service: Usage) -> Response:
    """Counts per `group_by` (default module and API call; also hour, day, month, bucket, task, model,
    entity_id, client_id) over `since`..`until` (default the last 30 days, at most 366) in `tz`: AI calls,
    successful, failed, API calls (`requests`), tokens, and each part (threats, scenario, controls,
    remediation, service_mapper). Kept per hour, up to 5 minutes behind; cached 60 s."""
    return await _report(
        UsageTotals, lambda: service.summarize_ai_usage(query), lambda: service.kept_ai_usage_totals(query)
    )


@router.get("/requests", response_model=RequestUsageList, summary="2. AI calls per request")
async def list_ai_usage_requests(query: Annotated[RequestUsageQuery, Query()], service: Usage) -> Response:
    """One entry per API call, newest first: its API (`api_label`, `api_description`), its AI calls per
    part and per model, successful and failed. With `session_id`: that session's calls, live, and its totals
    (`summary`); without, a range of at most 366 days (default the last day), up to 5 minutes behind. `next`
    gives the next page."""
    return await _report(
        RequestUsageList,
        lambda: service.list_request_ai_usage(query),
        lambda: service.kept_request_ai_usage(query),
    )


@router.get(
    "/requests/{request_id}",
    response_model=RequestUsageDetail,
    summary="3. One request's AI calls by activity",
)
async def read_ai_usage_request(request_id: Annotated[str, Path(max_length=64)], service: Usage) -> Response:
    """The request's counts, then each activity: its part, name and one-line description, its model, and
    its AI calls, successful and failed. 404 when no AI call is recorded for the request."""
    return await _report(RequestUsageDetail, lambda: service.get_request_ai_usage(request_id))


@router.get("/calls", response_model=UsageCallList, summary="4. Every AI call of a request or session")
async def list_ai_usage_calls(query: Annotated[UsageCallQuery, Query()], service: Usage) -> Response:
    """Each AI attempt (and each earlier answer reused), newest first: when, its activity and description,
    model, outcome and reason, try number within its ask, tokens and seconds. Needs `request_id` or
    `session_id`; `next` gives the next page."""
    return await _report(UsageCallList, lambda: service.list_ai_usage_calls(query))
