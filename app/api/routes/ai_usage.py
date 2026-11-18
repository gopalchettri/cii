"""AI usage reports for dashboards (no key, owner 2026-10-29): counts only, never a prompt or an answer.
Reports run and render on threads of their own, never the UI routes' or status streams': at most
REPORTS_AT_ONCE at once per API process; one more waits REPORT_SLOT_WAIT_SECONDS for a place, then answers 503."""

import asyncio
import contextvars
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Annotated, Any

from fastapi import APIRouter, Path, Query, Response
from pydantic import BaseModel

from app.api.openapi_ai_usage import CALLS_DOCS, EXAMPLE_REQUEST_ID, REQUEST_DOCS, REQUESTS_DOCS, TOTALS_DOCS
from app.core.constants import AiUsageLimits, AiUsageMessage, ApiTag
from app.core.database import get_mongodb
from app.core.exceptions import Unavailable
from app.domain import ai_usage
from app.schemas.ai_usage import (
    RequestUsageDetail,
    RequestUsageList,
    RequestUsageQuery,
    UsageCallList,
    UsageCallQuery,
    UsageTotals,
    UsageTotalsQuery,
)

router = APIRouter(prefix="/v1/ai-usage", tags=[ApiTag.AI_USAGE])

#: The reports' own threads (asyncio's default executor also runs the status streams' reads).
_THREADS = ThreadPoolExecutor(AiUsageLimits.REPORTS_AT_ONCE, thread_name_prefix="ai-usage-report")
_REPORTS = asyncio.Semaphore(AiUsageLimits.REPORTS_AT_ONCE)


async def _report(shape: type[BaseModel], work: Callable[[], dict[str, Any]]) -> Response:
    try:
        async with asyncio.timeout(AiUsageLimits.REPORT_SLOT_WAIT_SECONDS):
            await _REPORTS.acquire()
    except TimeoutError as exc:
        raise Unavailable(AiUsageMessage.REPORTS_BUSY) from exc
    try:
        run = contextvars.copy_context().run  # the request's log fields
        body = await asyncio.get_running_loop().run_in_executor(_THREADS, run, lambda: _rendered(shape, work()))
    finally:
        _REPORTS.release()
    return Response(body, media_type="application/json")


def _rendered(shape: type[BaseModel], report: dict[str, Any]) -> bytes:
    return shape.model_validate(report).model_dump_json().encode()


@router.get("", response_model=UsageTotals, summary="1. AI calls added up (dashboards)", **TOTALS_DOCS)
async def read_ai_usage_totals(query: Annotated[UsageTotalsQuery, Query()]) -> Response:
    """AI calls added up per `group_by` over a time range (Swagger's text: TOTALS_DOCS)."""
    return await _report(UsageTotals, lambda: ai_usage.summarize_ai_usage(get_mongodb(), query))


@router.get("/requests", response_model=RequestUsageList, summary="2. AI calls per request", **REQUESTS_DOCS)
async def list_ai_usage_requests(query: Annotated[RequestUsageQuery, Query()]) -> Response:
    """One entry per API call of a session or a time range, newest first (Swagger's text: REQUESTS_DOCS)."""
    return await _report(RequestUsageList, lambda: ai_usage.list_request_ai_usage(get_mongodb(), query))


@router.get(
    "/requests/{request_id}",
    response_model=RequestUsageDetail,
    summary="3. One request's AI calls by activity",
    **REQUEST_DOCS,
)
async def read_ai_usage_request(
    request_id: Annotated[
        str,
        Path(
            max_length=64,
            description="The API call's X-Request-Id, or a `request_id` from report 2.",
            openapi_examples={"create_scenario": {"summary": "A Create scenario call", "value": EXAMPLE_REQUEST_ID}},
        ),
    ],
) -> Response:
    """One API call's counts, then each activity (Swagger's text: REQUEST_DOCS)."""
    return await _report(RequestUsageDetail, lambda: ai_usage.get_request_ai_usage(get_mongodb(), request_id))


@router.get("/calls", response_model=UsageCallList, summary="4. Every AI call of a request or session", **CALLS_DOCS)
async def list_ai_usage_calls(query: Annotated[UsageCallQuery, Query()]) -> Response:
    """Each AI attempt of a request or session, newest first (Swagger's text: CALLS_DOCS)."""
    return await _report(UsageCallList, lambda: ai_usage.list_ai_usage_calls(get_mongodb(), query))
