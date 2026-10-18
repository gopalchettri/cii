"""Composition root: builds the FastAPI app (routers, middleware, error handlers) and runs start-up and
shutdown."""

import asyncio
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import container
from app.api.errors import register_exception_handlers
from app.api.middleware import AnswerUnexpectedErrors, RequestContextMiddleware
from app.api.openapi_docs import API_DESCRIPTION, OPENAPI_TAGS
from app.api.routers import scenario
from app.api.routers.admin import router as admin_router
from app.api.routers.external_intelligence import router as external_intelligence_router
from app.api.routers.health import router as health_router
from app.api.routers.jobs import router as jobs_router
from app.api.routers.library import router as library_router
from app.api.routers.remediation import router as remediation_router
from app.api.routers.service_mapper import router as service_mapper_router
from app.core.config import get_settings
from app.core.constants import Header
from app.core.logging import configure_logging
from app.realtime.event_hub import EventHub


def _ignore_client_gone(loop: asyncio.AbstractEventLoop, context: dict[str, Any]) -> None:
    """A browser that closed its live-update stream first makes Windows' event loop raise ConnectionResetError
    (WinError 10054) in its own clean-up, printed as a traceback; the client is simply gone (G221). Anything
    else goes to the default handler, as before."""
    if isinstance(context.get("exception"), ConnectionResetError) and "_call_connection_lost" in str(
        context.get("message", "")
    ):
        return
    loop.default_exception_handler(context)


@asynccontextmanager
async def application_lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    configure_logging(get_settings(), "api")
    asyncio.get_running_loop().set_exception_handler(_ignore_client_gone)
    container.set_up_api()
    app.state.event_hub = EventHub()  # one Redis subscription for every live-update stream
    yield
    await app.state.event_hub.close()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="DESC - Critical Information Infrastructure",
        version="1.0.0",
        description=API_DESCRIPTION,
        openapi_tags=OPENAPI_TAGS,
        lifespan=application_lifespan,
    )
    # Added first = innermost: an unexpected 500 still passes CORS and gets a request id.
    app.add_middleware(AnswerUnexpectedErrors)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],  # exactly the methods the routers use
        allow_headers=[h.value for h in Header] + ["Content-Type"],
        expose_headers=[Header.REQUEST_ID],
    )
    app.add_middleware(RequestContextMiddleware)  # added last = outermost: CORS answers get a request id too
    register_exception_handlers(app)
    # In the order a tester sets up and tests (app/api/openapi_docs.py): Swagger lists them so.
    app.include_router(health_router)
    app.include_router(admin_router)
    app.include_router(external_intelligence_router)
    app.include_router(scenario.router)
    app.include_router(scenario.review_router)
    app.include_router(remediation_router)
    app.include_router(jobs_router)
    app.include_router(scenario.events_router)
    app.include_router(library_router)
    app.include_router(service_mapper_router)
    return app


app = create_app()
