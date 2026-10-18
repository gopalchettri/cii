"""Probes for OpenShift and Prometheus: /health (alive), /ready (MongoDB, Redis and a worker on every queue;
SQL Server reported), /metrics. All three are public: no key, served on the API port."""

from fastapi import APIRouter, Response
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from app.core.constants import ApiTag, Dependency
from app.services.readiness import check_readiness_without_a_thread

router = APIRouter(tags=[ApiTag.HEALTH])


@router.get("/health", summary="1. Is the API alive?")
async def report_liveness() -> dict[str, str]:
    """Answers `{"status": "ok"}` while the process runs (the liveness probe). No key."""
    # async: no I/O, so it never waits for a request thread. A sync handler would queue behind /ready and
    # /metrics calls held by a hung store, and the liveness probe would then restart a healthy pod.
    return {"status": "ok"}


@router.get("/ready", summary="2. Are its stores and workers ready?")
async def report_readiness() -> JSONResponse:
    """200 `ready` when MongoDB and Redis answer and every queue has a live worker; else 503 `not_ready`,
    naming what is down. SQL Server is reported but never fails readiness: only the library routes need it,
    and a 503 here would take every route out of service. No key."""
    # async: public, so it must not hold one of the request threads while a slow store keeps it waiting.
    dependencies, workers = await check_readiness_without_a_thread()
    stores_up = all(up for name, up in dependencies.items() if name != Dependency.SQL)
    ready = stores_up and workers is not None and all(workers.values())
    return JSONResponse(
        {"status": "ready" if ready else "not_ready", "dependencies": dependencies, "workers": workers},
        status_code=200 if ready else 503,
    )


@router.get("/metrics", summary="Prometheus metrics", include_in_schema=False)
async def export_prometheus_metrics() -> Response:
    # The store and worker gauges are refreshed here, not only by /ready: on a laptop no probe calls /ready,
    # and a scrape should report the stores as they are now.
    await check_readiness_without_a_thread()
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
