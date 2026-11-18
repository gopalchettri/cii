"""Celery task for one Service Mapper run, under the fenced MongoDB job lease."""

import time

from celery import Task

from app import ai
from app.ai.chat import TruncatedAiAnswer, UnreadableAiAnswer
from app.core.constants import Collection, ErrorCode, TaskName
from app.core.exceptions import JobFailed
from app.crud import service_mapper as crud
from app.crud.jobs import JobLease
from app.domain.service_mapper.catalog import catalog_snapshot
from app.domain.service_mapper.generate import generate_result
from app.worker.celery_app import celery_app
from app.worker.jobs import run_leased_job

_TOO_LONG = (
    "The AI answer was too long for the model; lower SERVICE_MAPPER_UPSTREAM_TOTAL_COUNT or "
    "SERVICE_MAPPER_DOWNSTREAM_TOTAL_COUNT."
)


@celery_app.task(name=TaskName.MAP_SERVICES, bind=True)
def map_services(self: Task, record_id: str, epoch: int) -> None:
    run_leased_job(
        self, Collection.SERVICE_MAPPINGS, record_id, epoch, generate_run, fields=("request", "limits", "result")
    )


def generate_run(lease: JobLease) -> None:
    """One run: the services the mapping does not hold yet, added after those it holds."""
    started = time.perf_counter()
    catalog = catalog_snapshot()
    catalog_read = time.perf_counter()
    try:
        found = generate_result(ai.chat.get_service_mapper_chat_model(), catalog, lease.record, lease.epoch)
    except UnreadableAiAnswer as exc:
        raise JobFailed(
            ErrorCode.INTERNAL_ERROR, "The AI answer did not satisfy the Service Mapper output contract."
        ) from exc
    except TruncatedAiAnswer as exc:
        raise JobFailed(ErrorCode.INTERNAL_ERROR, _TOO_LONG) from exc
    crud.finish_run(
        lease, found, {"catalog_s": catalog_read - started, "services_s": time.perf_counter() - catalog_read}
    )
