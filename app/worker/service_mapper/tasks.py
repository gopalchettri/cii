"""Celery entry point for one Service Mapper generation."""

from celery import Task

from app.core.constants import Collection, TaskName
from app.data_access.jobs.job_repository import JobLease
from app.worker.celery_app import celery_app
from app.worker.jobs import run_leased_job


@celery_app.task(name=TaskName.MAP_SERVICES, bind=True)
def map_services(self: Task, record_id: str, epoch: int) -> None:
    from app import container

    def generate(lease: JobLease) -> None:
        container.get_service_mapper_job().generate(lease)

    run_leased_job(
        self,
        Collection.SERVICE_MAPPINGS,
        record_id,
        epoch,
        generate,
        fields=("request", "limits", "pending_archive"),
    )
