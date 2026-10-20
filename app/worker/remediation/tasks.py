"""The remediation task: tsg_write_plan, one plan version written under its job lease."""

from celery import Task

from app.core.constants import Collection, TaskName
from app.data_access.jobs.job_repository import JobLease
from app.worker.celery_app import celery_app
from app.worker.jobs import run_leased_job
from app.worker.remediation.remediation_plan_job import RemediationPlanJob


@celery_app.task(name=TaskName.WRITE_PLAN, bind=True)
def write_plan(self: Task, record_id: str, epoch: int) -> None:
    """Writes one remediation plan version under its job lease."""
    from app import container

    def write_version(lease: JobLease) -> None:
        container.get_remediation_plan_job().write_remediation_plan_version(lease)

    run_leased_job(
        self,
        Collection.REMEDIATIONS,
        record_id,
        epoch,
        write_version,
        fields=RemediationPlanJob.RECORD_FIELDS,
    )
