"""Admin use cases: API clients (create with the secret shown once, list, revoke, verify a caller's key) and
the embeddings build on request (#18, #19): the library's vectors made now instead of at the next 30-minute
build, one build at a time; its job record says how it went (app/worker/admin/library_indexes.py runs it)."""

import secrets
import uuid
from typing import Any

from app.core.callables import SendAdminJob
from app.core.clock import utc_now
from app.core.constants import (
    AdminJobKind,
    AdminJobMessage,
    ApiClientMessage,
    ApiKey,
    AuditAction,
    AuditTarget,
    ConflictReason,
    ErrorCode,
    Status,
    TaskName,
)
from app.core.exceptions import Conflict, DuplicateRecord, NotFound, Unavailable
from app.core.logging import current_request_id
from app.data_access.admin.admin_job_repository import AdminJobRepository
from app.data_access.admin.api_client_repository import ApiClientRepository
from app.data_access.admin.audit_repository import AuditRepository
from app.domain.admin.api_keys import could_be_minted_key, hash_api_key
from app.domain.shared.audit import admin_actor, audit_target

_KIND = AdminJobKind.EMBEDDINGS_BUILD


def _as_client(stored: dict[str, Any]) -> dict[str, Any]:
    """A stored client with its id as `client_id` (`_id` is only MongoDB's name for it)."""
    return {"client_id": stored.pop("_id"), **stored}


def queue_admin_job(
    jobs: AdminJobRepository,
    send: SendAdminJob,
    task: TaskName,
    job: dict[str, Any],
    in_progress: str,
    not_sent: str,
) -> None:
    """Create the queued job and send its message: 409 job_in_progress (details.job_id: the active one) while
    one of its kind is queued or running; a send that raises or returns False (503) fails the job, so a job no
    worker will run never blocks the next."""
    job_id = job["_id"]
    active_id = jobs.create_admin_job(job | {"created_at": utc_now(), "request_id": current_request_id()})
    if active_id != job_id:
        raise Conflict(in_progress, reason=ConflictReason.JOB_IN_PROGRESS, details={"job_id": active_id})
    sent = False
    try:
        sent = send(task, job_id)
    finally:
        if not sent:
            error = {"code": ErrorCode.UNAVAILABLE, "message": not_sent}
            jobs.update_admin_job_finished(job_id, utc_now(), error=error)
    if not sent:
        raise Unavailable(not_sent)


class AdminService:
    def __init__(
        self,
        api_clients: ApiClientRepository,
        admin_jobs: AdminJobRepository,
        audit: AuditRepository,
        send_admin_job: SendAdminJob,
    ) -> None:
        self._api_clients, self._admin_jobs, self._audit = api_clients, admin_jobs, audit
        self._send_admin_job = send_admin_job

    def create_api_client(
        self, name: str, description: str | None, created_by: str
    ) -> tuple[dict[str, Any], str]:
        """Create a client and return it with its secret. Only the secret's SHA-256 hash is stored."""
        api_key = ApiKey.PREFIX + secrets.token_urlsafe(ApiKey.RANDOM_BYTES)
        client_id, key_prefix = uuid.uuid4().hex, api_key[: ApiKey.SHOWN_PREFIX_LENGTH]
        client: dict[str, Any] = {
            "client_id": client_id,
            "name": name,
            "description": description,
            "key_hash": hash_api_key(api_key),
            "key_prefix": key_prefix,
            "active": True,
            "created_at": utc_now(),
            "created_by": created_by,
        }
        stored = {"_id": client_id} | {key: value for key, value in client.items() if key != "client_id"}
        try:
            self._api_clients.create(stored)
        except DuplicateRecord as exc:  # an active client has its name
            raise Conflict(ApiClientMessage.NAME_TAKEN.format(name=name)) from exc
        client.pop("key_hash")
        self._audit.create_audit_record(
            AuditAction.KEY_MINTED,
            admin_actor(created_by),
            audit_target(AuditTarget.API_CLIENT, client_id),
            after={"name": name, "key_prefix": key_prefix, "active": True},
        )
        return client, api_key

    def list_api_clients(self, active: bool | None) -> list[dict[str, Any]]:
        """Every client (or only active or revoked ones), newest first, never its key hash."""
        where = {} if active is None else {"active": active}
        listed = self._api_clients.list("without_key_hash", sort="-created_at", **where)
        return [_as_client(stored) for stored in listed]

    def revoke_api_client(self, client_id: str, revoked_by: str) -> dict[str, Any]:
        """Idempotent: revoking a revoked client returns it unchanged; only the first revoke is audited."""
        client = self._api_clients.revoke_api_client(client_id, revoked_by, utc_now())
        if client is not None:
            self._audit.create_audit_record(
                AuditAction.KEY_REVOKED,
                admin_actor(revoked_by),
                audit_target(AuditTarget.API_CLIENT, client_id),
                before={"active": True},
                after={"active": False},
            )
            return _as_client(client)
        client = self._api_clients.get("without_key_hash", _id=client_id)
        if client is None:
            raise NotFound(ApiClientMessage.NOT_FOUND.format(client_id=client_id))
        return _as_client(client)

    def get_api_client_id(self, raw_key: str) -> str | None:
        """The client id owning an active key, or None. A key that cannot be one TSG minted (wrong prefix or
        length) is refused without a MongoDB read: junk keys from anyone cost nothing."""
        if not could_be_minted_key(raw_key):
            return None
        return self._api_clients.get_active_client_id(hash_api_key(raw_key))

    def create_embeddings_build(self, requested_by: str) -> dict[str, Any]:
        """The queued build's id (queue_admin_job: 409 while one is queued or running, 503 when not sent)."""
        job_id = uuid.uuid4().hex
        job = {"_id": job_id, "kind": _KIND, "status": Status.QUEUED, "requested_by": requested_by}
        queue_admin_job(
            self._admin_jobs,
            self._send_admin_job,
            TaskName.BUILD_LIBRARY_INDEXES,
            job,
            AdminJobMessage.IN_PROGRESS,
            AdminJobMessage.NOT_SENT,
        )
        target = audit_target(AuditTarget.ADMIN_JOB, job_id)
        self._audit.create_audit_record(
            AuditAction.ADMIN_JOB_STARTED, admin_actor(requested_by), target, after={"kind": _KIND}
        )
        return {"job_id": job_id, "status": Status.QUEUED}

    def get_embeddings_build(self, job_id: str) -> dict[str, Any]:
        """One build job as the API shows it; 404 for any other job."""
        record = self._admin_jobs.get_admin_job(job_id, _KIND)
        if record is None:
            raise NotFound(AdminJobMessage.NOT_FOUND.format(job_id=job_id))
        return {"job_id": record.pop("_id"), **record}
