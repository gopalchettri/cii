"""Application errors, each with its HTTP status and code, and the driver errors that mean a store is down."""

from http import HTTPStatus
from typing import Any, ClassVar

from pymongo.errors import ConnectionFailure as MongoConnectionFailure
from pymongo.errors import ExecutionTimeout as MongoExecutionTimeout
from pymongo.errors import WriteConcernError as MongoWriteConcernError
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import OutOfMemoryError as RedisOutOfMemoryError
from redis.exceptions import ReadOnlyError as RedisReadOnlyError
from redis.exceptions import TimeoutError as RedisTimeoutError

from app.core.constants import AiOutage, ErrorCode, ErrorMessage, IntelMessage, Limits

#: Unreachable, past its time limit, or a write the replicas did not confirm: the API answers 503, workers retry.
#: ponytail: a misconfigured write concern is retried as an outage too, until Lease.MAX_ATTEMPTS.
MONGO_UNAVAILABLE_ERRORS: tuple[type[Exception], ...] = (
    MongoConnectionFailure,
    MongoExecutionTimeout,
    MongoWriteConcernError,
)

#: Redis also refuses writes on a failover (READONLY replica) or when its memory is full.
REDIS_UNAVAILABLE_ERRORS: tuple[type[Exception], ...] = (
    RedisConnectionError,
    RedisTimeoutError,
    RedisReadOnlyError,
    RedisOutOfMemoryError,
)


class AppError(Exception):
    """Base error: each subclass fixes its HTTP status and code; the detail defaults to the status phrase."""

    status: ClassVar[int] = 500
    code: ClassVar[ErrorCode] = ErrorCode.INTERNAL_ERROR
    default_retry_after: ClassVar[int | None] = None  # seconds a caller should wait before retrying

    def __init__(
        self,
        detail: str | None = None,
        *,
        reason: str | None = None,
        errors: list[dict[str, str]] | None = None,
        details: dict[str, Any] | None = None,
        retry_after: int | None = None,
    ) -> None:
        """`reason`: the rule that refused it; `errors`: the fields at fault; `details`: facts to act on."""
        self.detail = detail or HTTPStatus(self.status).phrase
        super().__init__(self.detail)
        self.reason = reason
        self.errors = errors
        self.details = details
        self.retry_after = self.default_retry_after if retry_after is None else retry_after


class Invalid(AppError):
    status, code = 422, ErrorCode.VALIDATION_ERROR


class Unauthorized(AppError):
    status, code = 401, ErrorCode.UNAUTHORIZED


class Forbidden(AppError):
    status, code = 403, ErrorCode.FORBIDDEN


class NotFound(AppError):
    status, code = 404, ErrorCode.NOT_FOUND


class Conflict(AppError):
    status, code = 409, ErrorCode.CONFLICT


class DuplicateRecord(Conflict):
    """A unique index refused a write: `index_name` says which rule (e.g. one run per Idempotency-Key)."""

    def __init__(self, index_name: str) -> None:
        super().__init__(ErrorMessage.UNIQUE_RULE_BROKEN.format(index_name=index_name))
        self.index_name = index_name


class OperationInProgress(Conflict):
    """Another attempt of the same SQL Server write is still young: the API answers 409, a job retries."""


class SetupError(AppError):
    """The server's own set-up is wrong (a procedure, a setting): 500 naming what to fix, logged."""

    status, code = 500, ErrorCode.SETUP_ERROR


class Unavailable(AppError):
    status, code = 503, ErrorCode.UNAVAILABLE
    default_retry_after = Limits.RETRY_AFTER_SECONDS


class OutcomeUnknown(Unavailable):
    """A SQL Server call was sent but its answer was lost: retried through its tsg_sql_operations record."""


#: A store or AI service down for now, or a SQL write still in progress: the job is retried later.
TEMPORARY_ERRORS: tuple[type[Exception], ...] = (
    Unavailable,
    OperationInProgress,
    *MONGO_UNAVAILABLE_ERRORS,
    *REDIS_UNAVAILABLE_ERRORS,
)


class LeaseLost(Exception):
    """This job no longer owns its record: stop without writing anything, and make no more AI calls."""


class WaitingForAnotherJob(Exception):
    """Another job holds what this job needs: given back to look again soon, using none of its attempts."""


class CodedFailure(Exception):
    """A final error with its code and message."""

    def __init__(self, code: ErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class JobFailed(CodedFailure):
    """A job's own final error: run_leased_job fails the job with it and never retries."""


class PlanRefused(JobFailed):
    """The planner cannot plan this asset at all (no threat actor is live): the run fails."""


class PathNotWritable(Exception):
    """One planned path lacks what its scenario needs: its failure card says why, and no AI invents it."""

    def __init__(self, path_id: str, problem: str, code: ErrorCode = ErrorCode.INVALID_PLAN) -> None:
        self.code = code
        self.message = ErrorMessage.PATH_NOT_WRITABLE.format(path_id=path_id, problem=problem)
        super().__init__(self.message)


class ControlsNotMapped(CodedFailure):
    """One scenario's controls cannot be mapped now (empty library, nothing fits): the sweep tries later."""


class IntelFetchFailed(Exception):
    """An intelligence source could not be read: only its refresh fails, and its last good data stays."""

    def __init__(self, message: IntelMessage, **fields: object) -> None:
        self.message = message.format(**fields)
        super().__init__(self.message)


def outage_reason(error: BaseException) -> AiOutage | None:
    """Which AI outage an error carries (an Unavailable's reason); None for any other error."""
    reason = error.reason if isinstance(error, AppError) else None
    return AiOutage(reason) if reason and reason in AiOutage else None


def job_error_of(exc: Exception) -> dict[str, str]:
    """The failure as an admin job shows it: its own code and message, else only the exception's type."""
    if isinstance(exc, AppError):
        reason = outage_reason(exc)
        return {"code": exc.code, "message": exc.detail} | ({"reason": reason} if reason else {})
    if isinstance(exc, JobFailed):
        return {"code": exc.code, "message": exc.message}
    return {"code": ErrorCode.INTERNAL_ERROR, "message": type(exc).__name__}
