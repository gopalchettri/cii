"""Application errors: each fixes its HTTP status and error code (app/api/errors.py turns them into problem
responses, titled with the status phrase), and which driver errors mean a store is unreachable."""

from http import HTTPStatus
from typing import Any, ClassVar

from pymongo.errors import ConnectionFailure as MongoConnectionFailure
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import TimeoutError as RedisTimeoutError

from app.core.constants import ErrorCode, ErrorMessage, IntelMessage, Limits

#: Driver errors meaning "the store is unreachable right now" (timeouts, lost connections, no primary).
#: The API answers them with 503 + Retry-After; workers retry them with back-off.
MONGO_UNAVAILABLE_ERRORS: tuple[type[Exception], ...] = (MongoConnectionFailure,)


REDIS_UNAVAILABLE_ERRORS: tuple[type[Exception], ...] = (RedisConnectionError, RedisTimeoutError)


class AppError(Exception):
    """Base error: each subclass fixes its HTTP status and error code; with no detail, the detail is the
    status phrase."""

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
        """`reason`: which rule refused it (409, e.g. active_session_exists) · `errors`: the fields at fault
        (422, `[{field, message}]`) · `details`: facts the caller can act on (the active session's id)."""
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


class SetupError(AppError):
    """The server's own set-up is wrong (a procedure, a setting): 500 naming what to fix, logged."""

    status, code = 500, ErrorCode.SETUP_ERROR


class Unavailable(AppError):
    status, code = 503, ErrorCode.UNAVAILABLE
    # Set here, not by each raiser: every 503 tells the caller when to retry, whoever raised it.
    default_retry_after = Limits.RETRY_AFTER_SECONDS


class LeaseLost(Exception):
    """This job no longer owns its record (its owner cancelled or deleted the run, G214; or its lease ran out
    and another delivery took it over): stop without writing anything, and make no more AI calls."""


class JobFailed(Exception):
    """A job's own final error, e.g. plan_refused: run_leased_job fails the job with this code and message and
    never retries it (a retry cannot change the asset's facts or the library)."""

    def __init__(self, code: ErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class PlanRefused(JobFailed):
    """The planner cannot plan this asset at all (its systems' facts do not fit the model input, or no threat
    actor is live): the run fails with this code and a message written for the user, never a smaller plan in
    silence."""


class PathNotWritable(Exception):
    """One planned path lacks what its scenario needs (its one threat, a type and name, an acting attacker, a
    system of the run): its failure card says why, and no AI is asked to invent the missing fact (spec v4.0
    §7.4.1). A retry cannot change a frozen plan, so the card is final for this attempt."""

    def __init__(self, path_id: str, problem: str, code: ErrorCode = ErrorCode.INVALID_PLAN) -> None:
        self.code = code
        self.message = ErrorMessage.PATH_NOT_WRITABLE.format(path_id=path_id, problem=problem)
        super().__init__(self.message)


class ControlsNotMapped(Exception):
    """One scenario's controls cannot be mapped for a reason a retry cannot change now (the control library is
    empty, or no control fits its asset and systems): its controls fail with this code and message, and the
    sweep tries again later, after a curator may have changed the library (spec v4.0 §7.5.2, §7.5.9)."""

    def __init__(self, code: ErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class IntelFetchFailed(Exception):
    """An external intelligence source could not be read (no answer, a refusal, an unexpected format): the
    refresh of that source fails, the others go on, and the last good data stays in use. Not an AppError:
    it never reaches an API caller."""

    def __init__(self, message: IntelMessage, **fields: object) -> None:
        self.message = message.format(**fields)
        super().__init__(self.message)
