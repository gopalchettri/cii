"""Database clients: MongoDB for TSG data, SQL Server through stored procedures only."""

import ssl
from typing import Any, Final

import pyodbc
from pymongo import MongoClient
from pymongo.collection import Collection as MongoCollection
from pymongo.database import Database
from pymongo.errors import OperationFailure
from redis import Redis
from redis.backoff import NoBackoff
from redis.retry import Retry
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.exc import TimeoutError as PoolTimeoutError

from app.core.config import get_settings
from app.core.constants import ErrorMessage, StoredProcedure, Timeouts
from app.core.exceptions import Invalid, OutcomeUnknown, SetupError, Unavailable
from app.core.singletons import singleton

Row = dict[str, Any]

#: Errors meaning "SQL Server cannot serve us right now": an outage or timeout (OperationalError), a login
#: refused while a database recovers or fails over (InterfaceError, SQLSTATE 28000), or every pooled
#: connection busy past the pool's wait. All are answered 503 / retried, never a 500.
SQL_UNAVAILABLE_ERRORS: tuple[type[Exception], ...] = (
    pyodbc.OperationalError,
    pyodbc.InterfaceError,
    PoolTimeoutError,
)
_INDEX_OPTIONS_CONFLICT: Final = 85  # MongoDB: an index on these keys exists with other options
_DEADLOCK_SQLSTATE: Final = "40001"  # SQL Server chose the call as a deadlock victim and rolled it back


@singleton
def get_mongodb() -> Database:
    settings = get_settings()
    client: MongoClient = MongoClient(
        settings.mongo_url,
        serverSelectionTimeoutMS=Timeouts.MONGO_MS,
        connectTimeoutMS=Timeouts.MONGO_MS,
        socketTimeoutMS=Timeouts.MONGO_SOCKET_MS,  # pymongo's default is no limit
        waitQueueTimeoutMS=Timeouts.MONGO_MS,  # every pooled connection busy: fail fast, never wait for ever
        # A write a failover cannot roll back, whatever the server's default; a standalone (dev) takes it as
        # w:1. Bounded below the socket timeout, so a lagging replica set answers WTimeoutError (an outage).
        w="majority",
        wTimeoutMS=Timeouts.MONGO_MAJORITY_WRITE_MS,
        tz_aware=True,
    )
    return client[settings.mongo_db]


def expire_documents_after(collection: MongoCollection, field: str, seconds: int) -> None:
    """TTL index on `field`. A changed retention updates the existing index in place (collMod): create_index
    alone refuses different options, which would stop every start-up."""
    try:
        collection.create_index(field, expireAfterSeconds=seconds)
    except OperationFailure as exc:
        if exc.code != _INDEX_OPTIONS_CONFLICT:
            raise
        collection.database.command(
            "collMod", collection.name, index={"keyPattern": {field: 1}, "expireAfterSeconds": seconds}
        )


def redis_tls_options(url: str) -> dict[str, Any]:
    """The TLS options of every Redis client and the broker: a rediss:// server's certificate and host name
    always verified (against CII_REDIS_CA_FILE when set); none for a plain redis:// URL."""
    if not url.startswith("rediss://"):
        return {}
    return {
        "ssl_cert_reqs": ssl.CERT_REQUIRED,
        "ssl_ca_certs": get_settings().redis_ca_file or None,
        "ssl_check_hostname": True,
    }


@singleton
def get_redis_client() -> Redis:
    url = get_settings().redis_url
    return Redis.from_url(
        url,
        socket_timeout=Timeouts.REDIS_SECONDS,
        socket_keepalive=True,
        health_check_interval=Timeouts.REDIS_HEALTH_CHECK_SECONDS,
        decode_responses=True,
        # No hidden retries (redis-py 6+ defaults Redis() to 3 with back-off): fail within the timeout.
        retry=Retry(NoBackoff(), 0),
        **redis_tls_options(url),
    )


class StoredProcedureClient:
    """The only way the app talks to SQL Server: call a named procedure, get back its result sets."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def execute_procedure(self, procedure: StoredProcedure, **params: Any) -> list[list[Row]]:
        """Run one TSG procedure with bound parameters and return its result sets. Never sent (connect or pool
        wait failed) or a deadlock (rolled back): Unavailable; sent with its answer lost (a timeout, a broken
        link): OutcomeUnknown; a value refused: Invalid; the procedure itself broken: SetupError."""
        if not isinstance(procedure, StoredProcedure):  # the name goes into the SQL text: members only
            raise SetupError(ErrorMessage.PROCEDURE_NOT_ALLOWED.format(procedure=procedure))
        args = ", ".join(f"@{name}=?" for name in params)
        sql = f"EXEC dbo.{procedure} {args}"  # noqa: S608 — procedure is an enum, params are bound
        try:
            connection = self._engine.raw_connection()
        except SQL_UNAVAILABLE_ERRORS as exc:
            raise Unavailable(ErrorMessage.SQL_UNREACHABLE) from exc
        try:
            cursor = connection.cursor()
            cursor.execute(sql, *params.values())
            return _read_all_result_sets(cursor)
        except (pyodbc.DataError, pyodbc.IntegrityError) as exc:
            raise Invalid(ErrorMessage.SQL_VALUE_REFUSED) from exc
        except pyodbc.ProgrammingError as exc:
            raise SetupError(ErrorMessage.SQL_PROCEDURE_BROKEN) from exc
        except pyodbc.Error as exc:
            if exc.args and exc.args[0] == _DEADLOCK_SQLSTATE:
                raise Unavailable(ErrorMessage.SQL_DEADLOCK) from exc
            if isinstance(exc, SQL_UNAVAILABLE_ERRORS):
                raise OutcomeUnknown(ErrorMessage.SQL_ANSWER_LOST) from exc
            raise
        finally:
            connection.close()

    def close(self) -> None:
        """Close every pooled connection (worker shutdown)."""
        self._engine.dispose()

    def check_connection(self) -> None:
        """SQL Server answers: a connection is opened, or a pooled one pinged (pool_pre_ping), then returned.
        Never runs a procedure, so a readiness probe every few seconds costs SQL Server nothing."""
        self._engine.raw_connection().close()


def _read_all_result_sets(cursor: pyodbc.Cursor) -> list[list[Row]]:
    result_sets: list[list[Row]] = []
    while True:
        if cursor.description:
            columns = [column[0] for column in cursor.description]
            result_sets.append([dict(zip(columns, row, strict=True)) for row in cursor.fetchall()])
        if not cursor.nextset():
            return result_sets


@singleton
def get_stored_procedure_client() -> StoredProcedureClient:
    engine = create_engine(
        get_settings().db_dsn,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=10,
        pool_timeout=Timeouts.SQL_CONNECT_SECONDS,  # all 15 busy: answer 503 after 5 s, not 30
        connect_args={"timeout": Timeouts.SQL_CONNECT_SECONDS},  # pyodbc: login timeout only
    )

    @event.listens_for(engine, "connect")
    def set_up_connection(dbapi_connection: pyodbc.Connection, _record: object) -> None:
        # pyodbc's default query timeout is 0 = wait for ever. A timed-out call raises OperationalError
        # (HYT00), which execute_procedure turns into Unavailable like any other outage.
        dbapi_connection.timeout = Timeouts.SQL_QUERY_SECONDS
        # Each procedure owns its transaction (BEGIN/COMMIT inside it). Without autocommit, pyodbc opens an
        # outer transaction that nothing commits, and the pool rolls it back when the connection is returned:
        # a write procedure would report success and save nothing.
        dbapi_connection.autocommit = True

    return StoredProcedureClient(engine)
