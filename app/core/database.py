"""Database clients: MongoDB for TSG data, SQL Server through stored procedures only."""

from typing import Any, Final

import pyodbc
from pymongo import MongoClient
from pymongo.collection import Collection as MongoCollection
from pymongo.database import Database
from pymongo.errors import OperationFailure
from redis import Redis
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.exc import TimeoutError as PoolTimeoutError

from app.core.config import get_settings
from app.core.constants import ErrorMessage, StoredProcedure, Timeouts
from app.core.exceptions import Unavailable
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


@singleton
def get_mongodb() -> Database:
    settings = get_settings()
    client: MongoClient = MongoClient(
        settings.mongo_url,
        serverSelectionTimeoutMS=Timeouts.MONGO_MS,
        connectTimeoutMS=Timeouts.MONGO_MS,
        socketTimeoutMS=Timeouts.MONGO_SOCKET_MS,  # pymongo's default is no limit
        waitQueueTimeoutMS=Timeouts.MONGO_MS,  # every pooled connection busy: fail fast, never wait for ever
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


@singleton
def get_redis_client() -> Redis:
    return Redis.from_url(
        get_settings().redis_url,
        socket_timeout=Timeouts.REDIS_SECONDS,
        socket_keepalive=True,
        health_check_interval=Timeouts.REDIS_HEALTH_CHECK_SECONDS,
        decode_responses=True,
    )


class StoredProcedureClient:
    """The only way the app talks to SQL Server: call a named procedure, get back its result sets."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def execute_procedure(self, procedure: StoredProcedure, **params: Any) -> list[list[Row]]:
        args = ", ".join(f"@{name}=?" for name in params)
        sql = f"EXEC dbo.{procedure} {args}"  # noqa: S608 — procedure is an enum, params are bound
        try:
            # Inside the try: an unreachable server fails at connect, not at execute.
            connection = self._engine.raw_connection()
            try:
                cursor = connection.cursor()
                cursor.execute(sql, *params.values())
                return _read_all_result_sets(cursor)
            finally:
                connection.close()
        except SQL_UNAVAILABLE_ERRORS as exc:
            raise Unavailable(ErrorMessage.SQL_UNREACHABLE) from exc

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
