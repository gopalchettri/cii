"""An unreachable MongoDB, Redis or SQL Server answers 503 + Retry-After with a clear message, never a 500."""

import pyodbc
import pytest
from fastapi.testclient import TestClient
from pymongo.errors import AutoReconnect, ServerSelectionTimeoutError
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import TimeoutError as RedisTimeoutError
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url

from app.core.config import get_settings
from app.core.constants import ErrorCode, ErrorMessage, Limits, StoredProcedure, Timeouts
from app.core.database import StoredProcedureClient, get_stored_procedure_client
from app.core.exceptions import Unavailable


def test_every_sql_call_has_a_query_timeout() -> None:
    """The cause of a possible hang: pyodbc waits for ever by default (timeout 0)."""
    connection = get_stored_procedure_client()._engine.raw_connection()
    try:
        assert connection.driver_connection.timeout == Timeouts.SQL_QUERY_SECONDS
    finally:
        connection.close()


def test_a_procedure_call_leaves_no_transaction_for_the_pool_to_roll_back() -> None:
    """Before: pyodbc opened an outer transaction that nothing committed, and the pool rolled it back when the
    connection was returned, so a write procedure would report success and save nothing."""
    connection = get_stored_procedure_client()._engine.raw_connection()
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT TOP 1 name FROM sys.objects")
        cursor.fetchall()
        cursor.execute("SELECT @@TRANCOUNT")
        assert cursor.fetchone()[0] == 0
    finally:
        connection.close()


def test_a_timed_out_query_is_an_operational_error_so_it_becomes_unavailable() -> None:
    connection = create_engine(get_settings().db_dsn).raw_connection()
    connection.driver_connection.timeout = 1
    try:
        with pytest.raises(pyodbc.OperationalError):
            connection.cursor().execute("WAITFOR DELAY '00:00:03'")
    finally:
        connection.close()


def test_an_unreachable_sql_server_raises_unavailable_at_connect() -> None:
    """The cause of the old 500: the connect sat outside the try, so its error escaped unconverted."""
    nothing_listens = make_url(get_settings().db_dsn).set(host="127.0.0.1", port=1)
    client = StoredProcedureClient(create_engine(nothing_listens, connect_args={"timeout": 1}))
    with pytest.raises(Unavailable, match=ErrorMessage.SQL_UNREACHABLE):
        client.execute_procedure(StoredProcedure.GET_LIBRARY_STAMP)


CASES = [
    (ServerSelectionTimeoutError("no servers"), ErrorMessage.MONGO_UNREACHABLE),
    (AutoReconnect("connection lost"), ErrorMessage.MONGO_UNREACHABLE),
    (RedisConnectionError("refused"), ErrorMessage.REDIS_UNREACHABLE),
    (RedisTimeoutError("timed out"), ErrorMessage.REDIS_UNREACHABLE),
    # Our own Unavailable raised without retry_after (as the AI gateways do): the header must come.
    (Unavailable(ErrorMessage.MONGO_UNREACHABLE), ErrorMessage.MONGO_UNREACHABLE),
]


@pytest.mark.parametrize(("driver_error", "expected_message"), CASES)
def test_unreachable_store_answers_503_with_retry_after(
    client: TestClient, driver_error: Exception, expected_message: ErrorMessage
) -> None:
    path = f"/test-only/raise/{type(driver_error).__name__}"

    def raise_driver_error() -> None:
        raise driver_error

    client.app.add_api_route(path, raise_driver_error)  # type: ignore[attr-defined]
    response = client.get(path)
    assert response.status_code == 503
    assert response.headers["Retry-After"] == str(Limits.RETRY_AFTER_SECONDS)
    assert response.json()["code"] == ErrorCode.UNAVAILABLE
    assert response.json()["detail"] == expected_message


def test_a_login_sql_server_refuses_is_unavailable_not_a_500() -> None:
    """While a database recovers or fails over, SQL Server refuses the login: pyodbc raises InterfaceError
    (SQLSTATE 28000), not OperationalError. It must still answer 503 and be retried."""
    no_such_database = make_url(get_settings().db_dsn).set(database="tsg_no_such_database")
    client = StoredProcedureClient(create_engine(no_such_database, connect_args={"timeout": 5}))
    with pytest.raises(Unavailable, match=ErrorMessage.SQL_UNREACHABLE):
        client.execute_procedure(StoredProcedure.GET_LIBRARY_STAMP)


def test_an_idle_redis_connection_is_checked_before_use() -> None:
    """A pooled connection a firewall dropped while idle used to fail the next publish or heartbeat after the
    5 s timeout; one idle REDIS_HEALTH_CHECK_SECONDS is now PINGed first and replaced if dead."""
    from app.core.database import get_redis_client

    options = get_redis_client().connection_pool.connection_kwargs
    assert options["health_check_interval"] == Timeouts.REDIS_HEALTH_CHECK_SECONDS
    assert options["socket_keepalive"] is True
