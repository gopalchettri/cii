"""Tests run against the real local MongoDB, SQL Server and Redis, in a separate Mongo database and two
spare Redis databases."""

import os
import shutil
import tempfile
from urllib.parse import urlsplit

from tests.checkout import CHECKOUT  # standard library only

TEST_DATABASE = f"cii_tsg_test_{CHECKOUT}"  # one per checkout: another checkout's run never drops it
os.environ["CII_MONGO_DB"] = TEST_DATABASE
# Before any test imports litellm: its model table from the installed package, as the app does
# (app/ai/__init__.py), so the tests make no call to GitHub (a CI runner may have no internet access).
os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] = "True"
os.environ["CII_ADMIN_API_KEY"] = "test-admin-key"
# The tests' log lines go to a throwaway folder: the developer's .env says CII_LOG_DIR=logs, which the local
# Grafana reads, and it showed the tests' simulated Redis/MongoDB/SQL outages as real ones (2026-10-09).
# A real folder, not "": Settings ignores an empty value (env_ignore_empty) and would fall back to .env. One
# fixed folder, emptied at each run (a new mkdtemp folder per run was never deleted).
TEST_LOG_DIR = os.path.join(tempfile.gettempdir(), "cii-test-logs")
shutil.rmtree(TEST_LOG_DIR, ignore_errors=True)
os.makedirs(TEST_LOG_DIR, exist_ok=True)
os.environ["CII_LOG_DIR"] = TEST_LOG_DIR
# The step trace stays off unless a test turns it on (test_step_tracing.py): with the developer's
# DEBUG_STEP_OUTPUT=true, every app start-up in a test switched it on and cached the trace's logger, so later
# tests capturing step lines saw none (2026-10-11).
os.environ["DEBUG_STEP_OUTPUT"] = os.environ["DEBUG_STEP_DETAIL"] = "false"
# Scenario sets at their defaults, whatever the developer's .env says for a live test (G196).
os.environ["INITIAL_SET_SIZE"] = os.environ["NEXT_SET_SIZE"] = "6"
# The similarity thresholds at their defaults too (G200): a developer may set others for a live test.
os.environ.update(
    CONTROL_SIMILARITY_THRESHOLD="60", THREAT_SIMILARITY_THRESHOLD="75", ACTOR_SIMILARITY_THRESHOLD="0"
)

from app.core.config import Settings  # noqa: E402  # reads .env only; builds no client

#: The same Redis server, other databases. The laptop's stack (and v1) use 0 and 1: there its worker would
#: take the tests' job messages, and its /ready would count the tests' made-up workers as its own.
#: Two checkouts testing at once each set CII_TEST_REDIS_DATABASES to their own pair of EMPTY spare databases:
#: Redis databases are numbered, not named, so they cannot be per checkout by themselves (on this laptop 8-12
#: hold other data). The claim below stops a second run on the same pair, or a run on a database holding other
#: data, at once: never a silent wipe.
_TEST_REDIS_NUMBERS = [int(n) for n in os.environ.get("CII_TEST_REDIS_DATABASES", "14,15").split(",")]
assert len(set(_TEST_REDIS_NUMBERS)) == 2 and not {0, 1} & set(_TEST_REDIS_NUMBERS), "two spare databases"
TEST_REDIS_DATABASES = dict(zip(("redis_url", "redis_celery_broker_url"), _TEST_REDIS_NUMBERS, strict=True))
#: Who runs tests on the test Redis databases now (a crashed run's claim ends by itself), and the mark a test
#: database keeps between runs, so a database holding anything else is never emptied.
TEST_RUN_KEY, TEST_RUN_CLAIM_SECONDS, TEST_DATABASE_MARK = "tsg:tests:running", 900, "tsg:tests:database"
_laptop = Settings()  # type: ignore[call-arg]  # the values come from .env
for _field, _number in TEST_REDIS_DATABASES.items():
    _url = urlsplit(getattr(_laptop, _field))._replace(path=f"/{_number}").geturl()
    os.environ[f"CII_{_field.upper()}"] = _url

from collections.abc import Iterator  # noqa: E402

import pytest  # noqa: E402
import structlog  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from redis import Redis  # noqa: E402
from sqlalchemy import Engine  # noqa: E402

from app.core.config import get_settings  # noqa: E402
from app.core.database import get_mongodb  # noqa: E402
from app.main import create_app  # noqa: E402
from tests.sql_test_database import build_sql_test_database  # noqa: E402

ADMIN = {"X-Admin-Key": "test-admin-key"}

# No property required unless a test sets one (G197): the developer's .env may set them for a live test, and
# an empty environment value would fall back to .env (env_ignore_empty), so they are cleared here.
for _name in ("asset_properties_required", "system_properties_required"):
    setattr(get_settings(), _name, "")


@pytest.fixture(scope="session", autouse=True)
def empty_test_database() -> Iterator[None]:
    """Every run starts from an empty test database. Before, it was dropped only after a run that used
    `client`, so a partial run (-k) left records that a later run's reaper test then found and re-sent."""
    database = get_mongodb()
    assert database.name == TEST_DATABASE  # never the developer's own data
    run = f"{CHECKOUT}:{os.getpid()}"
    _claim_test_redis_databases(run)  # empties them too: messages no worker took, made-up workers' heartbeats
    database.client.drop_database(TEST_DATABASE)
    yield
    database.client.drop_database(TEST_DATABASE)
    _release_test_redis_databases(run)


def _test_redis(field: str) -> Redis:
    url = getattr(get_settings(), field)
    assert urlsplit(url).path == f"/{TEST_REDIS_DATABASES[field]}"  # never the developer's own data
    return Redis.from_url(url, socket_timeout=5, socket_connect_timeout=5)  # never hangs a run


def _claim_test_redis_databases(run: str) -> None:
    """One run at a time on the test Redis databases: a second run (this checkout's or another's), or a run
    pointed at databases holding other data, stops at once with what to do, never emptying them. Claimed,
    emptied and marked in one transaction per database."""
    numbers = ",".join(map(str, TEST_REDIS_DATABASES.values()))
    with _test_redis("redis_url") as redis, _test_redis("redis_celery_broker_url") as broker:
        if any(db.dbsize() and not db.exists(TEST_DATABASE_MARK) for db in (redis, broker)):
            _stop(
                f"The Redis databases {numbers} hold data that is not a TSG test run's (or a run without "
                "this claim is using them). Set CII_TEST_REDIS_DATABASES to two empty spare databases."
            )
        if not redis.set(TEST_RUN_KEY, run, nx=True, ex=TEST_RUN_CLAIM_SECONDS):
            holder = (redis.get(TEST_RUN_KEY) or b"?").decode()
            _stop(
                f"Another test run ({holder}) is using the test Redis databases {numbers}. Wait for it to "
                f"end (a crashed run's claim ends within {TEST_RUN_CLAIM_SECONDS // 60} minutes), or set "
                "CII_TEST_REDIS_DATABASES to two empty spare databases."
            )
        _empty_and_mark(broker)
        _empty_and_mark(redis, (TEST_RUN_KEY, run))


def _release_test_redis_databases(run: str) -> None:
    """Emptied at the end only while still ours: a run whose claim ran out never empties the next run's."""
    with _test_redis("redis_url") as redis, _test_redis("redis_celery_broker_url") as broker:
        if redis.get(TEST_RUN_KEY) == run.encode():
            _empty_and_mark(broker)
            _empty_and_mark(redis)


def _empty_and_mark(db: Redis, claim: tuple[str, str] | None = None) -> None:
    with db.pipeline(transaction=True) as empty:
        empty.flushdb().set(TEST_DATABASE_MARK, 1)
        if claim:
            empty.set(*claim, ex=TEST_RUN_CLAIM_SECONDS)
        empty.execute()


def _stop(message: str) -> None:
    pytest.exit(message, returncode=3)


@pytest.fixture(autouse=True)
def loggers_never_cached() -> None:
    """The app caches each module's logger on first use (cache_logger_on_first_use, for speed): a logger first
    used inside a test's capture_logs kept writing to that capture, so a later test saw none of its lines
    (2026-10-12: test_library's warning after test_asset_types). In tests a logger is never cached."""
    structlog.configure(cache_logger_on_first_use=False)


@pytest.fixture(autouse=True)
def no_log_fields_left_over() -> None:
    """Each test starts with no request or job fields bound to its log lines: a test that bound them (a
    request through the middleware, a job) and ended before unbinding tagged every later test's lines."""
    structlog.contextvars.clear_contextvars()


@pytest.fixture(scope="session")
def client(empty_test_database: None) -> Iterator[TestClient]:
    with TestClient(create_app()) as test_client:
        yield test_client


@pytest.fixture(scope="session")
def sql_test_engine() -> Iterator[Engine]:
    """The SQL test database (tests/sql_test_database.py), built once per test run: never DevTest5."""
    engine = build_sql_test_database()
    yield engine
    engine.dispose()
