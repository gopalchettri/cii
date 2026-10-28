"""Tests run against the real local MongoDB, SQL Server and Redis, in a separate Mongo database and two
spare Redis databases."""

import os
import shutil
import tempfile
from urllib.parse import urlsplit

from tests.checkout import CHECKOUT  # standard library only

TEST_DATABASE = f"cii_tsg_test_{CHECKOUT}"  # one per checkout: another checkout's run never drops it
os.environ["CII_MONGO_DB"] = TEST_DATABASE
# Tests never call a real reranker (each fakes it): a service address, so no test needs the local model's
# package (G265: a local reranker without it stops start-up).
os.environ["CII_RERANK_BASE_URL"] = "http://rerank.invalid"
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
# Scenario sets at their defaults, whatever the developer's .env says for a live test (G196).
os.environ["INITIAL_SET_SIZE"] = os.environ["NEXT_SET_SIZE"] = "6"
# The similarity thresholds at their defaults too (G200): a developer may set others for a live test.
os.environ.update(CONTROL_SIMILARITY_THRESHOLD="60", THREAT_SIMILARITY_THRESHOLD="75")
# Control selection at its defaults (G225); the word limits wide open (G226): a test's short sample draft is
# about its own rule, never its length. The length rule's tests set their own limits (test_word_limits.py).
os.environ.update(
    CONTROL_CANDIDATES="40",
    MIN_CONTROLS="1",
    MAX_CONTROLS="10",
    NEAREST_CONTROLS="1",
    THREAT_SCENARIO_WORD_LIMIT="1-100000",
    RISK_STATEMENT_WORD_LIMIT="1-100000",
    EVIDENCE_STATEMENT_WORD_LIMIT="1-100000",
)
# External intelligence OFF for the whole suite, whatever the developer's .env says: the app's own tests then
# exercise the original path. A test of the ON path asks for the `intel` fixture
# (tests/external_intelligence/conftest.py).
os.environ["EXTERNAL_INTELLIGENCE_ENABLED"] = "false"

from app.core.config import Settings  # noqa: E402  # reads .env only; builds no client


def _database_number(url: str) -> int:
    """The Redis database a URL names (none = 0)."""
    return int(urlsplit(url).path.lstrip("/") or 0)


def _test_redis_numbers(value: str, developers: set[int]) -> list[int]:
    """The two spare Redis databases of CII_TEST_REDIS_DATABASES: never the developer's own (their .env's, and
    0 and 1, the laptop stack's and v1's)."""
    numbers = [int(number) for number in value.split(",")]
    assert len(numbers) == len(set(numbers)) == 2, "CII_TEST_REDIS_DATABASES: two spare databases"
    assert not ({0, 1} | developers) & set(numbers), "CII_TEST_REDIS_DATABASES: never the developer's own"
    return numbers


#: The same Redis server, other databases. The laptop's stack (and v1) use 0 and 1: there its worker would
#: take the tests' job messages, and its /ready would count the tests' made-up workers as its own.
#: Two checkouts testing at once each set CII_TEST_REDIS_DATABASES to their own pair of EMPTY spare databases:
#: Redis databases are numbered, not named, so they cannot be per checkout by themselves (on this laptop 8-12
#: hold other data). The claim below stops a second run on the same pair, or on a pair sharing one database,
#: or a run on a database holding other data, at once: never a silent wipe.
_laptop = Settings()  # type: ignore[call-arg]  # the values come from .env
_TEST_REDIS_NUMBERS = _test_redis_numbers(
    os.environ.get("CII_TEST_REDIS_DATABASES", "14,15"),
    {_database_number(_laptop.redis_url), _database_number(_laptop.redis_celery_broker_url)},
)
TEST_REDIS_DATABASES = dict(zip(("redis_url", "redis_celery_broker_url"), _TEST_REDIS_NUMBERS, strict=True))
#: Who runs tests on the test Redis databases now, claimed in both and renewed while the run lasts (a crashed
#: run's claim ends by itself), and the mark a test database keeps between runs, so a database holding
#: anything else is never emptied.
TEST_RUN_KEY, TEST_RUN_CLAIM_SECONDS, TEST_DATABASE_MARK = "tsg:tests:running", 900, "tsg:tests:database"
TEST_RUN = f"{CHECKOUT}:{os.getpid()}"
TEST_RUN_RENEW_SECONDS = 60
for _field, _number in TEST_REDIS_DATABASES.items():
    _url = urlsplit(getattr(_laptop, _field))._replace(path=f"/{_number}").geturl()
    os.environ[f"CII_{_field.upper()}"] = _url

import math  # noqa: E402
import time  # noqa: E402
from collections.abc import Iterator  # noqa: E402

import pytest  # noqa: E402
import structlog  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from redis import Redis  # noqa: E402
from sqlalchemy import Engine  # noqa: E402

from app.container import create_all_indexes  # noqa: E402
from app.core import clock  # noqa: E402
from app.core.config import get_settings  # noqa: E402
from app.core.database import get_mongodb  # noqa: E402
from app.main import create_app  # noqa: E402
from app.worker.jobs import JOB_COLLECTIONS  # noqa: E402
from tests.sql_test_database import build_sql_test_database  # noqa: E402

ADMIN = {"X-Admin-Key": "test-admin-key"}

# No property required unless a test sets one (G197): the developer's .env may set them for a live test, and
# an empty environment value would fall back to .env (env_ignore_empty), so they are cleared here.
for _name in ("asset_properties_required", "system_properties_required"):
    setattr(get_settings(), _name, "")


@pytest.fixture(scope="session", autouse=True)
def empty_test_database() -> Iterator[None]:
    """Every run starts from an empty test database. Before, it was dropped only after a run that used
    `client`, so a partial run (-k) left records that a later run's reaper test then found and re-sent. Its
    indexes are made first, as at start-up: a rule an index enforces (one title per run) holds in every test,
    never only after the test that happened to make them."""
    database = get_mongodb()
    assert database.name == TEST_DATABASE  # never the developer's own data
    _claim_test_redis_databases(TEST_RUN)  # empties them too: messages no worker took, made-up workers' beats
    database.client.drop_database(TEST_DATABASE)
    create_all_indexes(JOB_COLLECTIONS)
    yield
    database.client.drop_database(TEST_DATABASE)
    _release_test_redis_databases(TEST_RUN)


def _test_redis(field: str) -> Redis:
    url = getattr(get_settings(), field)
    assert urlsplit(url).path == f"/{TEST_REDIS_DATABASES[field]}"  # never the developer's own data
    return Redis.from_url(url, socket_timeout=5, socket_connect_timeout=5)  # never hangs a run


def _claim_test_redis_databases(run: str) -> None:
    """One run at a time on each test Redis database: a second run (this checkout's or another's, on the same
    pair or on a pair sharing one database), or a run pointed at databases holding other data, stops at once
    with what to do, never emptying them. Each database claimed, then emptied and marked in one go."""
    numbers = ",".join(map(str, TEST_REDIS_DATABASES.values()))
    with _test_redis("redis_url") as redis, _test_redis("redis_celery_broker_url") as broker:
        databases = (redis, broker)
        if any(db.dbsize() and not db.exists(TEST_DATABASE_MARK) for db in databases):
            _stop(
                f"The Redis databases {numbers} hold data that is not a TSG test run's (or a run without "
                "this claim is using them). Set CII_TEST_REDIS_DATABASES to two empty spare databases."
            )
        refused = [
            db for db in databases if not db.set(TEST_RUN_KEY, run, nx=True, ex=TEST_RUN_CLAIM_SECONDS)
        ]
        if refused:
            holders = ", ".join(sorted({(db.get(TEST_RUN_KEY) or b"?").decode() for db in refused}))
            for db in databases:  # only the claims this run just made
                if db.get(TEST_RUN_KEY) == run.encode():
                    db.delete(TEST_RUN_KEY)
            _stop(
                f"Another test run ({holders}) is using the test Redis databases {numbers}. Wait for it to "
                f"end (a crashed run's claim ends within {TEST_RUN_CLAIM_SECONDS // 60} minutes), or set "
                "CII_TEST_REDIS_DATABASES to two empty spare databases."
            )
        for db in databases:
            _empty_and_mark(db, (TEST_RUN_KEY, run))


def _renew_test_redis_claim(run: str) -> None:
    """Keeps this run's claim on both databases alive; a claim that ran out stops the run at once, since
    another run may have emptied the databases since."""
    with _test_redis("redis_url") as redis, _test_redis("redis_celery_broker_url") as broker:
        for db in (redis, broker):
            if db.get(TEST_RUN_KEY) != run.encode():
                _stop(
                    "This run's claim on the test Redis databases ran out (a pause longer than "
                    f"{TEST_RUN_CLAIM_SECONDS // 60} minutes?); another run may have emptied them. Run again."
                )
            db.expire(TEST_RUN_KEY, TEST_RUN_CLAIM_SECONDS)


def _release_test_redis_databases(run: str) -> None:
    """Each emptied at the end only while still ours: a run whose claim ran out never empties another's."""
    with _test_redis("redis_url") as redis, _test_redis("redis_celery_broker_url") as broker:
        for db in (redis, broker):
            if db.get(TEST_RUN_KEY) == run.encode():
                _empty_and_mark(db)


def _empty_and_mark(db: Redis, claim: tuple[str, str] | None = None) -> None:
    with db.pipeline(transaction=True) as empty:
        empty.flushdb().set(TEST_DATABASE_MARK, 1)
        if claim:
            empty.set(*claim, ex=TEST_RUN_CLAIM_SECONDS)
        empty.execute()


def _stop(message: str) -> None:
    pytest.exit(message, returncode=3)


_claim_renewed_at = -math.inf


@pytest.fixture(autouse=True)
def claim_on_test_redis_kept() -> None:
    """Before a test, at most once a TEST_RUN_RENEW_SECONDS: this run's claim renewed, or the run stopped if
    it ran out."""
    # ponytail: renewed between tests only, so one test (or a debugger pause) longer than
    # TEST_RUN_CLAIM_SECONDS still loses it; a renewing thread if that ever happens.
    global _claim_renewed_at
    if time.monotonic() - _claim_renewed_at >= TEST_RUN_RENEW_SECONDS:
        _renew_test_redis_claim(TEST_RUN)
        _claim_renewed_at = time.monotonic()


@pytest.fixture(scope="session", autouse=True)
def loggers_never_cached() -> Iterator[None]:
    """The app caches each module's logger on first use (cache_logger_on_first_use, for speed): a logger first
    used inside a test's capture_logs kept writing to that capture, so a later test saw none of its lines
    (2026-10-12: test_library's warning after test_asset_types). In tests a logger is never cached, also once
    a test starts a worker or the app: configure_logging turned caching back on mid-test, and lifecycle's
    logger stayed bound to that test's set-up (2026-10-23: test_job_monitor's job lines after test_worker).
    For the whole run, so also while a session fixture starts the app (`client`) before any test begins."""
    configure = structlog.configure
    configure(cache_logger_on_first_use=False)
    never_cached = {"cache_logger_on_first_use": False}
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(structlog, "configure", lambda **options: configure(**options | never_cached))
        yield


@pytest.fixture(autouse=True)
def no_log_fields_left_over() -> None:
    """Each test starts with no request or job fields bound to its log lines: a test that bound them (a
    request through the middleware, a job) and ended before unbinding tagged every later test's lines."""
    structlog.contextvars.clear_contextvars()


@pytest.fixture(autouse=True)
def pod_clock_is_mongodbs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests run where MongoDB is: the shared clock's offset stays 0 and it never asks MongoDB its time
    (tests/test_clock.py measures it on purpose)."""
    monkeypatch.setattr(clock._clock, "_offset", 0.0)
    monkeypatch.setattr(clock._clock, "_next_check", math.inf)


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
