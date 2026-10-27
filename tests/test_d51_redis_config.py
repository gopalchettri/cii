"""Redis set-up: its eviction policy is named at start-up, every Redis client and the Celery broker verify a
rediss:// server, each component logs in to Redis as its own user, Celery never puts a job back by itself,
and one test run at a time owns the test Redis databases."""

import asyncio
import os
import ssl
from urllib.parse import urlsplit

import pytest
from celery import Celery
from redis.connection import SSLConnection

from app import container
from app.core import readiness
from app.core.broker import shared_celery_conf
from app.core.config import get_settings
from app.core.constants import LogEvent
from app.core.database import get_redis_client
from app.realtime import event_hub
from app.worker import celery_app
from tests import conftest
from tests.checkout import CHECKOUT
from tests.test_deploy import SECRETS_FILE, _all_deployments, _objects, _reads, _secrets

CA_FILE = "/etc/tsg/redis-ca/ca.crt"
TLS_URL = "rediss://tsg-test:secret@redis.example:6380/1"
#: Each pod component that talks to Redis, by its pod's component label; its login is Secret tsg-redis-<it>
#: (redis-exporter's: tsg-redis-exporter).
REDIS_COMPONENTS = {"api", "worker", "beat", "flower", "redis-exporter"}


class _RecordingLog:
    def __init__(self) -> None:
        self.lines: list[tuple[str, str, dict[str, object]]] = []

    def __getattr__(self, level: str):  # type: ignore[no-untyped-def]
        return lambda event, **fields: self.lines.append((level, event, fields))


class _RedisAnswering:
    """The app's Redis, answering INFO memory with `policy`, or raising it."""

    def __init__(self, policy: str | Exception) -> None:
        self.policy = policy

    def info(self, section: str) -> dict[str, object]:
        assert section == "memory"
        if isinstance(self.policy, Exception):
            raise self.policy
        return {"maxmemory_policy": self.policy, "used_memory": 1}


@pytest.mark.parametrize(
    ("policy", "level"), [("noeviction", "info"), ("allkeys-lru", "error"), ("volatile-ttl", "error")]
)
def test_start_up_names_redis_eviction_policy_and_an_evicting_one_is_an_error(
    monkeypatch: pytest.MonkeyPatch, policy: str, level: str
) -> None:
    """Any policy but noeviction can drop a queue list or the AI limiters' state once Redis is full: the owner
    sees it in the first start-up line, not after jobs were lost."""
    log = _RecordingLog()
    monkeypatch.setattr(readiness, "log", log)
    monkeypatch.setattr(readiness, "get_redis_client", lambda: _RedisAnswering(policy))
    readiness.log_redis_eviction_policy()
    assert log.lines == [(level, LogEvent.REDIS_EVICTION_POLICY, {"maxmemory_policy": policy})]


def test_the_eviction_policy_line_never_fails_start_up(monkeypatch: pytest.MonkeyPatch) -> None:
    log = _RecordingLog()
    monkeypatch.setattr(readiness, "log", log)
    monkeypatch.setattr(readiness, "get_redis_client", lambda: _RedisAnswering(ConnectionError("refused")))
    readiness.log_redis_eviction_policy()
    assert [(level, event) for level, event, _ in log.lines] == [("warning", LogEvent.REDIS_EVICTION_POLICY)]
    assert log.lines[0][2]["maxmemory_policy"] is None


def test_the_eviction_policy_is_read_from_the_real_redis(monkeypatch: pytest.MonkeyPatch) -> None:
    log = _RecordingLog()
    monkeypatch.setattr(readiness, "log", log)
    readiness.log_redis_eviction_policy()
    [(level, event, fields)] = log.lines
    assert event == LogEvent.REDIS_EVICTION_POLICY and level in {"info", "error"}
    assert isinstance(fields["maxmemory_policy"], str)


def test_the_api_and_every_worker_log_the_eviction_policy_at_start_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    logged: list[str] = []
    monkeypatch.setattr(container, "log_redis_eviction_policy", lambda: logged.append("policy"))
    monkeypatch.setattr(container, "log_mongodb_topology", lambda: None)
    monkeypatch.setattr(container, "create_all_indexes", lambda *_: None)
    for gateway in ("get_chat_model", "get_embedding_model", "get_rerank_model"):
        monkeypatch.setattr(container, gateway, lambda: None)
    for worker_setting in ("_ai_slot_wait_seconds", "_waits_out_rate_limits"):  # set_up_worker changes them
        monkeypatch.setattr(container, worker_setting, getattr(container, worker_setting))
    container.set_up_api()
    container.set_up_worker(())
    assert logged == ["policy", "policy"]


def _redis_over_tls(monkeypatch: pytest.MonkeyPatch, ca_file: str = "") -> None:
    settings = get_settings()
    for field in ("redis_url", "redis_celery_broker_url"):
        monkeypatch.setattr(settings, field, TLS_URL)
    if ca_file:
        monkeypatch.setattr(settings, "redis_ca_file", ca_file)


def test_a_rediss_broker_is_verified_never_left_unverified(monkeypatch: pytest.MonkeyPatch) -> None:
    """kombu turns a bare rediss:// broker URL into TLS with no certificate check (ssl_cert_reqs=CERT_NONE),
    while redis-py verifies: every sender, worker, beat and Flower would have trusted any server."""
    _redis_over_tls(monkeypatch)
    app = Celery("tls-check", broker=get_settings().redis_celery_broker_url)
    app.conf.update(shared_celery_conf())
    with app.connection_for_write() as connection:
        assert connection.ssl["ssl_cert_reqs"] == ssl.CERT_REQUIRED
        assert connection.ssl["ssl_check_hostname"] is True


def test_every_redis_client_verifies_a_rediss_server_against_the_ca_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The limiter, publisher, heartbeat and readiness client, the event hub's subscription and the broker:
    the server's certificate checked against CII_REDIS_CA_FILE, and its host name."""
    _redis_over_tls(monkeypatch, CA_FILE)
    verified = {"ssl_cert_reqs": ssl.CERT_REQUIRED, "ssl_ca_certs": CA_FILE, "ssl_check_hostname": True}

    client = get_redis_client._build()
    connection = client.connection_pool.make_connection()
    assert isinstance(connection, SSLConnection)
    assert (connection.cert_reqs, connection.ca_certs, connection.check_hostname) == (
        ssl.CERT_REQUIRED,
        CA_FILE,
        True,
    )
    client.close()

    class Built(Exception):
        pass

    hub_client: dict[str, object] = {}

    def build_hub_client(url: str, **options: object) -> None:
        hub_client.update(options, url=url)
        raise Built

    monkeypatch.setattr(event_hub.AsyncRedis, "from_url", build_hub_client)
    with pytest.raises(Built):
        asyncio.run(event_hub.EventHub()._read_until_disconnected())
    assert hub_client["url"] == TLS_URL and verified.items() <= hub_client.items()

    assert shared_celery_conf()["broker_use_ssl"] == verified  # also what Flower's broker view uses


def test_a_plain_redis_url_gets_no_tls_options(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "redis_ca_file", CA_FILE)
    assert not shared_celery_conf()["broker_use_ssl"]  # the laptop's redis:// stays as it was
    client = get_redis_client._build()
    assert not isinstance(client.connection_pool.make_connection(), SSLConnection)
    client.close()


def test_each_component_logs_in_to_redis_as_its_own_user_over_tls() -> None:
    """API, workers, beat, Flower and redis-exporter each read their own Redis login (Secret
    tsg-redis-<component>), never one shared by all: one leaked or rotated password touches one component,
    and Redis' ACL log and CLIENT LIST name who did what. tsg-secrets carries no Redis login."""
    logins = {
        (secret["metadata"]["namespace"], secret["metadata"]["name"]): secret["stringData"]
        for secret in _objects(SECRETS_FILE, kind="Secret")
    }
    users: dict[str, set[str | None]] = {}
    for deployment in _all_deployments():
        component = deployment["spec"]["template"]["metadata"]["labels"].get("component")
        login = f"tsg-redis-{str(component).removeprefix('redis-')}"
        read = {
            name for kind, name, _ in _reads(deployment) if kind == "Secret" and name.startswith("tsg-redis")
        }
        assert read == ({login} if component in REDIS_COMPONENTS else set()), deployment["metadata"]["name"]
        for url in logins.get((deployment["metadata"]["namespace"], login), {}).values():
            assert urlsplit(url).scheme == "rediss", (login, "verified TLS")
            users.setdefault(component, set()).add(urlsplit(url).username)
    assert set(users) == REDIS_COMPONENTS
    assert all(len(names) == 1 and None not in names for names in users.values())  # one named user each
    assert len(set.union(*users.values())) == len(REDIS_COMPONENTS)  # never shared
    assert not {"CII_REDIS_URL", "CII_REDIS_CELERY_BROKER_URL"} & set(_secrets())


def test_celery_never_puts_a_job_back_first_in_line_by_itself() -> None:
    """Retries belong to the lease (Lease.MAX_ATTEMPTS, the reaper). Under the threads pool a dead worker is
    the whole pod, so reject_on_worker_lost only ever saw a task thread's BaseException, and put that message
    straight back at the front of its queue, again and again, outside the attempt count."""
    celery_app.loader.import_default_modules()  # what a worker does at start: imports TASK_MODULES
    tasks = [task for name, task in celery_app.tasks.items() if not name.startswith("celery.")]
    assert tasks and not any(task.reject_on_worker_lost for task in tasks)


def _claims() -> list[bytes | None]:
    claims = []
    for field in conftest.TEST_REDIS_DATABASES:
        with conftest._test_redis(field) as database:
            claims.append(database.get(conftest.TEST_RUN_KEY))
    return claims


def test_this_run_holds_its_claim_on_both_test_redis_databases() -> None:
    """A run whose pair overlaps a live run's broker database found it unclaimed and emptied it mid-run."""
    assert _claims() == [f"{CHECKOUT}:{os.getpid()}".encode()] * 2


def test_the_claim_is_renewed_while_the_run_lasts() -> None:
    """A claim set once ran out after 15 minutes of a longer run, and the next run emptied its databases."""
    databases = [conftest._test_redis(field) for field in conftest.TEST_REDIS_DATABASES]
    try:
        for database in databases:
            database.expire(conftest.TEST_RUN_KEY, 5)
        conftest._renew_test_redis_claim(conftest.TEST_RUN)
        assert all(database.ttl(conftest.TEST_RUN_KEY) > 800 for database in databases)
    finally:
        for database in databases:
            database.expire(conftest.TEST_RUN_KEY, conftest.TEST_RUN_CLAIM_SECONDS)
            database.close()


def test_a_run_that_lost_its_claim_stops_and_leaves_the_claim_alone() -> None:
    before = _claims()
    with pytest.raises(pytest.exit.Exception, match="ran out"):
        conftest._renew_test_redis_claim("another-run")
    assert _claims() == before


@pytest.mark.parametrize("value", ["2,14", "14,3", "0,14", "14,1", "14,14", "14"])
def test_the_test_databases_are_never_the_developer_s_own(value: str) -> None:
    """The developer's .env databases (here 2 and 3) and the laptop stack's and v1's 0 and 1."""
    with pytest.raises(AssertionError):
        conftest._test_redis_numbers(value, {2, 3})
    assert conftest._test_redis_numbers("14,15", {2, 3}) == [14, 15]
