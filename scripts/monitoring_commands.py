"""What scripts/monitoring.py runs on a laptop: each program's command line and settings, read from .env and
observability/ (the same files UAT uses), and Grafana's admin password."""

from __future__ import annotations

import os
import secrets
import subprocess
import sys
from urllib.parse import urlparse

from dotenv import dotenv_values
from monitoring_install import REPO, ROOT, program

OBS = REPO / "observability"
#: Grafana settings the scripts set themselves: the links, the /grafana path and the home dashboard depend on
#: them, so a GF_ line for one of these in .env is ignored (deploy/observability.ps1 has the same list, UAT).
FIXED_GRAFANA_SETTINGS = (
    "GF_SERVER_ROOT_URL",
    "GF_SERVER_SERVE_FROM_SUB_PATH",
    "GF_SERVER_HTTP_ADDR",
    "GF_SERVER_HTTP_PORT",
    "GF_SECURITY_ADMIN_PASSWORD",
    "GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH",
    "GF_LOG_MODE",
    "GF_PATHS_",
)
# Keep in step with app/core/constants.py Queue for queue-depth monitoring.
QUEUES = ("tsg_threats", "tsg_scenarios", "tsg_servicemapper", "tsg_maintenance")
QUEUE_KEY_PREFIX = "tsg:"  # app/core/constants.py Worker.BROKER_KEY_PREFIX
Command = tuple[list[str], dict[str, str]]  # (command line, extra environment)


# ---------------------------------------------------------------- settings from .env
def _env_value(name: str, default: str = "") -> str:
    """A setting as the app reads it: the environment first, then the repo's .env."""
    return os.environ.get(name) or dotenv_values(REPO / ".env").get(name) or default


def _grafana_password() -> str:
    configured = _env_value("GRAFANA_ADMIN_PASSWORD")
    if configured:
        return configured
    kept = ROOT / "grafana-admin-password.txt"
    if not kept.exists():
        kept.parent.mkdir(parents=True, exist_ok=True)
        kept.write_text(secrets.token_urlsafe(12), encoding="utf-8")
    return kept.read_text(encoding="utf-8").strip()


def grafana_settings_from_env() -> dict[str, str]:
    """Every GF_ line of .env (owner, 2026-10-09: Grafana's settings are the owner's to change there), except
    the ones the scripts set themselves."""
    lines = dotenv_values(REPO / ".env")
    return {
        key: value or ""
        for key, value in lines.items()
        if key.startswith("GF_") and not key.startswith(FIXED_GRAFANA_SETTINGS)
    }


def _grafana_env() -> dict[str, str]:
    data = ROOT / "data" / "grafana"
    return {
        **grafana_settings_from_env(),
        "GF_SERVER_SERVE_FROM_SUB_PATH": "true",
        "GF_SECURITY_ADMIN_PASSWORD": _grafana_password(),
        "GF_SERVER_HTTP_ADDR": "127.0.0.1",
        "GF_SERVER_HTTP_PORT": "3000",
        "GF_SERVER_ROOT_URL": "http://localhost:3000/grafana/",
        "GF_PATHS_DATA": data.as_posix(),
        "GF_PATHS_PLUGINS": (data / "plugins").as_posix(),
        "GF_PATHS_LOGS": (ROOT / "logs").as_posix(),
        "GF_PATHS_PROVISIONING": (OBS / "grafana" / "provisioning").as_posix(),
        "GF_LOG_MODE": "console",
        "GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH": (OBS / "grafana" / "dashboards" / "tsg.json").as_posix(),
        "GRAFANA_DASHBOARDS": (OBS / "grafana" / "dashboards").as_posix(),
        "PROMETHEUS_URL": "http://127.0.0.1:9090/prometheus",
        "LOKI_URL": "http://127.0.0.1:3100",
        "ALERTMANAGER_URL": "http://127.0.0.1:9093/alertmanager",
    }


# ---------------------------------------------------------------- one command per program
def _loki() -> Command:
    config = OBS / "loki" / "loki.yaml"
    command = [str(program("loki")), f"-config.file={config}", "-config.expand-env=true", "-target=all"]
    command += [
        "-server.http-listen-address=127.0.0.1",
        "-server.grpc-listen-address=127.0.0.1",
    ]  # this PC only
    return command, {"LOKI_DATA": (ROOT / "data" / "loki").as_posix()}


def _prometheus() -> Command:
    return [
        str(program("prometheus")),
        f"--config.file={OBS / 'prometheus' / 'prometheus.local.yml'}",
        f"--storage.tsdb.path={ROOT / 'data' / 'prometheus'}",
        "--storage.tsdb.retention.time=7d",
        "--web.listen-address=127.0.0.1:9090",
        "--web.external-url=http://localhost:9090/prometheus/",
    ], {}


def _alertmanager() -> Command:
    return [
        str(program("alertmanager")),
        f"--config.file={OBS / 'alertmanager' / 'alertmanager.yml'}",
        f"--storage.path={ROOT / 'data' / 'alertmanager'}",
        "--web.listen-address=127.0.0.1:9093",
        "--web.external-url=http://localhost:9093/alertmanager/",
        "--cluster.listen-address=",  # one Alertmanager: no peers to find
    ], {}


def _redis_exporter() -> Command:
    broker = _env_value("CII_REDIS_CELERY_BROKER_URL")
    if not broker:
        raise SystemExit("CII_REDIS_CELERY_BROKER_URL is not set in .env")
    db = urlparse(broker).path.strip("/") or "0"
    keys = ",".join(f"db{db}={QUEUE_KEY_PREFIX}{queue}" for queue in QUEUES)
    env = {
        "REDIS_ADDR": broker,
        "REDIS_EXPORTER_CHECK_SINGLE_KEYS": keys,
        "REDIS_EXPORTER_INCL_SYSTEM_METRICS": "false",
    }
    return [str(program("redis_exporter")), "--web.listen-address=127.0.0.1:9121"], env


def _alloy() -> Command:
    log_dir = REPO / _env_value("CII_LOG_DIR", "logs")
    return [
        str(program("alloy")),
        "run",
        str(OBS / "alloy" / "local.alloy"),
        "--server.http.listen-addr=127.0.0.1:12345",
        f"--storage.path={ROOT / 'data' / 'alloy'}",
        "--disable-reporting",
    ], {"TSG_LOG_DIR": log_dir.as_posix()}


def _grafana() -> Command:
    grafana = program("grafana")
    return [str(grafana), "server", f"--homepath={grafana.parent.parent}"], _grafana_env()


def _flower() -> Command:
    command = [sys.executable, "-m", "celery", "-A", "app.worker", "flower"]
    return [*command, "--address=127.0.0.1", "--port=5555", "--url_prefix=flower"], {}


#: Start order = READY order.
COMMANDS = {
    "loki": _loki,
    "prometheus": _prometheus,
    "alertmanager": _alertmanager,
    "redis_exporter": _redis_exporter,
    "alloy": _alloy,
    "grafana": _grafana,
    "flower": _flower,
}


def reset_grafana_password() -> None:
    """Grafana uses GF_SECURITY_ADMIN_PASSWORD only when it creates its database: set it again on every later
    start, so the .env line is always the password. Through stdin, never the command line."""
    if not (ROOT / "data" / "grafana" / "grafana.db").exists():
        return
    grafana = program("grafana")
    command = [str(grafana), "cli", f"--homepath={grafana.parent.parent}", "admin", "reset-admin-password"]
    result = subprocess.run(  # noqa: S603 — our own installed program
        [*command, "--password-from-stdin"],
        input=_grafana_password().encode(),
        capture_output=True,
        env={**os.environ, **_grafana_env()},
        check=False,
    )
    if result.returncode:
        raise SystemExit(
            f"Grafana did not accept the admin password: {result.stderr.decode(errors='replace')}"
        )
