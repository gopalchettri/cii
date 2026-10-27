"""The monitoring sees what it claims to: a worker's own view of its stores, lost log lines, a pod by its
name, Alloy's read positions across restarts, the newest reaper pass's job counts, and alerts by email."""

import re
import subprocess
from pathlib import Path

import pytest
import yaml
from pymongo.errors import AutoReconnect

from app.core import metrics, readiness
from app.core.constants import Dependency, Queue
from app.worker.heartbeat import WorkerHeartbeat
from tests.test_deploy import COMMON_FILE, SECRETS_FILE, _container, _deployment, _objects, _reads
from tests.test_observability import OBS, _panels, _rules

RULES_TEST = OBS / "prometheus" / "rules.test.yml"
ALERTMANAGER = OBS / "alertmanager" / "alertmanager.yml"
PLACEHOLDER = "CHANGE_ME"


def _cases() -> list[dict]:
    return yaml.safe_load(RULES_TEST.read_text(encoding="utf-8"))["tests"]


def _firing(alert: str) -> list[dict]:
    """Every firing expectation rules.test.yml has for one alert (promtool proves each)."""
    return [
        expected
        for case in _cases()
        for check in case["alert_rule_test"]
        if check["alertname"] == alert
        for expected in check.get("exp_alerts") or []
    ]


def _gauge(name: Dependency) -> float:
    return metrics.DEPENDENCY_UP.labels(name)._value.get()


def test_a_worker_reports_its_stores_on_each_beat(monkeypatch: pytest.MonkeyPatch) -> None:
    """Before: only the API's /ready and /metrics set tsg_dependency_up, so a worker that lost MongoDB
    raised no alert. Each beat now checks the worker's MongoDB and Redis (not SQL Server: not every worker
    uses it)."""

    def mongo_is_down() -> None:
        raise AutoReconnect("connection refused")

    def sql_must_not_run() -> None:
        raise AssertionError("a worker does not check SQL Server")

    monkeypatch.setattr(readiness, "_runs", {})
    monkeypatch.setitem(readiness._DEPENDENCY_CHECKS, Dependency.MONGO, mongo_is_down)
    monkeypatch.setitem(readiness._DEPENDENCY_CHECKS, Dependency.REDIS, lambda: True)
    monkeypatch.setitem(readiness._DEPENDENCY_CHECKS, Dependency.SQL, sql_must_not_run)
    for name, value in ((Dependency.MONGO, 1), (Dependency.REDIS, 0), (Dependency.SQL, 7)):
        metrics.DEPENDENCY_UP.labels(name).set(value)
    beating = WorkerHeartbeat([Queue.THREATS], "celery@stores-test")
    monkeypatch.setattr(beating, "beat", lambda: None)
    beating._stopped.set()  # one pass of the loop
    beating._beat_until_stopped()
    assert (_gauge(Dependency.MONGO), _gauge(Dependency.REDIS), _gauge(Dependency.SQL)) == (0, 1, 7)


@pytest.mark.parametrize(("alert", "store"), [("MongoDown", "MongoDB"), ("RedisDown", "Redis")])
def test_a_store_down_alert_names_the_process_that_cannot_reach_it(alert: str, store: str) -> None:
    """The API and the workers both report their stores; the alert says which one lost it."""
    [rule] = [rule for rule in _rules() if rule["alert"] == alert]
    assert rule["expr"].startswith("min by (job) (")
    workers = [e for e in _firing(alert) if e["exp_labels"].get("job") == "worker"]
    assert workers and workers[0]["exp_annotations"]["summary"] == f"{store} does not answer the worker."


def test_lost_log_lines_raise_an_alert_of_their_own_group() -> None:
    """Before: Alloy giving up on a batch, or Loki refusing lines (too old, too long, over its rate), showed
    only in their own counters, and no rule read them. Loki makes its counter at its first refusal, which
    increase() cannot see: a counter new in the window counts too (promtool runs both cases)."""
    groups = yaml.safe_load((OBS / "prometheus" / "rules.yml").read_text(encoding="utf-8"))["groups"]
    [group] = [group for group in groups if any(rule["alert"] == "LogLinesLost" for rule in group["rules"])]
    assert [rule["alert"] for rule in group["rules"]] == ["LogLinesLost"]
    [rule] = group["rules"]
    for counter in ("loki_write_dropped_entries_total", "loki_discarded_samples_total"):
        assert f"increase({counter}[15m])" in rule["expr"]
        assert f"{counter} > 0 unless {counter} offset 15m" in rule["expr"]
    fired_by = [
        series["series"].split("{")[0]
        for case in _cases()
        if any(
            check["alertname"] == "LogLinesLost" and check.get("exp_alerts")
            for check in case["alert_rule_test"]
        )
        for series in case["input_series"]
    ]
    assert {"loki_write_dropped_entries_total", "loki_discarded_samples_total"} <= set(fired_by)


def test_uat_alerts_name_a_pod_by_its_project_and_name_not_its_address() -> None:
    """Before: UAT kept Prometheus' default instance, the pod's IP:port, so ClockSkew and TargetDown said
    "10.128.3.17:9100". The pods job now sets instance to <project>/<pod>: every alert and panel reads it."""
    uat = yaml.safe_load((OBS / "prometheus" / "prometheus.yml").read_text(encoding="utf-8"))
    [pods] = [job for job in uat["scrape_configs"] if job["job_name"] == "pods"]
    [instance] = [rule for rule in pods["relabel_configs"] if rule.get("target_label") == "instance"]
    assert instance["source_labels"] == ["__meta_kubernetes_namespace", "__meta_kubernetes_pod_name"]
    assert instance["separator"] == "/" and instance.get("action", "replace") == "replace"


def test_alloy_keeps_its_read_positions_on_a_disk_that_outlives_the_pod() -> None:
    """Before: --storage.path was an emptyDir, so every rollout or eviction forgot how far Alloy had read:
    lines were shipped twice (Loki refused the old ones) or missed."""
    alloy = _deployment("alloy")
    [path] = [arg.split("=", 1)[1] for arg in _container(alloy)["args"] if arg.startswith("--storage.path=")]
    [mount] = [m for m in _container(alloy)["volumeMounts"] if m["mountPath"] == path]
    [volume] = [v for v in alloy["spec"]["template"]["spec"]["volumes"] if v["name"] == mount["name"]]
    claim = volume["persistentVolumeClaim"]["claimName"]
    assert alloy["spec"]["strategy"] == {"type": "Recreate"}  # one pod at a time on a ReadWriteOnce disk
    [disk] = [
        c for c in _objects(COMMON_FILE, kind="PersistentVolumeClaim") if c["metadata"]["name"] == claim
    ]
    assert disk["spec"]["accessModes"] == ["ReadWriteOnce"]


def test_jobs_now_reads_only_the_worker_whose_reaper_ran_last() -> None:
    """Two maintenance workers share the reaper's queue; each keeps the counts of its own last pass. Before:
    the panel took the max over both, so the twin that missed the latest passes showed jobs that had ended."""
    [panel] = [p for p in _panels() if p["title"] == "Jobs now, by kind and status"]
    [expr] = [target["expr"] for target in panel["targets"]]
    assert "and on (instance) topk(1, tsg_reaper_last_pass_timestamp_seconds)" in expr
    tested = [test for case in _cases() for test in case.get("promql_expr_test", []) if test["expr"] == expr]
    assert tested and all('status="running"' not in str(test["exp_samples"]) for test in tested)


def _alertmanager_secret_files() -> dict[str, str]:
    """Each file of Secret tsg-monitoring the alertmanager container sees, with the key it holds."""
    deployment = _deployment("alertmanager")
    mounts = {m["name"]: m["mountPath"] for m in _container(deployment)["volumeMounts"]}
    return {
        f"{mounts[volume['name']]}/{item['path']}": item["key"]
        for volume in deployment["spec"]["template"]["spec"]["volumes"]
        if volume.get("secret", {}).get("secretName") == "tsg-monitoring"
        for item in volume["secret"]["items"]
    }


def test_alertmanager_emails_through_the_receiver_its_route_names() -> None:
    """Owner: email, through the company relay or Gmail; one route line picks which. Before: the only receiver
    had no notifier, so no alert ever left Alertmanager. Each password is a file from Secret tsg-monitoring,
    never in the config; the addresses the owner fills in are marked CHANGE_ME."""
    config = yaml.safe_load(ALERTMANAGER.read_text(encoding="utf-8"))
    receivers = {receiver["name"]: receiver for receiver in config["receivers"]}
    assert set(receivers) == {"company-smtp", "gmail"} and config["route"]["receiver"] in receivers
    files = _alertmanager_secret_files()
    [monitoring] = [
        o for o in _objects(SECRETS_FILE, kind="Secret") if o["metadata"]["name"] == "tsg-monitoring"
    ]
    for name, receiver in receivers.items():
        [email] = receiver["email_configs"]
        assert files[email["auth_password_file"]] in monitoring["stringData"], name
        assert "auth_password" not in email and email["send_resolved"] is True, name
        assert all(PLACEHOLDER in email[field] for field in ("from", "to", "auth_username")), name
    assert receivers["gmail"]["email_configs"][0]["smarthost"] == "smtp.gmail.com:587"
    assert PLACEHOLDER in receivers["company-smtp"]["email_configs"][0]["smarthost"]
    reads = _reads(_deployment("alertmanager"))
    assert {("Secret", "tsg-monitoring", key) for key in files.values()} <= reads  # test_deploy checks them


def _amtool() -> str | None:
    found = sorted(Path.home().glob(".tsg/monitoring-v2/bin/alertmanager-*/**/amtool.exe"))
    return str(found[-1]) if found else None


def test_amtool_accepts_the_alertmanager_config() -> None:
    """The pinned Alertmanager (laptop = UAT image version) reads email auth_password_file and the rest."""
    amtool = _amtool()
    if amtool is None:
        pytest.skip("amtool is not installed (python scripts/monitoring.py install)")
    command = [amtool, "check-config", str(ALERTMANAGER)]
    result = subprocess.run(command, capture_output=True, text=True, check=False)  # noqa: S603
    assert result.returncode == 0, result.stdout + result.stderr
    assert re.search(r"- 2 receivers", result.stdout), result.stdout
