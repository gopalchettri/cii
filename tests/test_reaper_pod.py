"""The reaper and the controls sweep run alone on queue tsg_reaper, in their own pod worker-reaper in
ai-common (owner, 2026-10-28: ai-threatgen's quota has no room); it may reach only DNS, Redis and MongoDB."""

from app.core.constants import TASK_ROUTES, Queue, TaskName
from tests.test_deploy import (
    COMMON_FILE,
    DNS,
    HARDENED,
    MONITORING_NAMESPACE,
    WORKER_PROBES,
    _container,
    _deployment,
    _objects,
)

REDIS = ("10.228.146.4/32", 6379)
MONGODB = ("10.228.146.3/32", 27018)


def _reaper_rules() -> list[dict]:
    """The network rules that select worker-reaper's pods."""
    labels = _deployment("worker-reaper")["spec"]["template"]["metadata"]["labels"]
    return [
        rule
        for rule in _objects(COMMON_FILE, kind="NetworkPolicy")
        if rule["metadata"]["namespace"] == MONITORING_NAMESPACE
        and rule["spec"]["podSelector"]["matchLabels"].items() <= labels.items()
    ]


def test_the_reaper_and_the_controls_sweep_have_their_own_queue() -> None:
    """No long library build or intelligence refresh holds the thread a reaper pass needs."""
    assert TASK_ROUTES[TaskName.REAP] == TASK_ROUTES[TaskName.RETRY_CONTROLS] == {"queue": Queue.REAPER}
    assert sum(route["queue"] == Queue.REAPER for route in TASK_ROUTES.values()) == 2


def test_worker_reaper_runs_in_ai_common_on_tsg_reaper_alone() -> None:
    reaper = _deployment("worker-reaper")
    assert reaper["metadata"]["namespace"] == MONITORING_NAMESPACE
    assert reaper["spec"]["replicas"] == 1
    assert reaper["spec"]["strategy"]["rollingUpdate"]["maxSurge"] == 0  # no extra pod in TSG's share
    assert "affinity" not in reaper["spec"]["template"]["spec"]  # one pod: nothing to keep apart
    labels = reaper["spec"]["template"]["metadata"]["labels"]
    assert labels == {"app": "worker-reaper", "component": "worker", "part-of": "tsg"}  # TSG's app
    container = _container(reaper)
    command = container["command"]
    assert command[:4] == ["celery", "-A", "app.worker", "worker"] and "--pool=threads" in command
    assert command[command.index("-Q") + 1] == Queue.REAPER
    assert container["envFrom"] == [
        {"configMapRef": {"name": "tsg-config"}},
        {"secretRef": {"name": "tsg-secrets"}},
    ]
    for probe, expected in WORKER_PROBES.items():  # the heartbeat's file, no Redis: as every worker
        assert container[probe]["exec"]["command"] == expected, probe
    assert container["securityContext"] == HARDENED


def test_worker_reaper_reaches_only_dns_redis_and_mongodb_and_only_prometheus_reaches_it() -> None:
    """Once a rule selects the pod, everything not listed is blocked: no proxy, AI gateway or SQL Server."""
    rules = _reaper_rules()
    reachable, dns_only = set(), []
    egress = [
        r for policy in rules if "Egress" in policy["spec"]["policyTypes"] for r in policy["spec"]["egress"]
    ]
    for rule in egress:
        ports = {(port["port"], port["protocol"]) for port in rule["ports"]}
        if "to" not in rule:
            dns_only.append(ports)  # to any address: DNS alone
        else:
            reachable |= {(peer["ipBlock"]["cidr"], port) for peer in rule["to"] for port, _ in ports}
    assert dns_only == [DNS]
    assert reachable == {REDIS, MONGODB}
    ingress = [
        r for policy in rules if "Ingress" in policy["spec"]["policyTypes"] for r in policy["spec"]["ingress"]
    ]
    assert ingress == [
        {
            "from": [{"podSelector": {"matchLabels": {"part-of": "tsg-monitoring"}}}],  # Prometheus, here
            "ports": [{"port": 9100, "protocol": "TCP"}],  # the worker's /metrics
        }
    ]
