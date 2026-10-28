"""Grafana and Flower on the API's own host (owner: https://threatgen-api.../grafana/). OpenShift gives a host
to one project only, and a Route reaches only a Service of its own project: their Routes are in ai-threatgen
and go through the monitoring proxy there (nginx), which forwards to TSG's Grafana and Flower in ai-common."""

import json
import re
from pathlib import Path

from tests.test_deploy import (
    API_HOST,
    APP_FILES,
    COMMON_FILE,
    DEPLOY,
    DNS,
    HARDENED,
    MONITORING_NAMESPACE,
    NETWORK_FILES,
    PROXY,
    REPO,
    ROUTER_PEER,
    _deployment,
    _objects,
)

PROXY_PEER = {
    "namespaceSelector": {},
    "podSelector": {"matchLabels": {"app": PROXY, "part-of": "tsg-monitoring"}},
}
OWN_PROJECT = {"podSelector": {}}
EDGE_TLS = {"termination": "edge", "insecureEdgeTerminationPolicy": "Redirect"}
NGINX_CONF = REPO / "observability" / "nginx" / "nginx.conf"
#: Where an address may be written: the deploy folder (but the operator's own secrets.yaml) and the runbook.
ADDRESS_FILES = [
    *(path for path in DEPLOY.rglob("*") if path.is_file() and path.name != "secrets.yaml"),
    REPO / "docs" / "UAT_LLM_TIMEOUT_RUNBOOK.md",
]


def _peer(selector: dict | None) -> str:
    """A network peer as JSON, so it can sit in a set."""
    return json.dumps(selector, sort_keys=True)


def _allowed(policy: dict, direction: str) -> set[tuple[str, object]]:
    """Each (peer as JSON, (port, protocol)) a NetworkPolicy allows; "null" is any address, "any" any port."""
    side = "from" if direction == "ingress" else "to"
    return {
        (_peer(peer), (port["port"], port["protocol"]) if port else "any")
        for rule in policy["spec"].get(direction, [])
        for peer in rule.get(side, [None])
        for port in rule.get("ports", [None])
    }


def _named(path: Path, kind: str, name: str) -> dict:
    """The one object of this kind and name in the file."""
    [found] = [o for o in _objects(path, kind=kind) if o["metadata"]["name"] == name]
    return found


def test_every_route_is_https_on_the_api_host_in_ai_threatgen_and_no_two_share_a_path() -> None:
    """Every Route is ai-threatgen's, https on the API's host, one per path, to a Service of its project."""
    routes = _objects(*APP_FILES.values(), COMMON_FILE, kind="Route")
    paths = [route["spec"]["path"] for route in routes]
    assert len(paths) == len(set(paths))
    assert {(r["metadata"]["namespace"], r["spec"]["host"]) for r in routes} == {("ai-threatgen", API_HOST)}
    assert sorted(paths) == ["/", "/flower", "/grafana"]  # owner: only Grafana and Flower next to the API
    assert all(route["spec"]["tls"] == EDGE_TLS for route in routes)
    services = {
        (service["metadata"]["namespace"], service["metadata"]["name"]): service
        for service in _objects(*APP_FILES.values(), COMMON_FILE, kind="Service")
    }
    for route in routes:
        name, target = route["metadata"]["name"], route["spec"]["to"]
        assert target["kind"] == "Service", name
        ports = services[(route["metadata"]["namespace"], target["name"])]["spec"]["ports"]
        assert route["spec"]["port"]["targetPort"] in {port["name"] for port in ports}, name
        assert (target["name"] == PROXY) == (route["spec"]["path"] != "/"), name


def test_every_public_address_in_the_deploy_files_is_the_api_host() -> None:
    """The deploy files, the guide and the runbook name no host but the API's; threatgen-grafana only bare."""
    for path in ADDRESS_FILES:
        text = path.read_text(encoding="utf-8")
        hosts = set(re.findall(r"threatgen-[\w-]+\.apps\.dda-desc-az1-01\.desccii\.local", text))
        assert hosts <= {API_HOST}, (path.name, hosts)
        assert not re.search(r"threatgen-grafana[./]\w", text), path.name


def test_only_the_router_reaches_the_proxy_and_the_proxy_only_tsg_s_grafana_and_flower() -> None:
    """Only the router reaches the proxy; it reaches only TSG's Grafana and Flower, which admit only it."""
    proxy = _deployment(PROXY)["spec"]["template"]
    labels = proxy["metadata"]["labels"].items()
    policy = _named(NETWORK_FILES["ai-threatgen"], "NetworkPolicy", PROXY)
    service = _named(COMMON_FILE, "Service", PROXY)["spec"]
    matches = (policy["spec"]["podSelector"], {"matchLabels": service["selector"]}, PROXY_PEER["podSelector"])
    assert all(match["matchLabels"].items() <= labels for match in matches), matches
    conf = NGINX_CONF.read_text(encoding="utf-8")
    [listen] = {int(port) for port in re.findall(r"^\s*listen (\d+);", conf, re.MULTILINE)}
    [container] = proxy["spec"]["containers"]
    probes = {container[probe]["httpGet"]["port"] for probe in ("readinessProbe", "livenessProbe")}
    container_ports = {port["containerPort"] for port in container["ports"]}
    assert {port["targetPort"] for port in service["ports"]} == container_ports == probes == {listen}
    assert set(policy["spec"]["policyTypes"]) == {"Ingress", "Egress"}
    assert _allowed(policy, "ingress") == {(_peer(ROUTER_PEER), (listen, "TCP"))}

    forwards = re.findall(
        r"location (/\w+) \{\s*proxy_pass http://([\w-]+)\.([\w-]+)\.svc\.cluster\.local:(\d+);", conf
    )
    assert {path for path, *_ in forwards} == {"/grafana", "/flower"}
    services = {s["metadata"]["name"]: s["spec"] for s in _objects(COMMON_FILE, kind="Service")}
    pods = {d["metadata"]["name"]: d["spec"]["template"] for d in _objects(COMMON_FILE, kind="Deployment")}
    reached = set()
    for _, name, namespace, port in forwards:
        assert namespace == MONITORING_NAMESPACE, name
        [target] = [p["targetPort"] for p in services[name]["ports"] if p["port"] == int(port)]
        selector = services[name]["selector"]
        assert selector == {"app": name, "part-of": "tsg-monitoring"}, name
        assert selector.items() <= pods[name]["metadata"]["labels"].items(), name
        listening = {p["containerPort"] for c in pods[name]["spec"]["containers"] for p in c["ports"]}
        assert target in listening, name
        reached.add(
            (_peer({"namespaceSelector": {}, "podSelector": {"matchLabels": selector}}), (target, "TCP"))
        )
    assert {port for _, (port, _) in reached} == {3000, 5555}
    assert _allowed(policy, "egress") == {("null", port) for port in DNS} | reached

    from_outside = {
        allowed
        for common in _objects(COMMON_FILE, kind="NetworkPolicy")
        if common["metadata"]["namespace"] == MONITORING_NAMESPACE
        and common["spec"]["podSelector"] == {"matchLabels": {"part-of": "tsg-monitoring"}}  # not the reaper
        for allowed in _allowed(common, "ingress")
        if allowed[0] != _peer(OWN_PROJECT)
    }
    assert from_outside == {(_peer(PROXY_PEER), port) for _, port in reached}


def test_the_proxy_runs_hardened_without_a_token_and_writes_only_under_tmp() -> None:
    """OpenShift runs nginx as a random user with no OpenShift token: its pid and temp files go to /tmp."""
    pod = _deployment(PROXY)["spec"]["template"]["spec"]
    assert pod["automountServiceAccountToken"] is False and pod["enableServiceLinks"] is False
    assert [container["securityContext"] for container in pod["containers"]] == [HARDENED]
    written = dict(
        re.findall(r"^\s*(pid|\w+_temp_path) (\S+);", NGINX_CONF.read_text(encoding="utf-8"), re.MULTILINE)
    )
    assert set(written) == {
        "pid",
        *(f"{kind}_temp_path" for kind in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi")),
    }
    assert {path.split("/")[1] for path in written.values()} == {"tmp"}, written
