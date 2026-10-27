"""The OpenShift delivery (M15, T-OPS-08; UAT is production), plain YAML applied with `oc apply -f` and every
value written in it: deploy_threatgen.yaml (ai-threatgen), deploy_remediation.yaml (ai-remediation),
deploy_common.yaml (the monitoring and Flower in ai-common), the two networkpolicy files, configmap.yaml
and secrets.example.yaml (the template of the git-ignored secrets.yaml). The settings the pods load, each
project's quota, the owner's two file rules (no kubernetes.io but the node label that spreads the pods, a
comment on every line), the spreading over nodes and what goes into the image.
A broken file must fail here, not halfway through a rollout."""

import math
import os
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

import pytest
import yaml
from pydantic import SecretStr, ValidationError

from app.core.config import Settings
from app.core.constants import LITELLM_MODEL_PREFIX, Controls, Generation, Lease, Queue, ThreatFinding, Worker
from app.worker import ROUTED_QUEUES, celery_app

REPO = Path(__file__).resolve().parents[1]
DEPLOY = REPO / "deploy"
APP_FILES = {
    "ai-threatgen": DEPLOY / "deploy_threatgen.yaml",
    "ai-remediation": DEPLOY / "deploy_remediation.yaml",
}
NETWORK_FILES = {
    "ai-threatgen": DEPLOY / "networkpolicy_threatgen.yaml",
    "ai-remediation": DEPLOY / "networkpolicy_remediation.yaml",
}
COMMON_FILE = DEPLOY / "deploy_common.yaml"
CONFIG_FILE = DEPLOY / "configmap.yaml"
SECRETS_FILE = DEPLOY / "secrets.example.yaml"
SECRETS_COPY = DEPLOY / "secrets.yaml"  # the operator's copy with the real values: git-ignored, may be absent
#: Every deploy file in git (the operator's secrets.yaml is not).
YAML_FILES = sorted(path for path in DEPLOY.glob("*.yaml") if path != SECRETS_COPY)
MONITORING_NAMESPACE = "ai-common"  # shared with the chatbot
WATCHED = [*APP_FILES, MONITORING_NAMESPACE]  # Flower and the monitoring itself run in ai-common
MIRROR = "quay-quay-registry.apps.dda-desc-az1-01.desccii.local/dda-desc"
#: build-image.bat's tag: the build date dd-Mon-yyyy (English month), -<suffix> on a same-day rebuild.
APP_IMAGE = re.compile(
    rf"{re.escape(MIRROR)}/tsg-api:\d{{2}}-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)-\d{{4}}(-\w+)?"
)
API_HOST = "threatgen-api.apps.dda-desc-az1-01.desccii.local"
#: The nginx in ai-threatgen that puts Grafana and Flower on the API's host (deploy_common.yaml).
PROXY = "monitoring-proxy"
#: Each project's quota in limits (CPU, memory Gi, storage Gi); in ai-common, TSG's share of it (the chatbot
#: has the rest).
QUOTAS = {
    "ai-threatgen": (6.0, 12.0, 60.0),
    "ai-remediation": (6.0, 12.0, 60.0),
    MONITORING_NAMESPACE: (3.0, 6.0, 60.0),
}
SECRET_NAMES = {
    "CII_DB_DSN",
    "CII_PROXY_URL",  # an address can carry a password
    "CII_MONGO_URL",
    "CII_CHAT_API_KEY",
    "CII_EMBEDDING_API_KEY",
    "CII_RERANK_API_KEY",
    "CII_ADMIN_API_KEY",
    "CII_NVD_API_KEY",
}
#: Connection strings carry their password: they are secrets, with the keys.
CONNECTIONS = {"db_dsn", "mongo_url", "redis_url", "redis_celery_broker_url"}
#: The settings in tsg-secrets that name a store the pods must reach; Redis is in each component's own login.
STORES = ("CII_MONGO_URL", "CII_DB_DSN")
#: Each component's Redis login, Secret tsg-redis-<component> (redis-exporter's holds REDIS_ADDR alone).
REDIS_LOGIN_KEYS = {"CII_REDIS_URL", "CII_REDIS_CELERY_BROKER_URL"}
DEFAULT_PORTS = {"redis": "6379", "rediss": "6379", "mongodb": "27017", "mssql+pyodbc": "1433"}
#: Each AI model and the base URL its calls go to.
GATEWAYS = (
    ("CII_CHAT_MODEL", "CII_CHAT_BASE_URL"),
    ("CII_CHAT_FALLBACK_MODEL", "CII_CHAT_BASE_URL"),
    ("CII_EMBEDDING_MODEL", "CII_EMBEDDING_BASE_URL"),
    ("CII_RERANK_MODEL", "CII_RERANK_BASE_URL"),
)
HARDENED = {
    "allowPrivilegeEscalation": False,
    "runAsNonRoot": True,
    "capabilities": {"drop": ["ALL"]},
    "seccompProfile": {"type": "RuntimeDefault"},
}
MONITORING_PEER = {"namespaceSelector": {}, "podSelector": {"matchLabels": {"part-of": "tsg-monitoring"}}}
ROUTER_PEER = {"namespaceSelector": {"matchLabels": {"policy-group.network.openshift.io/ingress": ""}}}
DNS = {(53, "UDP"), (53, "TCP"), (5353, "UDP"), (5353, "TCP")}  # 5353: where OpenShift's DNS pods listen
#: Each config file configmap.yaml embeds, and the observability/ file the laptop runs.
EMBEDDED_CONFIGS = {
    "prometheus.yml": "observability/prometheus/prometheus.yml",
    "rules.yml": "observability/prometheus/rules.yml",
    "alertmanager.yml": "observability/alertmanager/alertmanager.yml",
    "loki.yaml": "observability/loki/loki.yaml",
    "config.alloy": "observability/alloy/uat.alloy",
    "datasources.yaml": "observability/grafana/provisioning/datasources/datasources.yaml",
    "dashboards.yaml": "observability/grafana/provisioning/dashboards/dashboards.yaml",
    "tsg.json": "observability/grafana/dashboards/tsg.json",
    "nginx.conf": "observability/nginx/nginx.conf",  # the monitoring proxy's: UAT only
}
#: How a pod names a ConfigMap or Secret it reads (envFrom, env valueFrom).
REFERENCES = {
    "configMapRef": "ConfigMap",
    "secretRef": "Secret",
    "configMapKeyRef": "ConfigMap",
    "secretKeyRef": "Secret",
}
BLOCK_SCALAR = re.compile(r"(?:^|:|-)\s*[|>][-+]?$")  # `key: |`, `- >-`: the lines below are file content
CHAT_MODEL_REQUESTS_PER_MINUTE = 192  # kimi-k2.5's own limit on UAT's gateway key (owner, 2026-10-24)
#: Every worker's startup and liveness probe: the heartbeat's file exists, then is fresh. No Redis.
FILE_AGE = f"$(( $(date +%s) - $(stat -c %Y {Worker.LIVENESS_FILE}) ))"
WORKER_PROBES = {
    "startupProbe": ["sh", "-c", f"test -f {Worker.LIVENESS_FILE}"],
    "livenessProbe": ["sh", "-c", f"test {FILE_AGE} -lt {Worker.LIVENESS_MAX_AGE_SECONDS}"],
}
KUBERNETES_IO = "kubernetes.io"
#: The owner's one exception to "no kubernetes.io" (2026-10-24): the node label as a spreading rule's key.
NODE_TOPOLOGY = ("topologyKey", "kubernetes.io/hostname")


def _objects(*paths: Path, kind: str = "") -> list[dict]:
    """Every object in the files, a List's items one by one."""
    found = []
    for path in paths:
        for document in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            if document:
                found += document["items"] if document["kind"] == "List" else [document]
    return [o for o in found if not kind or o["kind"] == kind]


def _app_deployments() -> list[dict]:
    return _objects(*APP_FILES.values(), kind="Deployment")


def _all_deployments() -> list[dict]:
    return _objects(*APP_FILES.values(), COMMON_FILE, kind="Deployment")


def _deployment(name: str) -> dict:
    [found] = [d for d in _all_deployments() if d["metadata"]["name"] == name]
    return found


def _container(deployment: dict) -> dict:
    [container] = deployment["spec"]["template"]["spec"]["containers"]
    return container


def _containers(deployment: dict) -> list[dict]:
    spec = deployment["spec"]["template"]["spec"]
    return spec["containers"] + spec.get("initContainers", [])


def _shared(path: Path, name: str) -> dict[str, dict[str, str]]:
    """Each project's copy of tsg-config or tsg-secrets: {namespace: its values}."""
    return {
        o["metadata"]["namespace"]: o.get("data") or o.get("stringData") or {}
        for o in _objects(path)
        if o["metadata"]["name"] == name
    }


def _settings() -> dict[str, str]:
    return _shared(CONFIG_FILE, "tsg-config")["ai-threatgen"]


def _secrets() -> dict[str, str]:
    return _shared(SECRETS_FILE, "tsg-secrets")["ai-threatgen"]


def _redis_logins(namespace: str) -> dict[str, dict[str, str]]:
    """Each component's Redis login in a project (Secret tsg-redis-<component>): {its name: its values}."""
    return {
        o["metadata"]["name"]: o["stringData"]
        for o in _objects(SECRETS_FILE, kind="Secret")
        if o["metadata"]["namespace"] == namespace and o["metadata"]["name"].startswith("tsg-redis-")
    }


def _env_name(field: str) -> str:
    """The environment name a setting is read from: the owner's own name (CONTROL_CANDIDATES), else
    CII_<FIELD>."""
    alias = Settings.model_fields[field].validation_alias
    return alias if isinstance(alias, str) else f"CII_{field.upper()}"


def _load_settings(environment: dict[str, str]) -> Settings:
    """The app's settings as a pod builds them from exactly `environment`: no .env file and nothing from this
    computer's environment, which is put back afterwards."""
    saved = dict(os.environ)
    os.environ.clear()
    os.environ.update(environment)
    try:
        return Settings(_env_file=None)  # type: ignore[call-arg]
    finally:
        os.environ.clear()
        os.environ.update(saved)


def _cpu(amount: str) -> float:
    return float(amount[:-1]) / 1000 if amount.endswith("m") else float(amount)


def _gib(amount: str) -> float:
    return float(amount[:-2]) * {"Mi": 1 / 1024, "Gi": 1.0}[amount[-2:]]


def _pod_limits(deployment: dict) -> tuple[float, float]:
    """A pod's CPU and memory limits as a quota counts them: its containers together, or its largest init
    container when that is larger."""
    spec = deployment["spec"]["template"]["spec"]
    cpu = sum(_cpu(c["resources"]["limits"]["cpu"]) for c in spec["containers"])
    memory = sum(_gib(c["resources"]["limits"]["memory"]) for c in spec["containers"])
    for init in spec.get("initContainers", []):
        cpu = max(cpu, _cpu(init["resources"]["limits"]["cpu"]))
        memory = max(memory, _gib(init["resources"]["limits"]["memory"]))
    return cpu, memory


def _surge_pods(deployment: dict) -> int:
    """The extra pods an update starts before it stops old ones (the default: 25%, rounded up)."""
    strategy = deployment["spec"].get("strategy", {})
    if strategy.get("type") == "Recreate":
        return 0
    surge = strategy.get("rollingUpdate", {}).get("maxSurge", "25%")
    if isinstance(surge, str):
        return math.ceil(deployment["spec"].get("replicas", 1) * int(surge.rstrip("%")) / 100)
    return surge


def _addresses(url: str) -> list[tuple[str, str]]:
    """Every host and port a connection string names (MongoDB may list several), without its password."""
    if not url:
        return []
    parts = urlsplit(url)
    default = DEFAULT_PORTS.get(parts.scheme, "")
    found = []
    for host in parts.netloc.rpartition("@")[2].split(","):
        name, _, port = host.partition(":")
        found.append((name, port or default))
    return found


def _reachable(rules: Path) -> set[tuple[str, str]]:
    """Every (IP, port) a NetworkPolicy file's egress rules let the pods reach (ipBlock rules only)."""
    found = set()
    for policy in _objects(rules, kind="NetworkPolicy"):
        for rule in policy["spec"].get("egress", []):
            hosts = [
                peer["ipBlock"]["cidr"].removesuffix("/32")
                for peer in rule.get("to", [])
                if "ipBlock" in peer
            ]
            found |= {(host, str(port["port"])) for host in hosts for port in rule.get("ports", [])}
    return found


def _ports_open_to(rules: Path, peer: dict) -> set[int]:
    """The ports a NetworkPolicy file's ingress rules open to `peer`."""
    return {
        port["port"]
        for policy in _objects(rules, kind="NetworkPolicy")
        for rule in policy["spec"].get("ingress", [])
        if peer in rule.get("from", [])
        for port in rule.get("ports", [])
    }


def _uncommented_lines(path: Path) -> list[str]:
    """Each line without a trailing comment, skipping blanks, full-line comments, `---` and a block scalar's
    content (an embedded file cannot carry YAML comments; its `key: |` line can)."""
    found, block = [], None
    for number, line in enumerate(path.read_text(encoding="utf-8").split("\n"), 1):
        text, indent = line.strip(), len(line) - len(line.lstrip(" "))
        if block is not None:
            if not text or indent > block:
                continue
            block = None
        if not text or text.startswith("#") or text == "---":
            continue
        if " #" not in line:
            found.append(f"line {number}: {text[:80]}")
        if BLOCK_SCALAR.search(line.split(" #")[0].rstrip()):
            block = indent
    return found


def _scalars(node: object, key: object = None) -> list[tuple[object, object]]:
    """Every scalar of a parsed YAML tree, each key too, with the key it sits under."""
    if isinstance(node, dict):
        return [found for name, value in node.items() for found in [(key, name), *_scalars(value, name)]]
    if isinstance(node, list):
        return [found for item in node for found in _scalars(item, key)]
    return [(key, node)]


def _reads(deployment: dict) -> set[tuple[str, str, str]]:
    """Each (kind, name, key) a pod reads: ConfigMaps and Secrets by envFrom, env valueFrom and volumes, and
    its volume claims; key "" = the whole object."""
    spec = deployment["spec"]["template"]["spec"]
    reads = set()
    for container in _containers(deployment):
        sources = container.get("envFrom", []) + [
            v["valueFrom"] for v in container.get("env", []) if "valueFrom" in v
        ]
        for source in sources:
            for reference, target in source.items():
                if reference in REFERENCES:
                    reads.add((REFERENCES[reference], target["name"], target.get("key", "")))
    for volume in spec.get("volumes", []):
        if "configMap" in volume:
            keys = [item["key"] for item in volume["configMap"].get("items", [])] or [""]
            reads |= {("ConfigMap", volume["configMap"]["name"], key) for key in keys}
        if "secret" in volume:
            keys = [item["key"] for item in volume["secret"].get("items", [])] or [""]
            reads |= {("Secret", volume["secret"]["secretName"], key) for key in keys}
        if "persistentVolumeClaim" in volume:
            reads.add(("PersistentVolumeClaim", volume["persistentVolumeClaim"]["claimName"], ""))
    return reads


@pytest.mark.parametrize("path", YAML_FILES, ids=lambda path: path.name)
def test_no_deploy_file_names_kubernetes_io_but_the_node_label_that_spreads_pods(path: Path) -> None:
    """The owner's rule: no kubernetes.io anywhere, not in a label, selector, Secret type or comment, with one
    exception (2026-10-24): kubernetes.io/hostname as a topologyKey value, alone on its line bar a comment."""
    text = path.read_text(encoding="utf-8")
    lines = [line for line in text.splitlines() if KUBERNETES_IO in line]
    for line in lines:
        assert line.split(" #")[0].strip() == ": ".join(NODE_TOPOLOGY), line
        assert line.count(KUBERNETES_IO) == 1, line  # not in the line's comment
    parsed = [
        found
        for document in yaml.safe_load_all(text)
        for found in _scalars(document)
        if KUBERNETES_IO in str(found[1])
    ]
    # Each such line is a real topologyKey, not text inside a string (an embedded file, say).
    assert parsed == [NODE_TOPOLOGY] * len(lines)


@pytest.mark.parametrize("path", YAML_FILES, ids=lambda path: path.name)
def test_every_line_of_a_deploy_file_says_what_it_does(path: Path) -> None:
    """The owner's rule: every YAML line carries a plain-English comment, but an embedded file's lines."""
    assert _uncommented_lines(path) == []


def test_no_pod_takes_the_project_s_service_variables() -> None:
    """A Service named flower puts FLOWER_PORT=tcp://<ip>:5555 into every pod of its project, and Flower reads
    every FLOWER_* variable as its own option, so it took that address for its port and stopped at start-up.
    No pod takes these variables: each finds a Service by its DNS name."""
    for deployment in _all_deployments():
        pod = deployment["spec"]["template"]["spec"]
        assert pod.get("enableServiceLinks") is False, deployment["metadata"]["name"]


def test_every_object_is_in_its_file_s_project() -> None:
    for namespace, path in [*APP_FILES.items(), *NETWORK_FILES.items()]:
        assert {o["metadata"]["namespace"] for o in _objects(path)} == {namespace}, path.name
    # All in ai-common, but the right to read an app project's pods, and the monitoring proxy with its Routes
    # (only ai-threatgen may use the API's host).
    for item in _objects(COMMON_FILE):
        where, name = item["metadata"]["namespace"], item["metadata"]["name"]
        if name == "tsg-monitoring-read-pods":
            assert where in APP_FILES, item["kind"]
        elif name == PROXY or item["kind"] == "Route":
            assert where == "ai-threatgen", (item["kind"], name)
        else:
            assert where == MONITORING_NAMESPACE, (item["kind"], name)
    for path, shared in ((CONFIG_FILE, "tsg-config"), (SECRETS_FILE, "tsg-secrets")):
        assert sorted(_shared(path, shared)) == sorted(WATCHED), path.name  # every project with TSG pods
        others = {
            o["metadata"]["namespace"]
            for o in _objects(path)
            if o["metadata"]["name"] not in {shared, PROXY}
            and not o["metadata"]["name"].startswith("tsg-redis-")
        }
        assert others == {MONITORING_NAMESPACE}, path.name  # the monitoring's files and Grafana's password


def test_every_app_pod_runs_the_deployed_image_with_the_shared_settings_hardened_and_sized() -> None:
    flower = _deployment("flower")
    assert flower["spec"]["template"]["spec"]["automountServiceAccountToken"] is False
    images = {_container(flower)["image"]}  # Flower runs from the app image
    for deployment in _app_deployments():
        name, pod = deployment["metadata"]["name"], deployment["spec"]["template"]
        assert deployment["spec"]["selector"]["matchLabels"] == {"app": name}
        # component: api, worker or beat (Prometheus' job); part-of: the network rules select it
        assert pod["metadata"]["labels"] == {"app": name, "component": name.split("-")[0], "part-of": "tsg"}
        assert pod["spec"]["automountServiceAccountToken"] is False, name  # the app never calls the cluster
        assert pod["spec"]["imagePullSecrets"] == [{"name": "quay-pull"}]
        assert pod["spec"]["hostAliases"] == [{"ip": "10.231.255.253", "hostnames": ["llmapi.govai.ae"]}]
        container = _container(deployment)
        images.add(container["image"])
        assert container["envFrom"] == [
            {"configMapRef": {"name": "tsg-config"}},
            {"secretRef": {"name": "tsg-secrets"}},
            {"secretRef": {"name": f"tsg-redis-{name.split('-')[0]}"}},  # its component's own Redis login
        ]
        # Only the proxy is written inline: every setting (CII_AI_BYPASS_PROXY too) comes from tsg-config.
        assert {e["name"] for e in container["env"]} == {"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "no_proxy"}
        assert set(container["resources"]) == {"requests", "limits"}, name
        for amounts in container["resources"].values():
            assert set(amounts) == {"cpu", "memory"}, name
        assert container["livenessProbe"], name
        assert container["securityContext"] == HARDENED, name
    [image] = images  # one release: one tag on every app pod and Flower
    assert APP_IMAGE.fullmatch(image), image


def test_every_queue_has_a_worker_in_each_app_project() -> None:
    """/ready needs a live worker on every routed queue: each project alone serves them all, so either one's
    copy may stop to update (maxSurge 0) while /ready stays green."""
    queues: dict[str, list[str]] = {}
    for namespace, path in APP_FILES.items():
        for deployment in _objects(path, kind="Deployment"):
            command = _container(deployment)["command"]
            if command[:4] == ["celery", "-A", "app.worker", "worker"]:
                assert "--pool=threads" in command  # the worker refuses any other pool at start-up
                queues.setdefault(namespace, []).append(command[command.index("-Q") + 1])
    assert sorted(queues["ai-threatgen"]) == sorted(queues["ai-remediation"]) == sorted(ROUTED_QUEUES)


def test_worker_probes_read_the_heartbeat_file_never_redis() -> None:
    """A probe that pings through Redis restarts every worker (and kills its jobs) during a 3-minute outage:
    each worker's startup and liveness probe only reads the file its heartbeat touches."""
    for namespace, path in APP_FILES.items():
        for deployment in _objects(path, kind="Deployment"):
            container = _container(deployment)
            if container["command"][:4] == ["celery", "-A", "app.worker", "worker"]:
                for probe, expected in WORKER_PROBES.items():
                    probe_command = container[probe]["exec"]["command"]
                    assert probe_command == expected, (namespace, probe)
                    assert "celery" not in " ".join(probe_command), (namespace, probe)  # no broker call


def test_beat_runs_once_the_api_only_in_ai_threatgen_and_only_two_copies_get_a_budget() -> None:
    deployments = _app_deployments()
    [beat] = [d for d in deployments if d["metadata"]["name"] == "beat"]
    assert beat["metadata"]["namespace"] == "ai-threatgen" and beat["spec"]["replicas"] == 1
    assert beat["spec"]["strategy"] == {"type": "Recreate"}
    command, [mount] = _container(beat)["command"], _container(beat)["volumeMounts"]
    assert command[3] == "beat" and command[command.index("-s") + 1].startswith(mount["mountPath"] + "/")
    [api] = [d for d in deployments if d["metadata"]["name"] == "api"]
    assert api["metadata"]["namespace"] == "ai-threatgen"
    budgets = {
        b["metadata"]["name"] for b in _objects(*APP_FILES.values(), COMMON_FILE, kind="PodDisruptionBudget")
    }
    assert budgets == {d["metadata"]["name"] for d in deployments if d["spec"]["replicas"] >= 2} == {"api"}
    for deployment in deployments:
        if deployment["spec"]["strategy"]["type"] == "RollingUpdate":
            # The API starts its new copy first; a worker stops first, while its twin serves the queue.
            api = deployment["metadata"]["name"] == "api"
            expected = {"maxUnavailable": 0, "maxSurge": 1} if api else {"maxUnavailable": 1, "maxSurge": 0}
            assert deployment["spec"]["strategy"]["rollingUpdate"] == expected, deployment["metadata"]
        else:
            assert deployment["metadata"]["name"] == "beat"


def test_every_worker_and_the_api_prefer_a_node_without_another_copy_of_themselves() -> None:
    """A worker and its twin in the other project, or the two API pods, on one node both stop when it fails.
    Preferred, never required: a pod must still start on a small or busy cluster and as the API's surge pod.
    The API names no namespaces (its own project), so a CrossNamespacePodAffinity quota never refuses it."""
    spread = set()
    for deployment in _app_deployments():
        name, namespace = deployment["metadata"]["name"], deployment["metadata"]["namespace"]
        affinity = deployment["spec"]["template"]["spec"].get("affinity")
        if name == "beat":
            assert affinity is None  # a single pod: nothing to keep apart
            continue
        term = {"labelSelector": {"matchLabels": {"app": name}}, "topologyKey": NODE_TOPOLOGY[1]}
        if name != "api":
            term["namespaces"] = list(APP_FILES)  # the twin runs in the other project
        assert affinity == {
            "podAntiAffinity": {
                "preferredDuringSchedulingIgnoredDuringExecution": [{"weight": 100, "podAffinityTerm": term}]
            }
        }, (namespace, name)
        spread.add((namespace, name))
    assert ("ai-threatgen", "api") in spread and len(spread) == 1 + 2 * len(ROUTED_QUEUES)


def test_every_project_stays_within_its_quota_during_an_update() -> None:
    """Steady limits plus what an update adds. `oc apply` of a new image and `oc rollout restart deployment`
    roll every Deployment of a project at once, so every surge counts. A stopping pod also counts until it
    has exited; that only delays its replacement (OpenShift retries a refused create), so it is not added."""
    deployments = _all_deployments()
    claims = _objects(COMMON_FILE, kind="PersistentVolumeClaim")
    for namespace, (cpu_quota, memory_quota, storage_quota) in QUOTAS.items():
        cpu_needed = memory_needed = 0.0
        for deployment in (d for d in deployments if d["metadata"]["namespace"] == namespace):
            cpu, memory = _pod_limits(deployment)
            pods = deployment["spec"].get("replicas", 1) + _surge_pods(deployment)
            cpu_needed, memory_needed = cpu_needed + pods * cpu, memory_needed + pods * memory
        assert cpu_needed <= cpu_quota, namespace
        assert memory_needed <= memory_quota, namespace
        storage = sum(
            _gib(c["spec"]["resources"]["requests"]["storage"])
            for c in claims
            if c["metadata"]["namespace"] == namespace
        )
        assert storage <= storage_quota, namespace


def test_prometheus_alloy_and_kube_state_metrics_see_the_app_in_all_three_projects() -> None:
    """The alerts read job="api" and job="worker" (the pod label component); each scraped pod declares its
    port; the monitoring in ai-common reads each app project's pods through a Role there."""
    rules = (REPO / "observability" / "prometheus" / "rules.yml").read_text(encoding="utf-8")
    assert {"api", "worker"} <= set(re.findall(r'job="(\w+)"', rules))
    scraped: dict[str, set[str]] = {}
    for deployment in _all_deployments():
        pod = deployment["spec"]["template"]
        port = pod["metadata"].get("annotations", {}).get("prometheus.io/port")
        if port:
            declared = {p["containerPort"] for c in _containers(deployment) for p in c.get("ports", [])}
            assert int(port) in declared, deployment["metadata"]["name"]
            if deployment["metadata"]["namespace"] in APP_FILES:
                scraped.setdefault(pod["metadata"]["labels"]["component"], set()).add(port)
    assert scraped == {"api": {"8000"}, "worker": {_settings()["CII_WORKER_METRICS_PORT"]}}
    prometheus = yaml.safe_load((REPO / "observability" / "prometheus" / "prometheus.yml").read_text("utf-8"))
    [pods_job] = [job for job in prometheus["scrape_configs"] if job["job_name"] == "pods"]
    assert set(pods_job["kubernetes_sd_configs"][0]["namespaces"]["names"]) == set(WATCHED)
    job_rule = {"source_labels": ["__meta_kubernetes_pod_label_component"], "target_label": "job"}
    assert job_rule in pods_job["relabel_configs"]
    alloy = (REPO / "observability" / "alloy" / "uat.alloy").read_text(encoding="utf-8")
    assert all(f'"{namespace}"' in alloy for namespace in WATCHED)
    for pod_label, log_label in (("part_of", "app"), ("component", "component")):
        rule = (
            rf'source_labels = \["__meta_kubernetes_pod_label_{pod_label}"\]\s+target_label\s+= "{log_label}"'
        )
        assert re.search(rule, alloy), log_label
    for namespace in APP_FILES:
        [binding] = [
            b for b in _objects(COMMON_FILE, kind="RoleBinding") if b["metadata"]["namespace"] == namespace
        ]
        assert {(s["name"], s["namespace"]) for s in binding["subjects"]} == {
            (name, MONITORING_NAMESPACE) for name in ("prometheus", "alloy", "kube-state-metrics")
        }, namespace
    assert f"--namespaces={','.join(WATCHED)}" in _container(_deployment("kube-state-metrics"))["args"]


def test_both_projects_reach_the_same_stores_and_the_monitoring_and_router_reach_the_app() -> None:
    """Prometheus (ai-common) scrapes the API and the workers, the router sends the public https calls to the
    API, and every pod looks names up: a rule without these leaves the pods unreachable or blind."""
    assert _reachable(NETWORK_FILES["ai-threatgen"]) == _reachable(NETWORK_FILES["ai-remediation"])
    scraped = {"ai-threatgen": {8000, 9100}, "ai-remediation": {9100}}  # the API and the worker metrics
    for namespace, path in NETWORK_FILES.items():
        assert _ports_open_to(path, MONITORING_PEER) >= scraped[namespace], namespace
        to_any_address = [
            {(port["port"], port["protocol"]) for port in rule["ports"]}
            for policy in _objects(path, kind="NetworkPolicy")
            for rule in policy["spec"].get("egress", [])
            if "to" not in rule
        ]
        assert any(ports >= DNS for ports in to_any_address), namespace
    # The API's port, and the monitoring proxy's (tests/test_deploy_monitoring_proxy.py checks it alone).
    assert _ports_open_to(NETWORK_FILES["ai-threatgen"], ROUTER_PEER) == {8000, 8080}


def test_each_project_may_reach_every_store_the_proxy_and_the_ai_gateway() -> None:
    """Owner 2026-10-16 (G264): on OpenShift the AI gateway is called directly (CII_AI_BYPASS_PROXY=true) and
    only the outside calls, the intel feeds, go through the proxy. Each project's egress rules allow every
    store the secrets name (the template keeps the real host:port), the pods' proxy and the pinned gateway
    address (hostAliases), so the rules and the addresses cannot drift apart."""
    secrets = _secrets()
    for namespace, app_file in APP_FILES.items():
        allowed = _reachable(NETWORK_FILES[namespace])
        assert ("10.61.192.2", "8080") in allowed, namespace  # the proxy the intel feeds go through
        logins = [url for login in _redis_logins(namespace).values() for url in login.values()]
        assert logins, namespace
        for url in [*(secrets[key] for key in STORES), *logins]:
            assert _addresses(url), urlsplit(url).scheme
            for address in _addresses(url):
                assert address in allowed, (namespace, address)
        for deployment in _objects(app_file, kind="Deployment"):
            name = deployment["metadata"]["name"]
            env = {variable["name"]: variable["value"] for variable in _container(deployment)["env"]}
            for proxy in ("HTTP_PROXY", "HTTPS_PROXY"):
                assert set(_addresses(env[proxy])) <= allowed, (namespace, name, proxy)
            for alias in deployment["spec"]["template"]["spec"]["hostAliases"]:
                assert (alias["ip"], "443") in allowed, (namespace, name)


def test_every_app_pod_lists_its_pinned_ai_gateway_on_both_no_proxy_spellings() -> None:
    """D23 (UAT, 2026-10-21): through the corporate proxy every AI call timed out; the pods list the gateway
    on NO_PROXY and no_proxy themselves, so every tool in the pod goes direct, the app's own bypass aside."""
    for deployment in _app_deployments():
        hosts = {
            name
            for alias in deployment["spec"]["template"]["spec"]["hostAliases"]
            for name in alias["hostnames"]
        }
        env = {variable["name"]: variable["value"] for variable in _container(deployment)["env"]}
        assert env["NO_PROXY"] == env["no_proxy"], deployment["metadata"]["name"]
        assert hosts <= set(env["NO_PROXY"].split(",")), deployment["metadata"]["name"]


def test_every_ai_gateway_is_https_on_443_pinned_and_off_the_proxy_in_every_app_pod() -> None:
    """A LiteLLM gateway (litellm_proxy/ models) the pods cannot call directly times out through the proxy:
    it must be https on 443 (the only port the egress rules open to it), pinned (hostAliases) and on
    NO_PROXY and no_proxy in every app pod, and the app must bypass the proxy for it."""
    settings = _settings()
    assert settings["CII_AI_BYPASS_PROXY"] == "true"
    gateways = {
        settings[url] for model, url in GATEWAYS if settings.get(model, "").startswith(LITELLM_MODEL_PREFIX)
    }
    assert gateways
    for address in gateways:
        parts = urlsplit(address)
        assert parts.scheme == "https" and parts.port in (None, 443), address
        for deployment in _app_deployments():
            name = deployment["metadata"]["name"]
            pinned = {
                host
                for alias in deployment["spec"]["template"]["spec"]["hostAliases"]
                for host in alias["hostnames"]
            }
            env = {variable["name"]: variable["value"] for variable in _container(deployment)["env"]}
            assert parts.hostname in pinned, (address, name)
            for variable in ("NO_PROXY", "no_proxy"):
                assert parts.hostname in env[variable].split(","), (address, name, variable)


def test_the_pods_settings_load_and_a_wildcard_origin_stops_them(monkeypatch: pytest.MonkeyPatch) -> None:
    """A pod builds its settings from tsg-config, tsg-secrets and its Redis login alone: a missing required
    setting, a short admin key or a "*" CORS origin would stop every pod at start-up, so it must fail here."""
    monkeypatch.setenv("TSG_TEST_SENTINEL", "kept")
    environment = _settings() | _secrets() | _redis_logins("ai-threatgen")["tsg-redis-api"]
    assert _load_settings(environment).ai_bypass_proxy is True
    assert environment["CII_CORS_ORIGINS"] != "*"
    with pytest.raises(ValidationError):
        _load_settings(environment | {"CII_CORS_ORIGINS": "*"})
    assert os.environ["TSG_TEST_SENTINEL"] == "kept"  # this process's environment is put back


def test_the_secret_template_holds_every_secret_and_placeholders_only() -> None:
    """Every key, password and connection string goes to tsg-secrets, never to tsg-config; the template in
    git holds no real value, and the operator's copy with the real values is git-ignored."""
    secrets = _secrets()
    assert set(secrets) == SECRET_NAMES
    secret_fields = CONNECTIONS | {
        field for field, info in Settings.model_fields.items() if info.annotation is SecretStr
    }
    assert {_env_name(field) for field in secret_fields} <= SECRET_NAMES | REDIS_LOGIN_KEYS
    logins = [
        url for namespace in WATCHED for login in _redis_logins(namespace).values() for url in login.values()
    ]
    assert all("CHANGE_ME" in value for value in [*secrets.values(), *logins] if value)
    # Every store login names its user: a Redis URL without one logs in as Redis' "default" user.
    assert all(urlsplit(url).username for url in [*(secrets[key] for key in STORES), *logins])
    assert not set(_settings()) & (SECRET_NAMES | REDIS_LOGIN_KEYS)
    git = shutil.which("git") or "git"
    ignored = subprocess.run(  # noqa: S603
        [git, "check-ignore", "-q", str(SECRETS_COPY.relative_to(REPO).as_posix())],
        cwd=REPO,
        check=False,
    )
    assert ignored.returncode == 0, "deploy/secrets.yaml must be git-ignored"


def test_every_project_gets_the_same_settings_and_only_ones_the_app_reads() -> None:
    """The three projects' pods share one queue and one database: their settings cannot differ. A key the app
    does not read (a typo, an old name) would be silently ignored."""
    for path, name in ((CONFIG_FILE, "tsg-config"), (SECRETS_FILE, "tsg-secrets")):
        copies = list(_shared(path, name).values())
        assert len(copies) == len(WATCHED) and all(copy == copies[0] for copy in copies), name
    read = {_env_name(field) for field in Settings.model_fields}
    assert set(_settings()) - read == set()


def test_every_config_map_secret_and_volume_a_pod_reads_is_written_in_its_project() -> None:
    """A pod that reads a ConfigMap, Secret, key or volume its project does not have never starts."""
    written = {
        (o["kind"], o["metadata"]["namespace"], o["metadata"]["name"]): o.get("data")
        or o.get("stringData")
        or {}
        for o in _objects(CONFIG_FILE, SECRETS_FILE, COMMON_FILE)
        if o["kind"] in {"ConfigMap", "Secret", "PersistentVolumeClaim"}
    }
    for deployment in _all_deployments():
        namespace, name = deployment["metadata"]["namespace"], deployment["metadata"]["name"]
        for kind, target, key in _reads(deployment):
            assert (kind, namespace, target) in written, (namespace, name, kind, target)
            assert not key or key in written[(kind, namespace, target)], (namespace, name, target, key)


def test_each_embedded_monitoring_config_is_its_observability_file_byte_for_byte() -> None:
    """The laptop runs observability/'s files and OpenShift configmap.yaml's copies: a change made to one
    only must fail here."""
    embedded = {
        key: text
        for config_map in _objects(CONFIG_FILE, kind="ConfigMap")
        if config_map["metadata"]["name"] != "tsg-config"
        for key, text in config_map["data"].items()
    }
    assert set(embedded) == set(EMBEDDED_CONFIGS)
    differ = [
        key
        for key, source in EMBEDDED_CONFIGS.items()
        if embedded[key].encode("utf-8") != (REPO / source).read_bytes()
    ]
    assert differ == []


def test_monitoring_images_come_from_the_mirror_with_a_pinned_version() -> None:
    """The cluster pulls only from the Quay mirror, and a moving tag (latest) would change a pod at its next
    restart. Flower runs from the app image, checked with the app pods."""
    for deployment in _objects(COMMON_FILE, kind="Deployment"):
        if deployment["metadata"]["name"] != "flower":
            for container in _containers(deployment):
                pinned = rf"{re.escape(MIRROR)}/[\w.-]+:v?\d+\.\d+\.\d+"
                assert re.fullmatch(pinned, container["image"]), container["image"]


def test_the_image_gets_only_what_it_runs() -> None:
    """.dockerignore is an allow-list (no .env file can reach a build), the Dockerfile copies exactly what it
    allows, and the image has no local reranker (torch) and no root user."""
    rules = [
        line
        for line in (REPO / ".dockerignore").read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    ]
    allowed = {line[1:].rstrip("/") for line in rules if line.startswith("!")}
    dockerfile = (REPO / "Dockerfile").read_text(encoding="utf-8")
    copied = {source for line in re.findall(r"^COPY (.+) \S+$", dockerfile, re.M) for source in line.split()}
    assert rules[0] == "*" and copied == allowed == {"pyproject.toml", "requirements.txt", "app"}
    assert "local" not in re.findall(r"\[(\w+)\]", dockerfile) and "\nUSER 10001\n" in dockerfile


def test_ai_workers_ask_for_about_as_many_ai_calls_as_the_cap_allows() -> None:
    """Each AI worker's own threads x AI calls per job x replicas, summed over a project, near
    CII_MAX_CONCURRENT_AI_CALLS (either project alone serves every queue while its twin restarts): more only
    waits on a slot (and times out the job), far fewer leaves the cap unused. With no cap (0), the chat
    model's requests-a-minute limit paces the calls: it is set, and within what kimi-k2.5 takes."""
    settings = _settings()
    cap = int(settings["CII_MAX_CONCURRENT_AI_CALLS"])
    if cap == 0:
        assert 0 < int(settings["CII_CHAT_REQUESTS_PER_MINUTE"]) <= CHAT_MODEL_REQUESTS_PER_MINUTE
        return
    calls_per_job = {
        Queue.THREATS: ThreatFinding.AI_BATCHES_AT_ONCE,
        Queue.SCENARIOS: Generation.WRITER_BATCH,
        Queue.CONTROLS: Controls.PER_DELIVERY,
    }
    for namespace, path in APP_FILES.items():
        asked, checked = 0, set()
        for deployment in _objects(path, kind="Deployment"):
            command = _container(deployment)["command"]
            queue = command[command.index("-Q") + 1] if "-Q" in command else None
            if queue in calls_per_job:
                threads = int(command[command.index("-c") + 1])
                asked += threads * calls_per_job[queue] * deployment["spec"]["replicas"]
                checked.add(queue)
        assert checked == set(calls_per_job), namespace
        assert cap / 2 < asked <= cap, (namespace, asked, cap)


def test_a_running_job_s_message_is_never_redelivered_to_another_worker() -> None:
    """The broker hands an unacknowledged message to another worker after its visibility timeout: it outlasts
    the longest job plus the lease the reaper waits out."""
    timeout = celery_app.conf.broker_transport_options["visibility_timeout"]
    assert timeout > Lease.MAX_JOB_SECONDS + Lease.SECONDS
