"""The OpenShift delivery (M15, T-OPS-08), laid out as v1 was: deploy/deploy.yaml (ai-threatgen),
deploy/deploy.ai-remediation.yaml, the two networkpolicy files, the settings generator and its safety gate,
the deploy script's lists, and what goes into the image. A broken file must fail here, not halfway through a
rollout."""

import importlib
import os
import re
import sys
from pathlib import Path

import pytest
import yaml

from app.core.config import Settings
from app.core.constants import Generation, Lease, Queue, ThreatFinding, Worker
from app.worker import ROUTED_QUEUES, celery_app

REPO = Path(__file__).resolve().parents[1]
DEPLOY = REPO / "deploy"
APP_FILES = {"ai-threatgen": DEPLOY / "deploy.yaml", "ai-remediation": DEPLOY / "deploy.ai-remediation.yaml"}
NETWORK_FILES = {
    "ai-threatgen": DEPLOY / "networkpolicy.yaml",
    "ai-remediation": DEPLOY / "networkpolicy.ai-remediation.yaml",
}
MONITORING_FILES = (DEPLOY / "observability.yaml", DEPLOY / "flower.yaml")
APP_IMAGE = "quay-quay-registry.apps.dda-desc-az1-01.desccii.local/dda-desc/tsg-api:v2-COMMIT"
API_HOST = "threatgen-api.apps.dda-desc-az1-01.desccii.local"
MONITORING_HOST = "threatgen-grafana.apps.dda-desc-az1-01.desccii.local"
QUOTA_CPU = 6.0  # v1's notes: ai-threatgen's budget, in CPU limits
SECRET_NAMES = {
    "CII_DB_DSN",
    "CII_PROXY_URL",  # an address can carry a password
    "CII_MONGO_URL",
    "CII_REDIS_URL",
    "CII_REDIS_CELERY_BROKER_URL",
    "CII_CHAT_API_KEY",
    "CII_EMBEDDING_API_KEY",
    "CII_RERANK_API_KEY",
    "CII_ADMIN_API_KEY",
    "CII_NVD_API_KEY",
}


def _generator():
    sys.path.insert(0, str(REPO / "scripts"))
    try:
        return importlib.import_module("gen_openshift_config")
    finally:
        sys.path.remove(str(REPO / "scripts"))


def _objects(*paths: Path, kind: str = "") -> list[dict]:
    found = [o for path in paths for o in yaml.safe_load_all(path.read_text(encoding="utf-8")) if o]
    return [o for o in found if not kind or o["kind"] == kind]


def _app_deployments() -> list[dict]:
    return _objects(*APP_FILES.values(), kind="Deployment")


def _container(deployment: dict) -> dict:
    [container] = deployment["spec"]["template"]["spec"]["containers"]
    return container


def _cpu(amount: str) -> float:
    return float(amount[:-1]) / 1000 if amount.endswith("m") else float(amount)


def _script_names(block: str) -> dict[str, list[str]]:
    """The names a deploy-script list holds: `$Monitoring = @(...)` -> {"": [...]}; an `[ordered]@{...}`
    block of `$App = @(...)` lines -> {"App": [...], "Extra": [...]}."""
    script = (DEPLOY / "deploy-uat.ps1").read_text(encoding="ascii")
    found = re.search(rf"^\${block} = (?:@\((.*?)\)|\[ordered\]@\{{(.*?)^\}})$", script, re.M | re.S)
    assert found, block
    if found.group(1) is not None:
        return {"": re.findall(r"'([^']+)'", found.group(1))}
    return {
        key: re.findall(r"'([^']+)'", names)
        for key, names in re.findall(r"\$(\w+)\s*= @\(([^)]*)\)", found.group(2))
    }


def _uat_values() -> dict[str, str]:
    """A settings file that must pass the gate: .env.example's lines, with UAT's kind of values."""
    values = _generator().read_env(REPO / ".env.example")
    return values | {
        "CII_ENV": "uat",
        "CII_CORS_ORIGINS": "https://platform.example.local",
        "CII_ADMIN_API_KEY": "a" * 40,
        "EVIDENCE_SIMILARITY_THRESHOLD": "40",
        "CII_DB_DSN": "mssql+pyodbc://tsg:pw@10.228.146.2:1444/EYShieldDB_Copy?driver=ODBC+Driver+17+for+SQL+Server",
        "CII_MONGO_URL": "mongodb://tsg:pw@10.228.146.3:27018/?authSource=admin&directConnection=true",
        "CII_REDIS_URL": "redis://:pw@10.228.146.4:6379/0",
        "CII_REDIS_CELERY_BROKER_URL": "redis://:pw@10.228.146.4:6379/1",
        "CII_AI_BYPASS_PROXY": "true",  # owner 2026-10-16: the pods call the AI gateway directly
    }


def test_every_object_is_in_its_file_s_project() -> None:
    for namespace, path in [*APP_FILES.items(), *NETWORK_FILES.items()]:
        assert {o["metadata"]["namespace"] for o in _objects(path)} == {namespace}, path.name


def test_every_app_pod_runs_the_deployed_image_with_the_shared_settings_hardened_and_sized() -> None:
    for deployment in _app_deployments():
        name, pod = deployment["metadata"]["name"], deployment["spec"]["template"]
        labels = pod["metadata"]["labels"]
        assert deployment["spec"]["selector"]["matchLabels"] == {"app.kubernetes.io/name": name}
        assert labels["app.kubernetes.io/name"] == name and labels["app.kubernetes.io/part-of"] == "tsg"
        assert pod["metadata"]["annotations"]["tsg/settings-fingerprint"] == "none"  # the script fills it
        assert pod["spec"]["imagePullSecrets"] == [{"name": "quay-pull"}]
        assert pod["spec"]["hostAliases"] == [{"ip": "10.231.255.253", "hostnames": ["llmapi.govai.ae"]}]
        container = _container(deployment)
        assert container["image"] == APP_IMAGE, name  # one image; deploy-uat.ps1 puts the deployed tag in
        assert container["envFrom"] == [
            {"configMapRef": {"name": "tsg-config"}},
            {"secretRef": {"name": "tsg-secrets"}},
        ]
        # Only the proxy is written inline: every setting (CII_AI_BYPASS_PROXY too) comes from the env file.
        assert {e["name"] for e in container["env"]} == {"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "no_proxy"}
        for amounts in container["resources"].values():
            assert set(amounts) == {"cpu", "memory"}, name
        assert container["livenessProbe"], name
        assert container["securityContext"] == {
            "allowPrivilegeEscalation": False,
            "runAsNonRoot": True,
            "capabilities": {"drop": ["ALL"]},
            "seccompProfile": {"type": "RuntimeDefault"},
        }


def test_every_queue_has_a_worker_in_ai_threatgen_and_the_second_ones_are_in_ai_remediation() -> None:
    """/ready needs a live worker on every routed queue: ai-threatgen alone must serve them all."""
    queues: dict[str, list[str]] = {}
    for namespace, path in APP_FILES.items():
        for deployment in _objects(path, kind="Deployment"):
            command = _container(deployment)["command"]
            if command[:4] == ["celery", "-A", "app.worker", "worker"]:
                assert "--pool=threads" in command  # the worker refuses any other pool at start-up
                queues.setdefault(namespace, []).append(command[command.index("-Q") + 1])
    assert sorted(queues["ai-threatgen"]) == sorted(ROUTED_QUEUES)
    assert sorted(queues["ai-remediation"]) == sorted(set(ROUTED_QUEUES) - {Queue.MAINTENANCE})


def test_beat_runs_once_the_api_only_in_ai_threatgen_and_only_two_copies_get_a_budget() -> None:
    deployments = _app_deployments()
    [beat] = [d for d in deployments if d["metadata"]["name"] == "beat"]
    assert beat["metadata"]["namespace"] == "ai-threatgen" and beat["spec"]["replicas"] == 1
    assert beat["spec"]["strategy"] == {"type": "Recreate"}
    command, [mount] = _container(beat)["command"], _container(beat)["volumeMounts"]
    assert command[3] == "beat" and command[command.index("-s") + 1].startswith(mount["mountPath"] + "/")
    [api] = [d for d in deployments if d["metadata"]["name"] == "api"]
    assert api["metadata"]["namespace"] == "ai-threatgen"
    budgets = {b["metadata"]["name"] for b in _objects(*APP_FILES.values(), kind="PodDisruptionBudget")}
    assert budgets == {d["metadata"]["name"] for d in deployments if d["spec"]["replicas"] >= 2} == {"api"}
    for deployment in deployments:
        if deployment["spec"]["strategy"]["type"] == "RollingUpdate":
            assert deployment["spec"]["strategy"]["rollingUpdate"] == {"maxUnavailable": 0, "maxSurge": 1}


def test_ai_threatgen_stays_within_its_cpu_budget_during_an_update() -> None:
    """Steady CPU limits plus the one extra pod an update starts at a time (deploy-uat.ps1 rolls them one by
    one)."""
    pods = [
        (d["spec"]["replicas"], _cpu(_container(d)["resources"]["limits"]["cpu"]))
        for d in _objects(APP_FILES["ai-threatgen"], kind="Deployment")
    ]
    assert sum(count * cpu for count, cpu in pods) + max(cpu for _, cpu in pods) <= QUOTA_CPU


def test_prometheus_alloy_and_kube_state_metrics_see_the_app_in_both_projects() -> None:
    """The alerts read job="api" and job="worker" (the component label); each scraped pod declares its port;
    the monitoring in ai-remediation reads ai-threatgen's pods through a Role there."""
    rules = (REPO / "observability" / "prometheus" / "rules.yml").read_text(encoding="utf-8")
    scraped: dict[str, set[str]] = {}
    for deployment in _app_deployments():
        pod = deployment["spec"]["template"]
        port = pod["metadata"]["annotations"].get("prometheus.io/port")
        if port:
            assert int(port) in {p["containerPort"] for p in _container(deployment)["ports"]}
            scraped.setdefault(pod["metadata"]["labels"]["app.kubernetes.io/component"], set()).add(port)
    assert {"api", "worker"} <= set(re.findall(r'job="(\w+)"', rules))
    assert scraped == {"api": {"8000"}, "worker": {str(Settings.model_fields["worker_metrics_port"].default)}}
    prometheus = yaml.safe_load((REPO / "observability" / "prometheus" / "prometheus.yml").read_text("utf-8"))
    [pods_job] = [job for job in prometheus["scrape_configs"] if job["job_name"] == "pods"]
    assert set(pods_job["kubernetes_sd_configs"][0]["namespaces"]["names"]) == set(APP_FILES)
    assert all(
        f'"{namespace}"' in (REPO / "observability" / "alloy" / "uat.alloy").read_text()
        for namespace in APP_FILES
    )
    [binding] = [
        b
        for b in _objects(*MONITORING_FILES, kind="RoleBinding")
        if b["metadata"]["namespace"] == "ai-threatgen"
    ]
    assert {s["name"] for s in binding["subjects"]} == {"prometheus", "alloy", "kube-state-metrics"}
    [ksm] = [
        d
        for d in _objects(*MONITORING_FILES, kind="Deployment")
        if d["metadata"]["name"] == "kube-state-metrics"
    ]
    assert f"--namespaces={','.join(APP_FILES)}" in _container(ksm)["args"]


def test_every_route_is_https_on_its_host_and_no_two_share_a_path() -> None:
    routes = _objects(*APP_FILES.values(), *MONITORING_FILES, kind="Route")
    places = [(r["metadata"]["namespace"], r["spec"]["host"], r["spec"]["path"]) for r in routes]
    assert len(places) == len(set(places))
    assert {place[:2] for place in places} == {
        ("ai-threatgen", API_HOST),
        ("ai-remediation", MONITORING_HOST),
    }
    assert ("ai-threatgen", API_HOST, "/") in places
    assert all(
        r["spec"]["tls"] == {"termination": "edge", "insecureEdgeTerminationPolicy": "Redirect"}
        for r in routes
    )


def test_both_projects_reach_the_same_stores_and_prometheus_reaches_the_app() -> None:
    generator = _generator()
    assert generator.reachable(NETWORK_FILES["ai-threatgen"]) == generator.reachable(
        NETWORK_FILES["ai-remediation"]
    )
    [ingress] = [p for p in _objects(NETWORK_FILES["ai-threatgen"]) if "Ingress" in p["spec"]["policyTypes"]]
    from_monitoring = [
        rule
        for rule in ingress["spec"]["ingress"]
        if {"kubernetes.io/metadata.name": "ai-remediation"}
        in [peer.get("namespaceSelector", {}).get("matchLabels") for peer in rule["from"]]
    ]
    assert from_monitoring and {p["port"] for p in from_monitoring[0]["ports"]} >= {8000, 9100}


def test_the_deploy_script_rolls_and_recognises_every_v2_deployment() -> None:
    """deploy-uat.ps1 rolls the app Deployments it names, the API last, and treats a Deployment of a v2
    monitoring name that v2 did not make as v1's: its lists must be the files' Deployments."""
    rollout = _script_names("Rollout")
    for namespace, variable in (("ai-threatgen", "App"), ("ai-remediation", "Extra")):
        in_file = [d["metadata"]["name"] for d in _objects(APP_FILES[namespace], kind="Deployment")]
        assert sorted(rollout[variable]) == sorted(in_file), namespace
    assert rollout["App"][-1] == "api"  # every queue has its worker before an API pod can be ready
    # ai-remediation's workers roll before ai-threatgen's, so the API is the last rollout of the whole run:
    # a new API may queue work only a new worker can do (D18).
    assert list(rollout) == ["Extra", "App"]
    in_files = {d["metadata"]["name"] for d in _objects(*MONITORING_FILES, kind="Deployment")}
    assert set(_script_names("Monitoring")[""]) == in_files


def test_secrets_go_to_the_secret_plain_settings_to_the_config_map_and_other_lines_nowhere() -> None:
    generator = _generator()
    extra = {
        "GRAFANA_ADMIN_PASSWORD": "x",
        "GF_AUTH_ANONYMOUS_ENABLED": "true",
        "CII_LOG_DIR": "logs",
        "OLD": "1",
    }
    values = _uat_values() | extra
    config, secret, left_out = generator.split_settings(values)
    assert set(secret) == SECRET_NAMES
    assert "CONTROL_CANDIDATES" in config and "CII_ENV" in config and not set(config) & set(secret)
    assert left_out == sorted({key for key in values if key.startswith("GF_")} | set(extra))


def test_the_manifests_carry_no_secret_in_plain_text_and_are_the_names_the_pods_read() -> None:
    generator = _generator()
    config, secret, _ = generator.split_settings(_uat_values() | {"THREAT_CONTEXT_COUNTRY": "Émirats"})
    text = generator.manifests(config, secret)
    assert text.isascii() and "a" * 40 not in text and ":pw@" not in text
    config_map, secret_object = yaml.safe_load_all(text)
    read = _container(_app_deployments()[0])["envFrom"]
    assert read == [
        {"configMapRef": {"name": config_map["metadata"]["name"]}},
        {"secretRef": {"name": secret_object["metadata"]["name"]}},
    ]
    assert config_map["data"]["THREAT_CONTEXT_COUNTRY"] == "Émirats"


def test_the_gate_passes_a_good_file_and_names_each_problem_never_its_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generator = _generator()
    monkeypatch.setenv("TSG_TEST_SENTINEL", "kept")
    good = _uat_values()
    assert generator.settings_problems(good) == [] and generator.store_problems(good) == []
    bad = {key: value for key, value in good.items() if key != "CONTROL_CANDIDATES"}
    problems = generator.settings_problems(
        bad | {"CII_CORS_ORIGINS": "*", "CII_ADMIN_API_KEY": "short-secret"}
    )
    # The laptop's .env sets CONTROL_CANDIDATES: the gate reads only the settings it is given.
    assert any(problem.startswith("CONTROL_CANDIDATES: Field required") for problem in problems)
    assert "short-secret" not in "".join(problems)
    assert generator.settings_problems(good | {"CII_CORS_ORIGINS": "*"})
    # Owner 2026-10-16 (G264): the AI direct, only the outside calls (the intel feeds) through the proxy.
    bypass = generator.settings_problems(good | {"CII_AI_BYPASS_PROXY": "false"})
    assert [problem.split(":")[0] for problem in bypass] == ["CII_AI_BYPASS_PROXY"]
    assert os.environ["TSG_TEST_SENTINEL"] == "kept"  # this process's environment is put back


def test_a_store_the_network_rules_do_not_allow_is_named_for_each_project_without_its_password() -> None:
    generator = _generator()
    moved = _uat_values() | {"CII_MONGO_URL": "mongodb://tsg:topsecret@10.0.0.9:27018,10.228.146.3:27018/"}
    problems = generator.store_problems(moved)
    assert [p.split(" is ")[0] for p in problems] == ["CII_MONGO_URL: 10.0.0.9:27018"] * 2
    assert (
        "deploy/networkpolicy.yaml" in problems[0]
        and "deploy/networkpolicy.ai-remediation.yaml" in problems[1]
    )
    assert "topsecret" not in "".join(problems)
    assert generator.addresses("redis://10.228.146.4/0") == [("10.228.146.4", "6379")]
    assert generator.monitoring_problems({"GRAFANA_ADMIN_PASSWORD": "x" * 15})
    assert generator.monitoring_problems({"GRAFANA_ADMIN_PASSWORD": "x" * 16}) == []
    assert generator.monitoring_problems({}) == []  # no line: no Grafana login (random password, never shown)


def test_the_fingerprint_changes_with_a_setting_and_only_then(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    generator = _generator()
    path = tmp_path / ".env.uat"

    def fingerprint(values: dict[str, str]) -> str:
        path.write_text("".join(f"{key}={value}\n" for key, value in values.items()), encoding="utf-8")
        assert generator.main([str(path), "--fingerprint"]) == 0
        return capsys.readouterr().out

    first = fingerprint(_uat_values())
    assert re.fullmatch(r"[0-9a-f]{16}", first) and fingerprint(_uat_values()) == first
    assert fingerprint(_uat_values() | {"CII_CHAT_API_KEY": "rotated"}) != first


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


def test_the_pods_may_reach_the_ai_gateway_directly_and_the_proxy_for_the_feeds() -> None:
    """Owner 2026-10-16 (G264): on OpenShift the AI gateway is called directly (CII_AI_BYPASS_PROXY=true) and
    only the outside calls, the intel feeds, go through the proxy: each project's egress rules allow both, so
    the pinned gateway address (hostAliases) and the rules cannot drift apart."""
    generator = _generator()
    for namespace, app_file in APP_FILES.items():
        allowed = generator.reachable(NETWORK_FILES[namespace])
        assert ("10.61.192.2", "8080") in allowed, namespace  # the proxy: the intel feeds
        for deployment in _objects(app_file, kind="Deployment"):
            for alias in deployment["spec"]["template"]["spec"]["hostAliases"]:
                assert (alias["ip"], "443") in allowed, (namespace, deployment["metadata"]["name"])


GATEWAY_SETTINGS = {
    "CII_CHAT_MODEL": "litellm_proxy/kimi-k2.5",
    "CII_CHAT_BASE_URL": "https://llmapi.govai.ae",
    "CII_EMBEDDING_MODEL": "litellm_proxy/qwen3-embedding-8b-mig",
    "CII_EMBEDDING_BASE_URL": "https://llmapi.govai.ae",
    "CII_RERANK_MODEL": "litellm_proxy/qwen3-reranker-8b-mig",
    "CII_RERANK_BASE_URL": "https://llmapi.govai.ae",
}


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


def test_the_gate_refuses_an_ai_gateway_the_pods_cannot_call_directly() -> None:
    generator = _generator()
    good = _uat_values() | GATEWAY_SETTINGS
    assert generator.gateway_problems(good) == []
    for url in ("http://llmapi.govai.ae", "https://llmapi.govai.ae:8443"):
        problems = generator.gateway_problems(good | {"CII_CHAT_BASE_URL": url})
        assert problems == [
            "CII_CHAT_BASE_URL: the AI gateway must be https on port 443, the port the egress rules open"
        ]
    moved = generator.gateway_problems(good | {"CII_EMBEDDING_BASE_URL": "https://llm.other.ae"})
    pods = len(_app_deployments())
    assert len(moved) == 3 * pods  # each pod: not pinned, not on NO_PROXY, not on no_proxy
    assert all(problem.startswith("CII_EMBEDDING_BASE_URL: llm.other.ae is not ") for problem in moved)
    not_the_gateway = {"CII_CHAT_MODEL": "openai/gpt"}  # not a LiteLLM gateway model: nothing to check
    assert generator.gateway_problems(good | not_the_gateway) == []


def test_the_deploy_gate_runs_the_gateway_check(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    generator, path = _generator(), tmp_path / ".env.uat"
    values = _uat_values() | GATEWAY_SETTINGS | {"CII_CHAT_BASE_URL": "http://llmapi.govai.ae"}
    path.write_text("".join(f"{key}={value}\n" for key, value in values.items()), encoding="utf-8")
    assert generator.main([str(path), "--gate"]) == 1
    assert "GATE FAILED  CII_CHAT_BASE_URL: the AI gateway must be https" in capsys.readouterr().out


def test_ai_workers_ask_for_about_as_many_ai_calls_as_the_cap_allows() -> None:
    """Threads x AI calls per job x replicas near CII_MAX_CONCURRENT_AI_CALLS: more only waits on a slot (and
    times out the job), far fewer leaves the cap unused."""
    cap = Settings.model_fields["max_concurrent_ai_calls"].default
    calls_per_job = {
        Queue.THREATS: ThreatFinding.AI_BATCHES_AT_ONCE,
        Queue.SCENARIOS: Generation.WRITER_BATCH,
    }
    for deployment in _objects(APP_FILES["ai-threatgen"], kind="Deployment"):
        command = _container(deployment)["command"]
        queue = command[command.index("-Q") + 1] if "-Q" in command else None
        if queue in calls_per_job:
            threads = int(command[command.index("-c") + 1])
            asked = threads * calls_per_job[queue] * deployment["spec"]["replicas"]
            assert threads == Worker.THREADS and cap / 2 < asked <= cap, (queue, asked, cap)


def test_a_running_job_s_message_is_never_redelivered_to_another_worker() -> None:
    """The broker hands an unacknowledged message to another worker after its visibility timeout: it outlasts
    the longest job plus the lease the reaper waits out."""
    timeout = celery_app.conf.broker_transport_options["visibility_timeout"]
    assert timeout > Lease.MAX_JOB_SECONDS + Lease.SECONDS
