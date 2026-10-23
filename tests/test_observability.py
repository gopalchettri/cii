"""The monitoring files (observability/, deploy/observability.yaml, scripts/monitoring.py) stay valid and in
step with the app: T-OPS-03..06. promtool checks run when it is installed (scripts/monitoring.py install)."""

import importlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from dotenv import dotenv_values
from prometheus_client import REGISTRY

import app.core.metrics  # noqa: F401 — registers every app metric
from app.core.constants import Dependency, Queue, Worker
from app.worker import ROUTED_QUEUES

REPO = Path(__file__).resolve().parents[1]
OBS = REPO / "observability"
RULES = OBS / "prometheus" / "rules.yml"
DASHBOARD = OBS / "grafana" / "dashboards" / "tsg.json"
TEMPLATE = REPO / "deploy" / "observability.yaml"
FLOWER = REPO / "deploy" / "flower.yaml"
MIRROR = "quay-quay-registry.apps.dda-desc-az1-01.desccii.local/dda-desc"
APP_IMAGE = f"{MIRROR}/tsg-api:v2-COMMIT"  # deploy-uat.ps1 puts the deployed tag in

#: §22.3 alerts that are Built (AiSlotsSaturated and IntelStale wait for their metrics).
BUILT_ALERTS = {
    "Api5xxHigh",
    "ApiLatencyHigh",
    "JobsFailing",
    "ReaperNotRunning",
    "QueueBacklog",
    "NoWorker",
    "MongoDown",
    "SqlDown",
    "RedisDown",
    "AiErrorRateHigh",
    "AuditWriteFailing",
    "TargetDown",
    "PodRestarting",
    "PodOOMKilled",
    # Added by the 2026-10-08 review: a component with no running pod, or an exporter blind to Redis.
    "QueueDepthUnknown",
    "ApiNotRunning",
    "WorkerNotRunning",
    "PodNotStarting",
    # Added by the second 2026-10-08 review: library edits silently not picked up.
    "LibraryCheckFailing",
    # 2026-10-10: the reaper (beat) stopped; every AI slot busy (Step 6).
    "AiSlotsSaturated",
    # 2026-10-23: the AI not answering, by reason; the API hitting a bug.
    "AiNotAnswering",
    "ApiCrashing",
}
#: Metrics that come from the exporters, not the app.
EXPORTER_METRICS = {
    "redis_key_size",
    "redis_up",
    "flower_task_runtime_seconds_bucket",
    "flower_events_total",
    "flower_worker_number_of_currently_executing_tasks",
    "kube_pod_container_status_restarts_total",
    "kube_pod_container_status_last_terminated_reason",
    "kube_pod_container_status_waiting_reason",
    "kube_pod_status_phase",
}
PUBLIC_PATHS = {"/grafana", "/flower", "/prometheus", "/alertmanager", "/loki"}


def _monitoring_script():
    """scripts/monitoring.py, loaded as the laptop runs it (scripts/ on the path, for monitoring_install)."""
    sys.path.insert(0, str(REPO / "scripts"))
    try:
        return importlib.import_module("monitoring")
    finally:
        sys.path.remove(str(REPO / "scripts"))


def _uat_objects() -> list[dict]:
    """Every object of the UAT monitoring files: deploy/observability.yaml and Flower's deploy/flower.yaml."""
    return [
        o for path in (TEMPLATE, FLOWER) for o in yaml.safe_load_all(path.read_text(encoding="utf-8")) if o
    ]


def _template_objects(kind: str) -> list[dict]:
    return [o for o in _uat_objects() if o["kind"] == kind]


def _app_metric_names() -> set[str]:
    names = set()
    for family in REGISTRY.collect():
        suffixes = {"counter": ["_total"], "histogram": ["_bucket", "_sum", "_count"]}.get(family.type, [""])
        names |= {family.name + suffix for suffix in suffixes}
    return names


def _rules() -> list[dict]:
    return [
        rule
        for group in yaml.safe_load(RULES.read_text(encoding="utf-8"))["groups"]
        for rule in group["rules"]
    ]


def _panels() -> list[dict]:
    """Every dashboard panel, those inside a folded row too."""
    top = json.loads(DASHBOARD.read_text(encoding="utf-8"))["panels"]
    return top + [child for panel in top for child in panel.get("panels", [])]


def _prometheus_queries() -> list[str]:
    from_dashboard = [
        target["expr"]
        for panel in _panels()
        if panel.get("datasource", {}).get("uid") == "prometheus"
        for target in panel["targets"]
    ]
    return [rule["expr"] for rule in _rules()] + from_dashboard


def test_every_config_file_parses() -> None:
    for path in [*OBS.rglob("*.yml"), *OBS.rglob("*.yaml")]:
        assert yaml.safe_load(path.read_text(encoding="utf-8")), path
    assert _uat_objects()
    json.loads(DASHBOARD.read_text(encoding="utf-8"))


def test_every_metric_in_alerts_and_dashboard_exists() -> None:
    """Catches a renamed metric (v1 alerted on tsg_http_request_duration_seconds, which no longer existed)."""
    known = _app_metric_names() | EXPORTER_METRICS
    used = {
        name
        for query in _prometheus_queries()
        # Quoted label values left out: task="tsg_reap" names a task, not a metric.
        for name in re.findall(r"\b(?:tsg|redis|flower|kube)_[a-z_]+\b", re.sub(r'"[^"]*"', '""', query))
    }
    assert used - known == set()
    named_stores = {
        name
        for query in _prometheus_queries()
        for name in re.findall(r'tsg_dependency_up\{name="(\w+)"', query)
    }
    assert named_stores <= {d.value for d in Dependency}


def test_the_built_alerts_are_all_there_each_with_a_firing_test() -> None:
    rules = _rules()
    assert {rule["alert"] for rule in rules} == BUILT_ALERTS
    assert all(
        rule.get("for")
        and rule["labels"]["severity"]
        and rule["annotations"]["summary"]
        and rule["annotations"]["description"]  # what to do
        for rule in rules
    )
    cases = yaml.safe_load((OBS / "prometheus" / "rules.test.yml").read_text(encoding="utf-8"))["tests"]
    # A case that expects silence (exp_alerts: []) proves nothing about firing: only firing cases count.
    fired = {
        check["alertname"] for case in cases for check in case["alert_rule_test"] if check.get("exp_alerts")
    }
    assert fired == BUILT_ALERTS


def test_queue_depth_reads_the_keys_celery_really_uses() -> None:
    _monitoring_script()
    commands = sys.modules["monitoring_commands"]
    assert set(commands.QUEUES) == set(ROUTED_QUEUES)
    assert commands.QUEUE_KEY_PREFIX == Worker.BROKER_KEY_PREFIX
    [exporter] = [d for d in _template_objects("Deployment") if d["metadata"]["name"] == "redis-exporter"]
    env = {e["name"]: e.get("value") for e in exporter["spec"]["template"]["spec"]["containers"][0]["env"]}
    for queue in ROUTED_QUEUES:
        assert f"={Worker.BROKER_KEY_PREFIX}{queue}" in env["REDIS_EXPORTER_CHECK_SINGLE_KEYS"]


def test_the_template_is_namespaced_pinned_sized_and_public() -> None:
    """In ai-remediation, as v1's monitoring; only the Role that lets it read the app's pods is in
    ai-threatgen."""
    objects = _uat_objects()
    assert not {o["kind"] for o in objects} & {"ClusterRole", "ClusterRoleBinding"}
    elsewhere = {(o["kind"], o["metadata"]["namespace"]) for o in objects} - {
        (o["kind"], "ai-remediation") for o in objects
    }
    assert elsewhere == {("Role", "ai-threatgen"), ("RoleBinding", "ai-threatgen")}
    for deployment in _template_objects("Deployment"):
        pod = deployment["spec"]["template"]["spec"]
        assert pod["imagePullSecrets"] == [{"name": "quay-pull"}]
        for container in pod.get("initContainers", []) + pod["containers"]:
            image = container["image"]
            assert image == APP_IMAGE or re.fullmatch(rf"{re.escape(MIRROR)}/[\w-]+:v?\d[\w.]*", image), image
            assert container["resources"]["requests"] and container["resources"]["limits"], deployment
            security = container["securityContext"]
            assert security["allowPrivilegeEscalation"] is False and security["runAsNonRoot"] is True
            assert security["capabilities"] == {"drop": ["ALL"]}, container["name"]
    assert {route["spec"]["path"] for route in _template_objects("Route")} == PUBLIC_PATHS


def test_each_scraped_pod_declares_the_port_it_is_scraped_on() -> None:
    """prometheus.yml keeps one target per pod: the declared port equal to the annotated one (keepequal)."""
    for deployment in _template_objects("Deployment"):
        pod = deployment["spec"]["template"]
        annotations = pod["metadata"].get("annotations", {})
        if annotations.get("prometheus.io/scrape") == "true":
            ports = {str(p["containerPort"]) for c in pod["spec"]["containers"] for p in c["ports"]}
            assert annotations["prometheus.io/port"] in ports, deployment["metadata"]["name"]


def test_laptop_and_uat_run_the_same_versions() -> None:
    _monitoring_script()  # loads monitoring_install and monitoring_commands too
    installer = sys.modules["monitoring_install"]
    assert set(installer.DOWNLOADS) <= set(installer.pinned_versions())


def test_laptop_grafana_takes_its_settings_from_env_but_never_the_fixed_ones(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Owner, 2026-10-09: every GF_ line of .env goes to Grafana; the address, port, /grafana path, paths,
    admin password and home dashboard stay the scripts' own (run.ps1's links and the dashboards need them)."""
    _monitoring_script()
    commands = sys.modules["monitoring_commands"]
    lines = "GF_USERS_DEFAULT_THEME=light\nGF_SERVER_HTTP_PORT=9999\nGF_PATHS_DATA=C:/x\nCII_LOG_LEVEL=INFO\n"
    (tmp_path / ".env").write_text(lines, encoding="utf-8")
    monkeypatch.setattr(commands, "REPO", tmp_path)
    monkeypatch.setattr(commands, "ROOT", tmp_path)  # the kept admin password file goes there, not to ~/.tsg
    grafana = commands._grafana_env()
    assert grafana["GF_USERS_DEFAULT_THEME"] == "light"
    assert grafana["GF_SERVER_HTTP_PORT"] == "3000" and grafana["GF_PATHS_DATA"] != "C:/x"
    assert "CII_LOG_LEVEL" not in grafana


def test_uat_grafana_reads_the_env_file_secret_and_the_same_fixed_list() -> None:
    """UAT: the GF_ lines of .env.uat reach Grafana through the Secret observability.ps1 builds; the template
    sets only fixed GF_ settings itself, and the deploy script ignores the same fixed list as the laptop."""
    _monitoring_script()
    fixed = sys.modules["monitoring_commands"].FIXED_GRAFANA_SETTINGS
    [grafana] = [d for d in _template_objects("Deployment") if d["metadata"]["name"] == "grafana"]
    container = grafana["spec"]["template"]["spec"]["containers"][0]
    assert container["envFrom"] == [{"secretRef": {"name": "tsg-grafana-settings"}}]
    assert all(e["name"].startswith(fixed) for e in container["env"] if e["name"].startswith("GF_"))
    script = (REPO / "deploy" / "observability.ps1").read_text(encoding="ascii")
    (listed,) = re.findall(r"\$fixedGrafana = @\(([^)]*)\)", script)
    assert tuple(re.findall(r"'([^']+)'", listed)) == fixed


def test_the_example_documents_grafana_settings_but_none_the_scripts_fix() -> None:
    _monitoring_script()
    fixed = sys.modules["monitoring_commands"].FIXED_GRAFANA_SETTINGS
    grafana = [key for key in dotenv_values(REPO / ".env.example") if key.startswith("GF_")]
    assert grafana and not [key for key in grafana if key.startswith(fixed)]


def test_every_dashboard_panel_uses_a_provisioned_data_source() -> None:
    sources = yaml.safe_load(
        (OBS / "grafana" / "provisioning" / "datasources" / "datasources.yaml").read_text(encoding="utf-8")
    )["datasources"]
    uids = {source["uid"] for source in sources}
    panels = _panels()
    assert len({p["id"] for p in panels}) == len(panels)
    assert {p["datasource"]["uid"] for p in panels if "datasource" in p} <= uids


def test_every_panel_says_what_it_shows_and_the_health_tiles_cover_every_part() -> None:
    """Owner, 2026-10-23: plain enough for anyone. Each panel's description says what it means; the top tiles
    name a live worker for every routed queue and every store, so a missing one cannot go unseen."""
    panels = _panels()
    assert [p["title"] for p in panels if not p.get("description")] == []
    [health] = [p for p in panels if p["title"] == "Parts of the system"]
    queries = " ".join(t["expr"] for t in health["targets"])
    assert all(f'queue="{queue}"' in queries for queue in ROUTED_QUEUES)
    assert all(f'name="{store.value}"' in queries for store in Dependency)


def _promtool() -> str | None:
    found = shutil.which("promtool")
    installed = [*Path.home().glob(".tsg/monitoring-v2/bin/prometheus-*/**/promtool.exe")]
    installed += Path.home().glob(".tsg/*/bin/prometheus-*/**/promtool.exe")  # v1's: same pinned version
    return found or (str(installed[0]) if installed else None)


@pytest.mark.parametrize(
    "args",
    [
        ["check", "config", "prometheus.yml"],
        ["check", "config", "prometheus.local.yml"],
        ["test", "rules", "rules.test.yml"],
    ],
)
def test_promtool_accepts_the_config_and_every_alert_fires(args: list[str]) -> None:
    promtool = _promtool()
    if promtool is None:
        pytest.skip("promtool is not installed (python scripts/monitoring.py install)")
    command = [promtool, *args]
    result = subprocess.run(command, cwd=OBS / "prometheus", capture_output=True, text=True, check=False)  # noqa: S603
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize(("started_at", "killed"), [(222, False), (111, True)])
def test_stop_kills_only_the_very_process_start_launched(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, started_at: int, killed: bool
) -> None:
    """Before: stop killed whatever process now had a recorded id; after a tool ended, Windows may give its id
    to an unrelated program (even another python.exe, like the API), which `taskkill /T /F` then ended."""
    script = _monitoring_script()
    commands: list[list[str]] = []

    def run(command: list[str], **_: object) -> subprocess.CompletedProcess:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(script, "ROOT", tmp_path)
    monkeypatch.setattr(script, "_pids", lambda: {"flower": [4242, 111]})
    monkeypatch.setattr(script, "_created_at", lambda _pid: started_at)
    monkeypatch.setattr(script.subprocess, "run", run)
    script.stop(quiet=True)
    assert (["taskkill", "/PID", "4242", "/T", "/F"] in commands) is killed


def test_a_tool_that_would_not_stop_stays_recorded_and_stop_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Before: a failed taskkill ("Access is denied": started from an administrator window) was ignored,
    pids.json was deleted and stop() returned 0, so the tool kept running unrecorded and the next start blamed
    v1's monitoring for the busy ports."""
    script = _monitoring_script()
    monkeypatch.setattr(script, "ROOT", tmp_path)
    script._save_pids({"grafana": [4242, 111], "loki": [4343, 222]})
    monkeypatch.setattr(script, "_created_at", lambda pid: {4242: 111, 4343: 222}[pid])

    def taskkill(command: list[str], **_: object) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(command, 1 if command[2] == "4242" else 0)

    monkeypatch.setattr(script.subprocess, "run", taskkill)
    assert script.stop(quiet=True) == 1
    assert script._pids() == {"grafana": [4242, 111]}


def test_a_setting_missing_for_a_later_program_starts_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Before: Loki, Prometheus and Alertmanager were already running when redis-exporter's missing setting
    stopped start(); pids.json was never written, so stop() could not find them and the ports stayed busy."""
    script = _monitoring_script()
    launched: list[object] = []

    def missing_setting() -> object:
        raise SystemExit("CII_REDIS_CELERY_BROKER_URL is not set in .env")

    monkeypatch.setattr(script, "ROOT", tmp_path)
    monkeypatch.setattr(script, "COMMANDS", {"first": lambda: (["first.exe"], {}), "second": missing_setting})
    monkeypatch.setattr(script.subprocess, "Popen", lambda *a, **k: launched.append(a))
    with pytest.raises(SystemExit):
        script._launch_all()
    assert launched == []


def test_the_laptop_workers_serve_every_routed_queue_and_maintenance_alone() -> None:
    """run.ps1 names its workers' queues itself: a queue added to the routes but not there gets no worker on
    the laptop, so its jobs wait for ever and /ready answers 503. tsg_maintenance has a worker of its own
    (G198, BLUEPRINT worker-maintenance): sharing threads with long jobs, the reaper waited behind ten stuck
    mappings and a lost job was never re-sent (live test 2026-10-11)."""
    workers = [
        queues.split(",")
        for queues in re.findall(r"'-Q', '([^']+)'", (REPO / "run.ps1").read_text(encoding="ascii"))
    ]
    assert sorted(queue for queues in workers for queue in queues) == sorted(ROUTED_QUEUES)
    assert [Queue.MAINTENANCE] in workers


@pytest.mark.skipif(sys.platform != "win32", reason="reads Windows process start times")
def test_a_process_start_time_tells_a_reused_id_apart() -> None:
    """monitoring.py and run.ps1 stop a process only when its id AND start time match what they started: a
    process started later (Windows reuses ids) reads a later time, and a live process reads one at all."""
    script = _monitoring_script()
    own = script._created_at(os.getpid())
    later = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(5)"])  # noqa: S603
    try:
        started_later = script._created_at(later.pid)
    finally:
        later.kill()
        later.wait()
    assert own and started_later and started_later > own


POWERSHELL_SCRIPTS = [
    "run.ps1",
    "stop.ps1",
    "deploy/observability.ps1",
    "deploy/deploy-uat.ps1",
    "deploy/build-image.ps1",
]
NO_POWERSHELL = pytest.mark.skipif(
    shutil.which("powershell") is None, reason="Windows PowerShell is not installed here"
)


@NO_POWERSHELL
@pytest.mark.parametrize("name", POWERSHELL_SCRIPTS)
def test_the_laptop_scripts_parse_and_are_plain_ascii(name: str) -> None:
    """run.ps1 / stop.ps1 start and stop the laptop stack: a broken edit must fail here, not at the next
    start. ASCII only: Windows PowerShell 5.1 reads a file without a byte-order mark as the ANSI code page."""
    script = REPO / name
    assert script.read_bytes().isascii()
    parse = (
        "$errors = $null; [System.Management.Automation.Language.Parser]::ParseFile("
        f"'{script.as_posix()}', [ref]$null, [ref]$errors) | Out-Null; $errors.Count"
    )
    powershell = [shutil.which("powershell") or "powershell", "-NoProfile", "-Command", parse]
    result = subprocess.run(powershell, capture_output=True, text=True, timeout=60, check=False)  # noqa: S603
    assert result.stdout.strip() == "0", result.stdout + result.stderr


#: Two mistakes PowerShell never reports, found with its own parser: one name in two casings in one scope
#: (names ignore case: one variable where two were meant), and a helper that runs a block it is given using a
#: name found elsewhere in the file (the block reads the helper's variable in place of its caller's).
VARIABLE_RULES = r"""using namespace System.Management.Automation.Language
param([string] $Path)
$tree = [Parser]::ParseFile($Path, [ref]$null, [ref]$null)
function Get-Function($node) {
    for ($up = $node.Parent; $up; $up = $up.Parent) { if ($up -is [FunctionDefinitionAst]) { return $up } }
}
$all = @($tree.FindAll({ $args[0] -is [VariableExpressionAst] }, $true) |
    Where-Object { -not $_.VariablePath.IsDriveQualified } |
    ForEach-Object { [pscustomobject]@{ Name = $_.VariablePath.UserPath -replace '^\w+:', ''
                                        In = Get-Function $_ } })
$all | Group-Object { "$($_.In.Name)|$($_.Name.ToLower())" } | ForEach-Object {
    $spellings = @($_.Group.Name | Sort-Object -Unique -CaseSensitive)
    if ($spellings.Count -gt 1) { "two casings in one scope: $($spellings -join ' and ')" }
}
$helpers = @($tree.FindAll({ $args[0] -is [FunctionDefinitionAst] }, $true) | Where-Object {
    $parameters = @($_.Parameters) + @($_.Body.ParamBlock.Parameters)
    @($parameters | Where-Object { $_.StaticType -eq [scriptblock] }).Count
})
$automatic = @('_', 'args', 'true', 'false', 'null', 'lastexitcode', 'input', 'matches')
foreach ($helper in $helpers) {
    $own = @($all | Where-Object { $_.In -eq $helper } | ForEach-Object { $_.Name.ToLower() } |
        Where-Object { $_ -notmatch 'preference$' -and $automatic -notcontains $_ } | Sort-Object -Unique)
    $elsewhere = @($all | Where-Object { $_.In -ne $helper } | ForEach-Object { $_.Name.ToLower() })
    foreach ($name in $own | Where-Object { $elsewhere -contains $_ }) {
        "$($helper.Name) runs a block, and its `$$name is used elsewhere"
    }
}
"""


def _variable_rule_breaks(script: Path, tmp_path: Path) -> list[str]:
    rules = tmp_path / "variable-rules.ps1"
    rules.write_text(VARIABLE_RULES, encoding="ascii")
    powershell = [shutil.which("powershell") or "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass"]
    run = [*powershell, "-File", str(rules), "-Path", str(script)]
    result = subprocess.run(run, capture_output=True, text=True, timeout=120, check=False)  # noqa: S603
    assert result.returncode == 0 and not result.stderr, result.stderr
    return result.stdout.splitlines()


@NO_POWERSHELL
@pytest.mark.parametrize("name", POWERSHELL_SCRIPTS)
def test_no_script_lets_one_variable_stand_in_for_another(name: str, tmp_path: Path) -> None:
    """Before: deploy-uat.ps1's `$v1 = @()` emptied its list $V1, so v1 was never stopped; and Invoke-Step's
    $Name took the place of the caller's $name in every step's block. Both parsed and passed list tests."""
    assert _variable_rule_breaks(REPO / name, tmp_path) == []


@NO_POWERSHELL
def test_the_variable_rules_find_both_mistakes(tmp_path: Path) -> None:
    sample = tmp_path / "sample.ps1"
    lines = [
        "$V1 = @{ a = 1 }",
        "$v1 = @()",
        "function Invoke-Step([string] $Name, [scriptblock] $Command) { & $Command }",
        "foreach ($name in 'a') { Invoke-Step 'x' { $name } }",
    ]
    sample.write_text("\n".join(lines) + "\n", encoding="ascii")
    assert _variable_rule_breaks(sample, tmp_path) == [
        "two casings in one scope: v1 and V1",
        "Invoke-Step runs a block, and its $name is used elsewhere",
    ]


def test_start_fails_when_a_window_s_program_has_ended() -> None:
    """Before: start judged success by /ready and monitoring only. /ready does not cover beat, which sends the
    reaper (the only repair of lost jobs), so a beat that died at start-up still gave exit code 0."""
    script = (REPO / "run.ps1").read_text(encoding="ascii")
    start = script[script.index("function Invoke-Start") : script.index("function Invoke-Stop")]
    assert "Get-Program" in start and "if ($ended -or" in start


def _run_powershell_function(script: Path, function: str, call: str) -> list[str]:
    """Defines the functions named (comma-separated) exactly as the script has them, runs `call`, and returns
    the output lines."""
    loader = (
        "$errors = $null; $ast = [System.Management.Automation.Language.Parser]::ParseFile("
        f"'{script.as_posix()}', [ref]$null, [ref]$errors); $names = '{function}'.Split(','); "
        "foreach ($fn in $ast.FindAll({ param($n) $n -is "
        "[System.Management.Automation.Language.FunctionDefinitionAst] -and $names -contains $n.Name }, "
        f"$true)) {{ Invoke-Expression $fn.Extent.Text }}; {call}"
    )
    powershell = [shutil.which("powershell") or "powershell", "-NoProfile", "-Command", loader]
    result = subprocess.run(powershell, capture_output=True, text=True, timeout=60, check=False)  # noqa: S603
    assert result.returncode == 0, result.stderr
    return result.stdout.splitlines()


@pytest.mark.skipif(shutil.which("powershell") is None, reason="Windows PowerShell is not installed here")
def test_the_scripts_read_env_values_as_the_app_does(tmp_path: Path) -> None:
    """Before: run.ps1 cut an unquoted value at any '#', so a Redis password holding '#' broke its broker
    check and stop killed the worker without letting it finish its jobs."""
    env = tmp_path / ".env"
    env.write_text(
        "A=p#ss\nB=\"q # x\"\nC=plain # a comment\nD='single'\nE=\nA=last#wins\n", encoding="utf-8"
    )
    keys = "ABCDE"
    expected = [dotenv_values(env)[key] or "" for key in keys]
    calls = "; ".join(f"Get-EnvValue '{key}'" for key in keys)
    assert (
        _run_powershell_function(REPO / "run.ps1", "Get-EnvValue", f"$EnvFile = '{env}'; {calls}") == expected
    )
    read_all = f"$utf8 = [System.Text.UTF8Encoding]::new($false); $v = Read-EnvFile '{env}'; " + "; ".join(
        f"$v['{key}']" for key in keys
    )
    deploy = REPO / "deploy" / "observability.ps1"
    assert _run_powershell_function(deploy, "Read-EnvFile", read_all) == expected


@pytest.mark.skipif(shutil.which("powershell") is None, reason="Windows PowerShell is not installed here")
def test_the_script_runs_on_env_not_on_a_copy_left_in_the_shell(tmp_path: Path) -> None:
    """A setting .env owns that the shell also sets (VS Code's useEnvFile copies .env into a terminal once,
    and the environment beats .env) is unset while the script runs, so every check and program it starts
    reads .env, then put back. Owned: every key .env names, set, blank or commented out (blank means the
    default), and every GF_ key (a GF_ line left out means Grafana's default). Only a value that differs is
    named."""
    env = tmp_path / ".env"
    env.write_text('A=1\n# B=2\nC="x"\nE=\nA=3\nG=same\n', encoding="utf-8")
    shell = "$env:A = 'stale'; $env:B = 'b'; $env:E = 'e'; $env:F = 'f'; $env:G = 'same'; $env:GF_X = 'g'"
    call = (
        f"Get-ChildItem Env:GF_* | Remove-Item; $EnvFile = '{env}'; {shell}; $saved = @{{}}; "
        "$stale = @(Hide-ShadowedSettings $saved); \"stale:$($stale -join ',')\"; "
        "\"hidden:$(($saved.Keys | Sort-Object) -join ',')\"; & cmd /c 'echo child:[%A%,%G%,%F%]'; "
        'Restore-Settings $saved; "back:$env:A,$env:B,$env:E,$env:F,$env:G,$env:GF_X"'
    )
    functions = "Get-ShadowedSettings,Get-EnvValue,Hide-ShadowedSettings,Restore-Settings"
    assert _run_powershell_function(REPO / "run.ps1", functions, call) == [
        "stale:A,B,E,GF_X",  # G is the same copy as .env's: not worth a warning
        "hidden:A,B,E,G,GF_X",  # F is no key of .env's: the shell's own
        "child:[%A%,%G%,f]",  # a program started meanwhile does not inherit the copies
        "back:stale,b,e,f,same,g",
    ]
    script = (REPO / "run.ps1").read_text(encoding="ascii")
    main = script[script.index("$exitCode = 0") :]
    assert main.index("$stale = @(Hide-ShadowedSettings $shadowed)") < main.index("switch ($Action)")
    assert main.index("Restore-Settings $shadowed") > main.index("} finally {")


@pytest.mark.skipif(shutil.which("powershell") is None, reason="Windows PowerShell is not installed here")
def test_a_window_started_as_administrator_is_never_forgotten() -> None:
    """Before: Windows hiding an administrator window's start time read as "gone", so stop deleted its record
    while the window kept running. Now a powershell window that cannot be checked stops the script with the
    reason; any other program that only reused the id is still not ours. G201 (live stop 2026-10-11): a
    window recorded as started WITHOUT administrator rights is always readable, so an unreadable powershell
    with its id is an administrator window that reused it: not ours either (stop no longer ends halfway)."""
    fake = (
        "function Get-Process { param($Id, $ErrorAction) "
        "$p = [pscustomobject]@{ ProcessName = $global:fakeName }; "
        "$p | Add-Member -MemberType ScriptProperty -Name StartTime "
        "-Value { throw 'Access is denied' }; $p }; "
        "foreach ($case in @('svchost', $null), @('powershell', $null), @('powershell', $false)) { "
        "$global:fakeName = $case[0]; "
        "try { $r = Get-Owned ([pscustomobject]@{ pid = 1; started = 'x'; elevated = $case[1] }); "
        "\"returned:$r\" } catch { 'refused' } }"
    )
    assert _run_powershell_function(REPO / "run.ps1", "Get-Owned", fake) == [
        "returned:",
        "refused",
        "returned:",
    ]


@pytest.mark.skipif(shutil.which("powershell") is None, reason="Windows PowerShell is not installed here")
def test_a_uat_file_without_grafana_lines_still_gets_its_grafana_secret() -> None:
    """GF_ lines are optional (owner, 2026-10-09). Grafana reads tsg-grafana-settings, so with none in
    .env.uat the Secret is still applied, empty, and never from an empty env file."""
    call = (
        "function oc { if ($args[0] -eq 'apply') { $input | ForEach-Object { \"applied $_\" } } "
        "else { 'create ' + ($args -join ' ') } }; function Assert-Ok {}; "
        "$utf8 = [System.Text.UTF8Encoding]::new($false); "
        "Set-Secret 'tsg-grafana-settings' ([ordered]@{}); "
        "Set-Secret 'tsg-grafana-settings' ([ordered]@{ GF_A = '1' })"
    )
    empty, with_lines = _run_powershell_function(REPO / "deploy" / "observability.ps1", "Set-Secret", call)
    assert empty == "applied create create secret generic tsg-grafana-settings --dry-run=client -o yaml"
    assert "--from-env-file=" in with_lines


def test_each_laptop_worker_serves_metrics_on_a_port_prometheus_scrapes() -> None:
    """G198: the job worker's port (.env.example's CII_WORKER_METRICS_PORT) and the maintenance worker's (set
    by run.ps1) are exactly the laptop Prometheus' worker targets: a worker on another port is never scraped.
    """
    default = dotenv_values(REPO / ".env.example")["CII_WORKER_METRICS_PORT"]
    started = re.findall(r"CII_WORKER_METRICS_PORT = '(\d+)'", (REPO / "run.ps1").read_text(encoding="ascii"))
    local = yaml.safe_load(
        (REPO / "observability" / "prometheus" / "prometheus.local.yml").read_text(encoding="utf-8")
    )
    (worker,) = [job for job in local["scrape_configs"] if job["job_name"] == "worker"]
    targets = {target for config in worker["static_configs"] for target in config["targets"]}
    assert targets == {f"localhost:{port}" for port in (default, *started)} and len(started) == 2
