"""run.ps1 sizes its workers from .env, and gives tsg_remediation its own worker with a remote reranker."""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from app.worker import ROUTED_QUEUES

REPO = Path(__file__).resolve().parents[1]
RUN_PS1 = (REPO / "run.ps1").read_text(encoding="ascii")
POWERSHELL = shutil.which("powershell") or ""
NO_POWERSHELL = pytest.mark.skipif(not POWERSHELL, reason="Windows PowerShell is not installed here")
#: Loads run.ps1's program table and functions (never its start), then prints each program's command line and
#: the Prometheus targets file start writes, for the .env given.
PROBE = r"""param([string]$Script, [string]$EnvFile, [string]$WorkerTargetsFile)
$ErrorActionPreference = 'Stop'
$tree = [System.Management.Automation.Language.Parser]::ParseFile($Script, [ref]$null, [ref]$null)
$tables = '$Programs', '$ProgramEnv', '$WorkerName', '$RemediationName', '$MapperWorkerName',
          '$MaintenanceName', '$ReaperName'
foreach ($statement in $tree.EndBlock.Statements) {
    $isTable = $statement -is [System.Management.Automation.Language.AssignmentStatementAst] -and
               $tables -contains $statement.Left.Extent.Text
    if ($isTable -or $statement -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
        Invoke-Expression $statement.Extent.Text
    }
}
$commands = [ordered]@{}  # not $programs: names ignore case, and that is run.ps1's $Programs
foreach ($name in Get-ProgramNames) { $commands[$name] = @(Get-Arguments $name) }
Save-WorkerTargets (Get-ProgramNames)
@{ programs = $commands; targets = [IO.File]::ReadAllText($WorkerTargetsFile) } | ConvertTo-Json -Depth 4
"""
CAPS = ["CII_WORKER_THREADS=40", "CII_REMEDIATION_MAX_CONCURRENT_AI_CALLS=4"]
LOCAL = [*CAPS, "CII_RERANK_BASE_URL="]
REMOTE = [*CAPS, "CII_RERANK_BASE_URL=https://rerank.example"]


def _start(tmp_path: Path, env_lines: list[str]) -> tuple[dict[str, list[str]], list[str]]:
    """What start would run for this .env: each program's arguments, and the worker targets for Prometheus."""
    env, probe, targets = tmp_path / ".env", tmp_path / "probe.ps1", tmp_path / "worker-targets.json"
    env.write_text("\n".join(env_lines) + "\n", encoding="utf-8")
    probe.write_text(PROBE, encoding="ascii")
    command = [POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(probe)]
    command += ["-Script", str(REPO / "run.ps1"), "-EnvFile", str(env), "-WorkerTargetsFile", str(targets)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)  # noqa: S603
    assert result.returncode == 0 and not result.stderr, result.stderr
    found = json.loads(result.stdout)
    return found["programs"], [
        target for group in json.loads(found["targets"]) for target in group["targets"]
    ]


def _option(arguments: list[str], flag: str) -> str:
    """The value after `flag` in a command line."""
    return arguments[arguments.index(flag) + 1]


@NO_POWERSHELL
def test_a_remote_reranker_gives_remediation_a_worker_sized_by_its_ai_cap(tmp_path: Path) -> None:
    """Plans waiting for AI slots hold their own scraped worker's threads (cap + 2), not the Starts'."""
    programs, targets = _start(tmp_path, REMOTE)
    assert list(programs) == [
        "api",
        "worker",
        "remediation",
        "service_mapper",
        "maintenance",
        "reaper",
        "beat",
    ]
    remediation = programs["remediation"]
    assert (_option(remediation, "-Q"), _option(remediation, "-c")) == ("tsg_remediation", "6")
    assert _option(remediation, "-n").startswith("remediation@")  # logs/worker-remediation.log
    assert _option(programs["worker"], "-Q") == "tsg_threats,tsg_scenarios,tsg_controls"
    assert targets == ["localhost:9105"]


@NO_POWERSHELL
def test_a_local_reranker_keeps_remediation_on_the_job_worker(tmp_path: Path) -> None:
    """The laptop's local model stays in one process; Prometheus is given no remediation worker to miss."""
    programs, targets = _start(tmp_path, LOCAL)
    assert "remediation" not in programs and targets == []
    worker = programs["worker"]
    assert (_option(worker, "-Q"), _option(worker, "-c")) == (
        "tsg_threats,tsg_scenarios,tsg_controls,tsg_remediation",
        "40",
    )


@NO_POWERSHELL
@pytest.mark.parametrize("env_lines", [LOCAL, REMOTE], ids=["local reranker", "remote reranker"])
def test_every_routed_queue_has_exactly_one_worker(tmp_path: Path, env_lines: list[str]) -> None:
    """In either layout each routed queue is served once: none waits for ever, none twice."""
    programs, _ = _start(tmp_path, env_lines)
    queues = [
        queue
        for arguments in programs.values()
        if "-Q" in arguments
        for queue in _option(arguments, "-Q").split(",")
    ]
    assert sorted(queues) == sorted(ROUTED_QUEUES)


@NO_POWERSHELL
@pytest.mark.parametrize(
    ("cap", "threads"),
    [
        (["CII_SERVICE_MAPPER_MAX_CONCURRENT_AI_CALLS=5"], "5"),
        (["CII_SERVICE_MAPPER_MAX_CONCURRENT_AI_CALLS=0"], "2"),
        ([], "2"),
    ],
)
def test_the_mapper_s_threads_follow_its_ai_cap(tmp_path: Path, cap: list[str], threads: str) -> None:
    """One mapping is one AI call, so its threads are its cap; no limit (0) or none set keeps 2."""
    programs, _ = _start(tmp_path, [*LOCAL, *cap])
    assert _option(programs["service_mapper"], "-c") == threads


def test_stop_asks_every_worker_to_finish_and_start_checks_every_metrics_port() -> None:
    """A worker missing from stop's list is killed mid-job; a port missing from start's check fails it."""
    stop = RUN_PS1[RUN_PS1.index("function Invoke-Stop") : RUN_PS1.index("function Show-Status")]
    programs = re.findall(
        r"^    (\w+) += @\('-m', 'celery', '-A', 'app.worker', 'worker',.*?'-n', (\$\w+)",
        RUN_PS1,
        re.M | re.S,
    )
    assert len(programs) == 5 and all(f"'{name}'" in stop and variable in stop for name, variable in programs)
    checked = re.search(r"foreach \(\$port in ([\d, ]+)\)", RUN_PS1)
    ports = re.findall(r"CII_WORKER_METRICS_PORT = '(\d+)'", RUN_PS1)
    assert checked and set(ports) <= set(checked.group(1).replace(" ", "").split(",")), ports
