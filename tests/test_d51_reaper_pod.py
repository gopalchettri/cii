"""The reaper and the controls sweep have a queue and a worker of their own: no long job takes a thread."""

import re
from itertools import takewhile
from pathlib import Path

import pytest

from app.core.constants import TASK_ROUTES, TaskName
from app.worker.celery_app import queue_of
from tests.test_deploy import APP_FILES, COMMON_FILE, MONITORING_NAMESPACE, _objects, _pod_limits
from tests.test_deploy_monitoring_images import GUIDE

REPO = Path(__file__).resolve().parents[1]


def test_the_reaper_and_the_sweep_share_their_queue_with_no_long_job() -> None:
    """A library build or an intelligence refresh holds a thread for up to an hour: on the reaper's queue,
    with every thread busy, REAP passes waited past their expiry and were dropped."""
    reaper_queue = queue_of(TaskName.REAP)
    sharing = {task for task, route in TASK_ROUTES.items() if route["queue"] == reaper_queue}
    assert sharing == {TaskName.REAP, TaskName.RETRY_CONTROLS}


def test_the_laptop_serves_the_reapers_queue_with_a_worker_of_its_own() -> None:
    """run.ps1 starts one worker per -Q list: the reaper's queue is a list on its own."""
    workers = re.findall(r"'-Q', '([^']+)'", (REPO / "run.ps1").read_text(encoding="ascii"))
    assert queue_of(TaskName.REAP) in workers


def _deployments(path: Path, namespace: str, part_of: str = "") -> list[dict]:
    """The file's Deployments in `namespace`, only those labelled part-of=`part_of` when it is given."""
    return [
        d
        for d in _objects(path, kind="Deployment")
        if d["metadata"]["namespace"] == namespace and part_of in ("", d["metadata"]["labels"].get("part-of"))
    ]


def _limits(deployments: list[dict]) -> tuple[float, float]:
    """The CPU and memory (Gi) limits of every replica of the Deployments together."""
    pods = [(d["spec"].get("replicas", 1), *_pod_limits(d)) for d in deployments]
    return sum(n * cpu for n, cpu, _ in pods), sum(n * memory for n, _, memory in pods)


def _header(path: Path) -> str:
    """The file's opening comment block as one line of text."""
    lines = takewhile(lambda line: line.startswith("#"), path.read_text(encoding="utf-8").splitlines())
    return " ".join(line.lstrip("#").strip() for line in lines)


def test_the_every_release_roll_out_counts_one_line_per_deployment_it_waits_for() -> None:
    """Part 4 step 7 waits for ai-remediation's, then ai-threatgen's part-of=tsg Deployments, then ai-common's
    monitoring and the proxy: the counts it tells the operator to expect are those."""
    guide = GUIDE.read_text(encoding="utf-8")
    part_4 = guide[guide.index("## Part 4.") : guide.index("## Part 5.")]
    [stated] = re.findall(r"line per Deployment: (\d+), then (\d+),\s+then (\d+)", part_4)
    monitoring = _deployments(COMMON_FILE, MONITORING_NAMESPACE, "tsg-monitoring")
    apps = [len(_deployments(APP_FILES[name], name, "tsg")) for name in ("ai-remediation", "ai-threatgen")]
    assert [int(count) for count in stated] == [*apps, len(monitoring) + 1]  # + the proxy's own rollout


def test_each_app_file_s_header_names_the_queue_of_every_worker_it_runs() -> None:
    """The header's queue list is the file's worker Deployments, and `all N roll at once` counts them all."""
    for project, path in APP_FILES.items():
        header, deployments = _header(path), _deployments(path, project)
        [queues] = re.findall(r"\((threats, [^)]+)\)", header)
        workers = {d["metadata"]["name"] for d in deployments if d["metadata"]["name"].startswith("worker-")}
        assert {f"worker-{queue.replace(' ', '-')}" for queue in queues.split(", ")} == workers, path.name
        assert [int(n) for n in re.findall(r"all (\d+) roll at once", header)] in ([], [len(deployments)])


def test_each_app_file_s_header_adds_up_its_own_limits() -> None:
    """ai-remediation's header: its pods' limits. ai-threatgen's: its pods', with the monitoring proxy, then
    with the API's update pod too."""
    for project, path in APP_FILES.items():
        deployments = _deployments(path, project)
        expected = [_limits(deployments)]
        if project == "ai-threatgen":
            cpu, gib = _limits([*deployments, *_deployments(COMMON_FILE, project)])
            api_cpu, api_gib = _pod_limits(next(d for d in deployments if d["metadata"]["name"] == "api"))
            expected += [(cpu, gib), (cpu + api_cpu, gib + api_gib)]
        [sentence] = re.findall(r"These pods use (.+?\.) [A-Z]", _header(path))
        stated = re.findall(r"([\d.]+) CPU(?:,| and) ([\d.]+) Gi", sentence)
        for (cpu, gib), total in zip(stated, expected, strict=True):
            assert (float(cpu), float(gib)) == pytest.approx(total, abs=0.006), path.name
