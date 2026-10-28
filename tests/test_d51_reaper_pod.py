"""The reaper's worker on the laptop, the guide's roll-out of worker-reaper before the API, and the app file's
header, which names every worker and adds up its limits (the pod itself: tests/test_reaper_pod.py)."""

import re
from itertools import takewhile
from pathlib import Path

import pytest

from app.core.constants import TaskName
from app.worker.celery_app import queue_of
from tests.test_deploy import APP_FILES, COMMON_FILE, MONITORING_NAMESPACE, _objects, _pod_limits
from tests.test_deploy_monitoring_images import GUIDE

REPO = Path(__file__).resolve().parents[1]
APP_PROJECT = "ai-threatgen"


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


def test_the_every_release_roll_out_starts_the_reaper_first_and_counts_each_deployment() -> None:
    """Part 4 step 7 rolls out worker-reaper (ai-common) before deploy_threatgen.yaml, so a reaper worker
    serves tsg_reaper before the new API and beat send to it; then ai-threatgen's part-of=tsg Deployments,
    then ai-common's monitoring and the proxy: the counts it tells the operator to expect are those."""
    guide = GUIDE.read_text(encoding="utf-8")
    part_4 = guide[guide.index("## Part 4.") : guide.index("## Part 5.")]
    reaper_ready = part_4.index(f"oc -n {MONITORING_NAMESPACE} rollout status deployment/worker-reaper")
    assert part_4.index("oc apply -f deploy\\deploy_common.yaml -l part-of=tsg") < reaper_ready
    assert reaper_ready < part_4.index("oc apply -f deploy\\deploy_threatgen.yaml")
    [stated] = re.findall(r"line per Deployment: ((?:\d+,?\s+then\s+)+\d+)", part_4)
    reaper = len(_deployments(COMMON_FILE, MONITORING_NAMESPACE, "tsg"))
    app = len(_deployments(APP_FILES[APP_PROJECT], APP_PROJECT, "tsg"))
    monitoring = len(_deployments(COMMON_FILE, MONITORING_NAMESPACE, "tsg-monitoring")) + 1  # + the proxy
    assert [int(n) for n in re.findall(r"\d+", stated)] in ([app, monitoring], [reaper, app, monitoring])


def test_the_app_file_s_header_names_the_queue_of_every_worker_it_runs() -> None:
    """The header's queue list is the file's worker Deployments, and `all N roll at once` counts them all."""
    path = APP_FILES[APP_PROJECT]
    header, deployments = _header(path), _deployments(path, APP_PROJECT)
    [queues] = re.findall(r"\((threats, [^)]+)\)", header)
    workers = {d["metadata"]["name"] for d in deployments if d["metadata"]["name"].startswith("worker-")}
    assert {f"worker-{queue.replace(' ', '-')}" for queue in queues.split(", ")} == workers
    assert [int(n) for n in re.findall(r"all (\d+) roll at once", header)] in ([], [len(deployments)])


def test_the_app_file_s_header_adds_up_its_own_limits() -> None:
    """ai-threatgen's header: its pods' limits, with the monitoring proxy, then with the API's update pod."""
    path = APP_FILES[APP_PROJECT]
    deployments = _deployments(path, APP_PROJECT)
    cpu, gib = _limits([*deployments, *_deployments(COMMON_FILE, APP_PROJECT)])
    api_cpu, api_gib = _pod_limits(next(d for d in deployments if d["metadata"]["name"] == "api"))
    expected = [_limits(deployments), (cpu, gib), (cpu + api_cpu, gib + api_gib)]
    [sentence] = re.findall(r"These pods use (.+?\.) [A-Z]", _header(path))
    stated = re.findall(r"([\d.]+) CPU(?:,| and) ([\d.]+) Gi", sentence)
    for (cpu_stated, gib_stated), total in zip(stated, expected, strict=True):
        assert (float(cpu_stated), float(gib_stated)) == pytest.approx(total, abs=0.006)
