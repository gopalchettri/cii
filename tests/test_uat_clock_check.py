"""The UAT clock check (scripts/uat_clock_check.py): the offset maths, the OFF verdict, MongoDB/Redis read
through a pod, the nodes it names, and the in-pod snippet run for real against the local stores."""

import contextlib
import importlib
import io
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
try:
    check = importlib.import_module("uat_clock_check")
finally:
    sys.path.remove(str(REPO / "scripts"))


def _pod(name: str, node: str, here: tuple[float, float], mongo: tuple[float, float] | None = None):  # type: ignore[no-untyped-def]
    pod = check.Pod(name, "ai-threatgen", node, "api", check.Offset(*here))
    if mongo:
        pod.store_minus_pod["mongo"] = check.Offset(*mongo)
    return pod


def test_the_offset_is_measured_from_the_middle_of_the_round_trip() -> None:
    offset = check.offset_from_timing(924.0, sent=999.0, received=1001.0)
    assert (offset.seconds, offset.error) == (-76.0, 1.0)


def test_a_clock_is_off_only_when_it_is_surely_past_the_limit() -> None:
    assert not check.Offset(3.0, 1.0).is_off(2.0)  # could be just 2 s off
    assert check.Offset(3.01, 1.0).is_off(2.0)
    assert check.Offset(-3.5, 1.0).is_off(2.0)


def test_only_running_pods_are_listed_with_their_node_and_first_container() -> None:
    listing = {
        "items": [
            {
                "metadata": {"name": "api-1"},
                "spec": {"nodeName": "w1", "containers": [{"name": "api"}]},
                "status": {"phase": "Running"},
            },
            {
                "metadata": {"name": "old"},
                "spec": {"nodeName": "w2", "containers": [{"name": "api"}]},
                "status": {"phase": "Succeeded"},
            },
        ]
    }
    [pod] = check.pods_from_listing(listing, "ai-threatgen")
    assert (pod.name, pod.node, pod.container) == ("api-1", "w1", "api")


def test_a_store_is_read_through_the_pod_with_the_shortest_round_trip() -> None:
    slow = _pod("api-1", "w1", here=(1.0, 0.8), mongo=(0.5, 0.01))
    fast = _pod("worker-1", "w3", here=(-76.0, 0.3), mongo=(76.4, 0.01))
    offset, via = check.store_minus_here([slow, fast], "mongo")
    assert via is fast and round(offset.seconds, 2) == 0.4 and round(offset.error, 2) == 0.31
    assert check.store_minus_here([slow, fast], "redis") is None


def test_the_nodes_of_off_pods_are_named_and_the_check_fails() -> None:
    pods = [_pod("api-1", "w1", here=(0.2, 0.5)), _pod("worker-1", "w3", here=(-76.0, 0.5))]
    assert list(check.nodes_to_fix(pods, 2.0)) == ["w3"]
    assert any("oc debug node/w3" in line for line in check.report(pods, 2.0))
    assert check.anything_off(pods, 2.0) and not check.anything_off(pods[:1], 2.0)


def test_every_pod_off_points_at_this_computers_clock() -> None:
    pods = [_pod("api-1", "w1", here=(30.0, 0.5)), _pod("worker-1", "w2", here=(30.2, 0.5))]
    assert any("check this computer's clock" in line for line in check.report(pods, 2.0))


def test_a_store_the_pod_cannot_read_becomes_a_note_and_a_pod_without_python_is_skipped(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    answer = json.dumps({"mongo": [0.1, 0.002], "redis": "ConnectionError('refused')"})
    monkeypatch.setattr(check, "oc", lambda *_: subprocess.CompletedProcess([], 0, answer, ""))
    pod = _pod("api-1", "w1", here=(0.0, 0.5))
    check.measure_stores(pod)
    assert pod.store_minus_pod == {"mongo": check.Offset(0.1, 0.002)} and "Redis not read" in pod.notes[0]
    monkeypatch.setattr(check, "oc", lambda *_: subprocess.CompletedProcess([], 127, "", "python: not found"))
    monitoring = _pod("prometheus-1", "w2", here=(0.0, 0.5))
    check.measure_stores(monitoring)
    assert monitoring.store_minus_pod == {} and monitoring.notes == []


def test_the_in_pod_snippet_reads_both_stores_with_the_apps_clients() -> None:
    printed = io.StringIO()
    with contextlib.redirect_stdout(printed):
        exec(check.STORE_SNIPPET, {})  # noqa: S102 — our own snippet, as the pod runs it
    measured = json.loads(printed.getvalue())
    for store in ("mongo", "redis"):
        seconds, error = measured[store]
        assert abs(seconds) < 2 and 0 <= error < 1  # same machine: the clocks agree
