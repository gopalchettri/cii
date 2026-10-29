"""The UAT clock check (scripts/uat_clock_check.py): differences in plain words, the WRONG verdict,
MongoDB and Redis read through a pod, the owner's real UAT run, and the in-pod snippet on local stores."""

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

PWK02, PWK03, PWK06 = (f"aos1descpwk0{n}.dda-desc-az1-01.desccii.local" for n in (2, 3, 6))


def _pod(name, node, here=None, mongo=None, redis=None, namespace="ai-threatgen", unread=""):  # type: ignore[no-untyped-def]
    pod = check.Pod(name, namespace, node, "main", check.Offset(*here) if here else None, unread=unread)
    for store, offset in (("mongo", mongo), ("redis", redis)):
        if offset is not None:
            pod.store_minus_pod[store] = check.Offset(offset, 0.001)
    return pod


def _uat_run():  # type: ignore[no-untyped-def]
    """Part of the owner's UAT run of 2026-10-29: MongoDB 10.6 s ahead, nodes pwk02 and pwk03 ahead."""
    return [
        _pod("api-79794b5968-6qv5n", PWK06, (-0.01, 0.90), mongo=10.66, redis=-0.22),
        _pod("api-79794b5968-h8jbk", PWK02, (78.00, 0.92), mongo=-67.35, redis=-78.22),
        _pod("beat-6fc5cc8585-99qc4", PWK03, (44.76, 0.89), mongo=-34.13, redis=-45.01),
        _pod("worker-reaper-7d4874bb8-h7fbx", PWK03, (44.75, 0.88), -34.13, -45.01, namespace="ai-common"),
        _pod("loki-64bd6885d5-fj96v", PWK03, (44.76, 0.89), namespace="ai-common"),
        _pod(
            "kube-state-metrics-77fc96bf7d-2f2zh",
            PWK03,
            namespace="ai-common",
            unread="its container is not running",
        ),
    ]


def _line(lines: list[str], start: str) -> str:
    return next(line for line in lines if line.strip().startswith(start))


def test_a_difference_reads_in_seconds_minutes_hours_or_days() -> None:
    assert check.how_far(0.01) == "in step"
    assert check.how_far(-0.26) == "0.3 s behind"
    assert check.how_far(10.62) == "11 s ahead"
    assert check.how_far(78.0) == "1 min 18 s ahead"
    assert check.how_far(-19800.0) == "5 h 30 min behind"
    assert check.how_far(2 * 86400 + 3 * 3600) == "2 d 3 h ahead"


def test_the_offset_is_measured_from_the_middle_of_the_round_trip() -> None:
    offset = check.offset_from_timing(924.0, sent=999.0, received=1001.0)
    assert (offset.seconds, offset.error) == (-76.0, 1.0)


def test_a_clock_is_wrong_only_when_it_is_surely_past_the_limit() -> None:
    assert not check.Offset(3.0, 1.0).is_off(2.0)  # could be just 2 s off
    assert check.Offset(3.01, 1.0).is_off(2.0)
    assert check.Offset(-3.5, 1.0).is_off(2.0)


def test_every_project_the_login_sees_is_listed() -> None:
    listing = "project.project.openshift.io/ai-threatgen\nproject.project.openshift.io/ai-common\n"
    assert check.project_names(listing) == ["ai-threatgen", "ai-common"]


def test_only_running_pods_are_listed_with_their_node_and_first_container() -> None:
    def item(name: str, phase: str) -> dict:
        return {
            "metadata": {"name": name},
            "spec": {"nodeName": "w1", "containers": [{"name": "api"}]},
            "status": {"phase": phase},
        }

    [pod] = check.pods_from_listing(
        {"items": [item("api-1", "Running"), item("old", "Succeeded")]}, "ai-threatgen"
    )
    assert (pod.name, pod.node, pod.container) == ("api-1", "w1", "api")


def test_a_store_is_read_through_the_pod_with_the_shortest_round_trip() -> None:
    mongo = check.store_minus_here(_uat_run(), "mongo")
    assert round(mongo.seconds, 2) == 10.62  # through worker-reaper: -34.13 + 44.75
    assert check.store_minus_here([_pod("loki", PWK03, (0.0, 0.5))], "mongo") is None


def test_the_report_of_the_uat_run_names_the_three_wrong_clocks_in_plain_words() -> None:
    lines = check.report(_uat_run(), 2.0)
    text = "\n".join(lines)
    assert "11 s ahead" in _line(lines, "MongoDB server") and "WRONG" in _line(lines, "MongoDB server")
    assert "0.3 s behind" in _line(lines, "Redis server") and "RIGHT" in _line(lines, "Redis server")
    assert "ai-threatgen: pods: 3, WRONG: 2" in text and "ai-common: pods: 3, WRONG: 2, not read: 1" in text
    row = _line(lines, "api-79794b5968-h8jbk")
    assert "1 min 18 s ahead" in row and "WRONG" in row and row.endswith("node aos1descpwk02")
    assert text.index("api-79794b5968-h8jbk") < text.index("api-79794b5968-6qv5n")  # wrong ones first
    assert "not read: its container is not running" in _line(lines, "kube-state-metrics")
    assert text.count("oc debug node/") == 2 and f"oc debug node/{PWK02} --" in text and PWK03 in text
    assert "Node aos1descpwk03 is 45 s ahead (our pods on it: 3)" in text
    assert "Saved times are 11 s ahead of real time." in text and "fires for 4 of 4 app pods" in text
    assert check.anything_off(_uat_run(), 2.0)


def test_right_clocks_leave_nothing_to_fix() -> None:
    pods = [_pod("api-1", PWK06, (0.1, 0.9), mongo=0.2, redis=-0.1)]
    assert "Nothing to fix: every clock read is right." in check.report(pods, 2.0)
    assert not check.anything_off(pods, 2.0)


def test_every_pod_wrong_points_at_this_computers_clock() -> None:
    pods = [_pod("api-1", PWK02, (30.0, 0.5)), _pod("worker-1", PWK06, (30.2, 0.5))]
    assert "check this computer's clock first" in "\n".join(check.report(pods, 2.0))


def test_an_oc_error_is_said_in_plain_words() -> None:
    error = 'error: unable to upgrade connection: container not found ("kube-state-metrics")'
    assert check.plain_reason(error) == "its container is not running"
    assert check.plain_reason("something new") == "something new"


def test_a_store_the_pod_cannot_read_becomes_a_note_and_a_pod_without_python_is_skipped(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    answer = json.dumps({"mongo": [0.1, 0.002], "redis": "ConnectionError('refused')"})
    monkeypatch.setattr(check, "oc", lambda *_: subprocess.CompletedProcess([], 0, answer, ""))
    pod = _pod("api-1", PWK06, (0.0, 0.5))
    check.measure_stores(pod)
    assert pod.store_minus_pod == {"mongo": check.Offset(0.1, 0.002)} and "Redis not read" in pod.notes[0]
    monkeypatch.setattr(check, "oc", lambda *_: subprocess.CompletedProcess([], 127, "", "python: not found"))
    monitoring = _pod("prometheus-1", PWK06, (0.0, 0.5))
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
