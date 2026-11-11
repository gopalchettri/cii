"""The UAT clock check (scripts/uat_clock_check.py): a plain log for the support team, one line per clock with
the time it shows and its gap from UTC, a summary of each gap and who fixes it, MongoDB and Redis read only in
TSG pods, our projects only, never a silent pass, and the owner's real UAT run."""

import contextlib
import importlib
import io
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
try:
    check = importlib.import_module("uat_clock_check")
finally:
    sys.path.remove(str(REPO / "scripts"))

PWK02, PWK03, PWK06 = (f"aos1descpwk0{n}.dda-desc-az1-01.desccii.local" for n in (2, 3, 6))
STANDARD = datetime(2026, 10, 30, 9, 15, 2, 400000, tzinfo=UTC).timestamp()
MONGO_ADDRESS, REDIS_ADDRESS = "10.228.146.3:27018", "10.228.146.4:6379"


def _pod(name, node, here=None, mongo=None, redis=None, namespace="ai-threatgen", unread=""):  # type: ignore[no-untyped-def]
    offset = check.Offset(*here) if here else None
    pod = check.Pod(name, namespace, node, "main", runs_app=True, pod_minus_here=offset, unread=unread)
    for store, seconds, address in (("mongo", mongo, MONGO_ADDRESS), ("redis", redis, REDIS_ADDRESS)):
        if seconds is not None:
            pod.store_minus_pod[store] = check.Offset(seconds, 0.001)
            pod.store_address[store] = address
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


def _fake_oc(monkeypatch, *answers: tuple[str, str]) -> list[list[str]]:  # type: ignore[no-untyped-def]
    """oc answers (stdout, stderr) in turn, failing when stderr is set; returns the commands it was given."""
    calls: list[list[str]] = []
    queue = list(answers)

    def fake(args: list[str], stdin: str | None = None) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        stdout, stderr = queue.pop(0)
        return subprocess.CompletedProcess(args, 1 if stderr else 0, stdout, stderr)

    monkeypatch.setattr(check, "oc", fake)
    return calls


def test_a_gap_reads_in_seconds_minutes_hours_or_days_from_utc() -> None:
    assert check.from_utc(0.01) == "in step with UTC"
    assert check.from_utc(-0.26) == "0.3 s behind UTC"
    assert check.from_utc(10.62) == "11 s ahead of UTC"
    assert check.from_utc(78.0) == "1 min 18 s ahead of UTC"
    assert check.from_utc(-19800.0) == "5 h 30 min behind UTC"
    assert check.from_utc(2 * 86400 + 3 * 3600) == "2 d 3 h ahead of UTC"


def test_a_clock_time_reads_in_utc_with_the_date_only_when_it_differs() -> None:
    assert check.utc_text(STANDARD) == "2026-10-30 09:15:02 UTC"
    assert check.clock_time(STANDARD + 10.62, STANDARD) == "09:15:13 UTC"
    assert check.clock_time(STANDARD + 15 * 3600, STANDARD) == "2026-10-31 00:15:02 UTC"


def test_the_offset_is_measured_from_the_middle_of_the_round_trip() -> None:
    offset = check.offset_from_timing(924.0, sent=999.0, received=1001.0)
    assert (offset.seconds, offset.error) == (-76.0, 1.0)


def test_a_clock_has_a_gap_only_when_it_is_surely_past_the_limit() -> None:
    assert not check.Offset(3.0, 1.0).is_off(2.0)  # could be just 2 s off
    assert check.Offset(3.01, 1.0).is_off(2.0)
    assert check.Offset(-3.5, 1.0).is_off(2.0)


def test_every_project_of_ours_is_listed_and_openshifts_own_are_skipped() -> None:
    names = ["ai-threatgen", "ai-common", "openshift", "openshift-monitoring", "kube-system", "kubeflow"]
    listing = "".join(f"project.project.openshift.io/{name}\n" for name in names)
    assert check.our_projects(listing) == ["ai-threatgen", "ai-common", "kubeflow"]


def test_the_tsg_image_is_known_by_its_name_whatever_the_registry_or_tag() -> None:
    registry = "quay-quay-registry.apps.dda-desc-az1-01.desccii.local/dda-desc"
    assert check.is_app_image(f"{registry}/tsg-api:31-Oct-2026")
    assert check.is_app_image(f"{registry}/tsg-api@sha256:0a1b2c") and check.is_app_image("tsg-api")
    assert not check.is_app_image(f"{registry}/prometheus:v3.15.0")
    assert not check.is_app_image(f"{registry}/tsg-api-proxy:1") and not check.is_app_image("")


def test_only_running_pods_are_listed_with_their_node_first_container_and_image() -> None:
    def item(name: str, phase: str, image: str) -> dict:
        spec = {"nodeName": "w1", "containers": [{"name": "main", "image": f"registry/dda-desc/{image}"}]}
        return {"metadata": {"name": name}, "spec": spec, "status": {"phase": phase}}

    items = [
        item("api-1", "Running", "tsg-api:1"),
        item("loki-1", "Running", "loki:3"),
        item("old", "Done", "x"),
    ]
    api, loki = check.pods_from_listing({"items": items}, "ai-threatgen")
    assert (api.name, api.node, api.container, api.runs_app) == ("api-1", "w1", "main", True)
    assert (loki.name, loki.runs_app) == ("loki-1", False)


def test_mongodb_and_redis_are_read_only_in_tsg_pods_with_the_server_that_answered(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    stores = json.dumps({"mongo": [0.1, 0.002, MONGO_ADDRESS], "redis": [0.0, 0.001]})
    calls = _fake_oc(monkeypatch, ("1761800000.5\n", ""), (stores, ""), ("1761800000.5\n", ""))
    app = check.Pod("api-1", "ai-threatgen", PWK06, "api", runs_app=True)
    check.measure(app)
    assert [call[-1] for call in calls] == ["+%s.%N", "-"] and set(app.store_minus_pod) == {"mongo", "redis"}
    assert app.store_address == {"mongo": MONGO_ADDRESS}  # Redis named no address: still read
    monitoring = check.Pod("loki-1", "ai-common", PWK06, "loki")
    check.measure(monitoring)
    assert len(calls) == 3 and monitoring.pod_minus_here and monitoring.store_minus_pod == {}


def test_a_clock_not_read_always_says_why(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    _fake_oc(monkeypatch, ("1761800000.%N\n", ""), ("", ""), ("", 'Error from server (Forbidden): pods "x"'))
    odd, silent, refused = (check.Pod(name, "ours", PWK06, "main") for name in ("odd", "silent", "refused"))
    for pod in (odd, silent, refused):
        check.measure(pod)
    assert odd.unread == "date printed '1761800000.%N'" and silent.unread == "no answer from date"
    assert refused.unread == "your login may not run commands in it"


def test_a_store_a_tsg_pod_cannot_read_becomes_a_note(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    _fake_oc(monkeypatch, (json.dumps({"mongo": [0.1, 0.002], "redis": "ConnectionError('refused')"}), ""))
    pod = _pod("api-1", PWK06, (0.0, 0.5))
    check.measure_stores(pod)
    assert pod.store_minus_pod == {"mongo": check.Offset(0.1, 0.002)} and "Redis not read" in pod.notes[0]
    _fake_oc(monkeypatch, ("", "Traceback ... ValidationError"))
    broken = _pod("api-2", PWK06, (0.0, 0.5))
    check.measure_stores(broken)
    assert broken.notes == ["MongoDB and Redis not read from this pod: Traceback ... ValidationError"]


def test_a_store_is_read_through_the_pod_with_the_shortest_round_trip() -> None:
    mongo = check.store_minus_here(_uat_run(), "mongo")
    assert round(mongo.seconds, 2) == 10.62  # through worker-reaper: -34.13 + 44.75
    assert check.store_minus_here([_pod("loki", PWK03, (0.0, 0.5))], "mongo") is None


def test_the_log_has_one_plain_line_per_clock_with_its_time_and_gap_from_utc() -> None:
    lines = check.report(_uat_run(), 2.0, STANDARD)
    assert lines[0] == "UAT CLOCK CHECK at 2026-10-30 09:15:02 UTC"
    assert "Allowed gap: 2 s. Each reading is accurate to within 0.9 s." in lines
    assert "Checked: MongoDB, Redis, and 6 pods in namespaces ai-common, ai-threatgen." in lines
    for expected in (
        "[GAP] MongoDB server 10.228.146.3:27018 shows 09:15:13 UTC: 11 s ahead of UTC",
        "[OK]  Redis server 10.228.146.4:6379 shows 09:15:02 UTC: 0.3 s behind UTC",
        "[N/A] Pod ai-common/kube-state-metrics-77fc96bf7d-2f2zh on node aos1descpwk03: not read"
        " (its container is not running)",
        "[GAP] Pod ai-common/loki-64bd6885d5-fj96v on node aos1descpwk03 shows 09:15:47 UTC:"
        " 45 s ahead of UTC",
        "[OK]  Pod ai-threatgen/api-79794b5968-6qv5n on node aos1descpwk06 shows 09:15:02 UTC:"
        " in step with UTC",
        "[GAP] Pod ai-threatgen/api-79794b5968-h8jbk on node aos1descpwk02 shows 09:16:20 UTC:"
        " 1 min 18 s ahead of UTC",
    ):
        assert expected in lines


def test_the_summary_numbers_each_gap_and_says_who_fixes_it() -> None:
    lines = check.report(_uat_run(), 2.0, STANDARD)
    summary = lines[lines.index("SUMMARY: 3 gaps found (more than 2 s from UTC)") :]
    assert summary[1:4] == [
        "1. MongoDB server 10.228.146.3:27018 is 11 s ahead of UTC.",
        "   Fix: the MongoDB server's admins turn on time sync (chrony or NTP) on that server.",
        "2. OpenShift node aos1descpwk02 is 1 min 18 s ahead of UTC.",
    ]
    assert f"   oc debug node/{PWK02} -- chroot /host chronyc tracking" in summary
    assert "3. OpenShift node aos1descpwk03 is 45 s ahead of UTC." in summary
    on_pwk03 = ["ai-common/loki-64bd6885d5-fj96v", "ai-common/worker-reaper-7d4874bb8-h7fbx"]
    on_pwk03.append("ai-threatgen/beat-6fc5cc8585-99qc4")
    assert f"   Our pods on it show the same gap: {', '.join(on_pwk03)}" in summary
    assert "No gap: Redis server 10.228.146.4:6379, OpenShift node aos1descpwk06." in summary
    assert "Pods not read: 1 (marked [N/A] above)." in summary
    text = "\n".join(summary)
    assert "every time it saves is 11 s ahead of UTC" in text and "fires for 4 of 4 TSG pods" in text
    assert "Not checked" not in text and "this computer's clock is probably wrong" not in text


def test_a_nodes_gap_comes_from_its_most_accurate_reading() -> None:
    rough, sharp = _pod("a-pod", PWK02, (14.0, 3.0)), _pod("b-pod", PWK02, (10.0, 0.5))  # one node, one clock
    assert "1. OpenShift node aos1descpwk02 is 10 s ahead of UTC." in check.report(
        [rough, sharp], 2.0, STANDARD
    )


def test_nothing_read_is_never_a_pass() -> None:
    refused = [_pod(f"api-{n}", PWK06, unread="your login may not run commands in it") for n in range(2)]
    text = "\n".join(check.report(refused, 2.0, STANDARD))
    assert "[N/A] MongoDB server: not read (no TSG pod could reach it; see the notes below)" in text
    assert "Not checked: MongoDB server, Redis server, every pod." in text and "No gap" not in text
    no_stores = [_pod("api-1", PWK06, (0.1, 0.9))]
    assert "Not checked: MongoDB server, Redis server." in "\n".join(check.report(no_stores, 2.0, STANDARD))


def test_the_exit_code_says_no_gap_gap_or_not_checked_and_the_log_is_saved(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    right = [_pod("api-1", PWK06, (0.1, 0.9), mongo=0.2, redis=-0.1)]
    assert "SUMMARY: 0 gaps found (more than 2 s from UTC)" in check.report(right, 2.0, STANDARD)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(check, "measure", lambda pod: None)
    for pods, code in ((right, 0), (_uat_run(), 1), ([_pod("api-1", PWK06, (0.1, 0.9))], 2)):
        monkeypatch.setattr(check, "running_pods", lambda pods=pods: pods)
        assert check.main([]) == code
    [log, *_] = sorted(tmp_path.glob("clock_check_*_UTC.log"))
    assert log.read_text(encoding="utf-8").startswith("UAT CLOCK CHECK at ")


def test_every_clock_with_a_gap_points_at_this_computers_clock() -> None:
    # This computer is 30 s behind everything: MongoDB and both nodes read 30 s ahead of it.
    pods = [_pod("api-1", PWK02, (30.0, 0.5), mongo=0.0), _pod("worker-1", PWK06, (30.2, 0.5))]
    assert "this computer's clock is probably wrong" in "\n".join(check.report(pods, 2.0, STANDARD))


def test_an_oc_error_is_said_in_plain_words() -> None:
    error = 'error: unable to upgrade connection: container not found ("kube-state-metrics")'
    assert check.plain_reason(error) == "its container is not running"
    assert check.plain_reason("something new") == "something new"


def test_the_in_pod_snippet_reads_both_stores_and_names_them() -> None:
    printed = io.StringIO()
    with contextlib.redirect_stdout(printed):
        exec(check.STORE_SNIPPET, {})  # noqa: S102 — our own snippet, as the pod runs it
    measured = json.loads(printed.getvalue())
    for store in ("mongo", "redis"):
        seconds, error, address = measured[store]
        assert abs(seconds) < 2 and 0 <= error < 1 and ":" in address  # same machine: the clocks agree
