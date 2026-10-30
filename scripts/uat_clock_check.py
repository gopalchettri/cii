"""UAT clock check: how far MongoDB's, Redis' and every pod's clock (in every project your login sees) is
from this computer's, in plain words, and what to fix (docs/UAT_CLOCK_SKEW_RUNBOOK.md). Read-only.

After oc login, from the project folder: python scripts/uat_clock_check.py [--max-skew 2]"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

STORES = {"mongo": "MongoDB", "redis": "Redis"}
OC_TIMEOUT_SECONDS = 60
PARALLEL_PODS = 8  # each measurement brackets its own oc call, so running them side by side stays correct
CLOCK_SKEW_ALERT_SECONDS = 5  # the ClockSkew alert in observability/prometheus/rules.yml
#: oc's error text -> what it means, for pods whose clock could not be read.
PLAIN_REASONS = {
    "container not found": "its container is not running",
    "forbidden": "your login may not run commands in it",
    "executable file not found": "it has no date command",
}
#: Runs inside an app pod with the app's own clients and settings; prints only offsets, never a password.
STORE_SNIPPET = """
import json, time
from datetime import UTC
from app.core.database import get_mongodb, get_redis_client
def mongo_epoch():  # localTime comes back naive UTC, as app/core/clock.py reads it
    server = get_mongodb().command("hello")["localTime"]
    return server.replace(tzinfo=server.tzinfo or UTC).timestamp()
def redis_epoch():
    seconds, micros = get_redis_client().time()
    return seconds + micros / 1e6
result = {}
for name, read in (("mongo", mongo_epoch), ("redis", redis_epoch)):
    try:
        read()  # the first call connects; the second measures one round trip
        sent = time.time()
        server = read()
        received = time.time()
        result[name] = [server - (sent + received) / 2, (received - sent) / 2]
    except Exception as exc:
        result[name] = repr(exc)[:200]
print(json.dumps(result))
"""


@dataclass
class Offset:
    """A clock minus another clock, in seconds, give or take `error`."""

    seconds: float
    error: float

    def is_off(self, max_skew: float) -> bool:
        return abs(self.seconds) - self.error > max_skew


@dataclass
class Pod:
    name: str
    namespace: str
    node: str
    container: str
    pod_minus_here: Offset | None = None
    store_minus_pod: dict[str, Offset] = field(default_factory=dict)
    unread: str = ""  # why its clock could not be read
    notes: list[str] = field(default_factory=list)


def oc(args: list[str], stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    """Runs one oc command; a failure comes back as a non-zero exit, never an exception."""
    try:
        return subprocess.run(  # noqa: S603 — fixed oc commands, no shell
            ["oc", *args],  # noqa: S607 — oc from PATH, as the runbook uses it
            input=stdin,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=OC_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError:
        raise SystemExit("oc is not on PATH: install the OpenShift CLI and run oc login first.") from None
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(args, 1, "", f"no answer within {OC_TIMEOUT_SECONDS} s")


def last_line(text: str) -> str:
    lines = text.strip().splitlines()
    return lines[-1] if lines else ""


def plain_reason(error: str) -> str:
    return next((plain for known, plain in PLAIN_REASONS.items() if known in error.lower()), error)


def short_name(node: str) -> str:
    return node.split(".")[0]


def how_far(seconds: float) -> str:
    """A clock difference in words: '0.3 s behind', '1 min 18 s ahead', '5 h 30 min behind'."""
    size = abs(seconds)
    if size < 0.05:
        return "in step"
    whole = round(size)
    if size < 10:
        amount = f"{size:.1f} s"
    elif whole < 60:
        amount = f"{whole} s"
    elif whole < 3600:
        amount = f"{whole // 60} min {whole % 60} s"
    elif whole < 86400:
        amount = f"{whole // 3600} h {whole % 3600 // 60} min"
    else:
        amount = f"{whole // 86400} d {whole % 86400 // 3600} h"
    return f"{amount} {'ahead' if seconds > 0 else 'behind'}"


def offset_from_timing(remote_epoch: float, sent: float, received: float) -> Offset:
    """Remote clock minus ours: the remote read its clock somewhere between `sent` and `received`."""
    return Offset(remote_epoch - (sent + received) / 2, (received - sent) / 2)


def project_names(listing: str) -> list[str]:
    """The names in `oc get projects -o name` (project.project.openshift.io/<name> lines)."""
    return [line.rsplit("/", 1)[-1] for line in listing.split()]


def pods_from_listing(listing: dict, namespace: str) -> list[Pod]:
    """The Running pods of one `oc get pods -o json` answer."""
    pods = []
    for item in listing["items"]:
        spec, name = item["spec"], item["metadata"]["name"]
        if item.get("status", {}).get("phase") == "Running":
            pods.append(Pod(name, namespace, spec["nodeName"], spec["containers"][0]["name"]))
    return pods


def running_pods() -> list[Pod]:
    """Every Running pod of every project this login sees; a project it may not list is named on stderr."""
    projects = oc(["get", "projects", "-o", "name"])
    if projects.returncode:
        raise SystemExit(f"oc get projects: {last_line(projects.stderr)}. Run oc login first.")
    pods = []
    for namespace in project_names(projects.stdout):
        answer = oc(["get", "pods", "-n", namespace, "-o", "json"])
        if answer.returncode:
            print(f"Skipped project {namespace}: {last_line(answer.stderr)}", file=sys.stderr)
            continue
        pods += pods_from_listing(json.loads(answer.stdout), namespace)
    return pods


def measure(pod: Pod) -> None:
    """The pod's clock minus this computer's (`date` in the pod), then MongoDB's and Redis' from inside it."""
    sent = time.time()
    answer = oc(["exec", "-n", pod.namespace, pod.name, "-c", pod.container, "--", "date", "+%s.%N"])
    received = time.time()
    try:
        pod.pod_minus_here = offset_from_timing(float(answer.stdout), sent, received)
    except ValueError:
        pod.unread = plain_reason(last_line(answer.stderr))
        return
    measure_stores(pod)


def measure_stores(pod: Pod) -> None:
    """MongoDB's and Redis' clocks minus the pod's, measured inside the pod (app image only)."""
    command = ["exec", "-i", "-n", pod.namespace, pod.name, "-c", pod.container, "--", "python", "-"]
    answer = oc(command, STORE_SNIPPET)
    try:
        measured = json.loads(last_line(answer.stdout))
    except ValueError:
        return  # no Python or no app in this image: not a TSG app pod
    for store, value in measured.items():
        if isinstance(value, list):
            pod.store_minus_pod[store] = Offset(*value)
        else:
            pod.notes.append(f"{STORES[store]} not read from this pod: {value}")


def store_minus_here(pods: list[Pod], store: str) -> Offset | None:
    """A store's clock minus this computer's, through the pod with the shortest oc round trip."""
    measured = [pod for pod in pods if pod.pod_minus_here and store in pod.store_minus_pod]
    if not measured:
        return None
    via = min(measured, key=lambda pod: pod.pod_minus_here.error)  # type: ignore[union-attr]
    pod_clock, store_clock = via.pod_minus_here, via.store_minus_pod[store]
    assert pod_clock is not None
    return Offset(store_clock.seconds + pod_clock.seconds, store_clock.error + pod_clock.error)


def pod_is_off(pod: Pod, max_skew: float) -> bool:
    return pod.pod_minus_here is not None and pod.pod_minus_here.is_off(max_skew)


def judged(offset: Offset, max_skew: float) -> str:
    """'1 min 18 s ahead   WRONG'."""
    return f"{how_far(offset.seconds):18} {'WRONG' if offset.is_off(max_skew) else 'RIGHT'}"


def store_lines(pods: list[Pod], max_skew: float) -> list[str]:
    lines = []
    for store, name in STORES.items():
        offset = store_minus_here(pods, store)
        lines.append(f"{name + ' server':16} {judged(offset, max_skew) if offset else 'not read'}")
    return [*lines, ""]


def namespace_lines(pods: list[Pod], max_skew: float) -> list[str]:
    """One project: its counts, then one row per pod, the wrong ones first."""
    wrong = sum(pod_is_off(pod, max_skew) for pod in pods)
    unread = sum(pod.pod_minus_here is None for pod in pods)
    counts = f"pods: {len(pods)}, WRONG: {wrong}" + (f", not read: {unread}" if unread else "")
    lines = [f"{pods[0].namespace}: {counts}"]
    width = max(len(pod.name) for pod in pods)
    for pod in sorted(pods, key=lambda pod: (not pod_is_off(pod, max_skew), pod.name)):
        if pod.pod_minus_here is None:
            lines.append(f"  {pod.name:{width}}   not read: {pod.unread}")
        else:
            row = judged(pod.pod_minus_here, max_skew)
            lines.append(f"  {pod.name:{width}}   {row}  node {short_name(pod.node)}")
        lines += [f"  {'':{width}}   {note}" for note in pod.notes]
    return [*lines, ""]


def fix_lines(pods: list[Pod], max_skew: float) -> list[str]:
    """What to fix: a wrong MongoDB or Redis server, and each node running a wrong pod."""
    lines = []
    for store, name in STORES.items():
        offset = store_minus_here(pods, store)
        if offset and offset.is_off(max_skew):
            lines.append(f"  {name} server is {how_far(offset.seconds)}. Its admins turn on time sync (NTP).")
    wrong_by_node: dict[str, list[Offset]] = {}
    for pod in pods:
        if pod.pod_minus_here and pod.pod_minus_here.is_off(max_skew):
            wrong_by_node.setdefault(pod.node, []).append(pod.pod_minus_here)
    for node, offsets in wrong_by_node.items():
        seconds = min(offsets, key=lambda offset: offset.error).seconds
        lines.append(
            f"  Node {short_name(node)} is {how_far(seconds)} (our pods on it: {len(offsets)}). Admin check:"
        )
        lines.append(f"    oc debug node/{node} -- chroot /host chronyc tracking")
    measured = [pod for pod in pods if pod.pod_minus_here]
    if measured and all(pod_is_off(pod, max_skew) for pod in measured):
        lines.append("  Every pod disagrees with this computer: check this computer's clock first.")
    return ["To fix:", *lines, ""] if lines else ["Nothing to fix: every clock read is right.", ""]


def meaning_lines(pods: list[Pod], max_skew: float) -> list[str]:
    """What the clocks mean for TSG, which takes MongoDB's time for every job."""
    app_pods = [pod for pod in pods if "mongo" in pod.store_minus_pod]
    if not app_pods:
        return []
    alerting = sum(abs(pod.store_minus_pod["mongo"].seconds) > CLOCK_SKEW_ALERT_SECONDS for pod in app_pods)
    mongo = store_minus_here(pods, "mongo")
    lines = ["What it means for TSG:", "  Every TSG pod takes MongoDB's time, so jobs still run."]
    if mongo and mongo.is_off(max_skew):
        lines.append(f"  Saved times are {how_far(mongo.seconds)} of real time.")
    alert = f"a pod more than {CLOCK_SKEW_ALERT_SECONDS} s from MongoDB"
    return [*lines, f"  The ClockSkew alert ({alert}) fires for {alerting} of {len(app_pods)} app pods."]


def report(pods: list[Pod], max_skew: float) -> list[str]:
    """The whole report: MongoDB and Redis, each project's pods, what to fix, what it means for TSG."""
    errors = [pod.pod_minus_here.error for pod in pods if pod.pod_minus_here]
    within = f"each figure ±{max(errors):.1f} s" if errors else "nothing read"
    header = f"Clock check against this computer's clock ({within}). WRONG = more than {max_skew:g} s off."
    lines = [header, "", *store_lines(pods, max_skew)]
    for namespace in sorted({pod.namespace for pod in pods}):
        lines += namespace_lines([pod for pod in pods if pod.namespace == namespace], max_skew)
    return lines + fix_lines(pods, max_skew) + meaning_lines(pods, max_skew)


def anything_off(pods: list[Pod], max_skew: float) -> bool:
    stores = [store_minus_here(pods, store) for store in STORES]
    wrong_store = any(offset.is_off(max_skew) for offset in stores if offset)
    return wrong_store or any(pod_is_off(pod, max_skew) for pod in pods)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="UAT clock check: MongoDB, Redis and every pod.")
    parser.add_argument("--max-skew", type=float, default=2.0, help="seconds a clock may be off (default 2)")
    max_skew = parser.parse_args(argv).max_skew
    pods = running_pods()
    print(f"Measuring {len(pods)} pod(s) ...", file=sys.stderr)
    with ThreadPoolExecutor(PARALLEL_PODS) as pool:
        list(pool.map(measure, pods))
    print("\n".join(report(pods, max_skew)))
    return 1 if anything_off(pods, max_skew) else 0


if __name__ == "__main__":
    sys.exit(main())
