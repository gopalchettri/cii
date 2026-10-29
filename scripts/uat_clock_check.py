"""UAT clock check: how far MongoDB's, Redis' and every TSG pod's clock is from this computer's, and which
nodes need time sync (docs/UAT_CLOCK_SKEW_RUNBOOK.md). Read-only; needs `oc` logged in to the cluster.

From the project folder: python scripts/uat_clock_check.py [--max-skew 2]"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from dataclasses import dataclass, field

NAMESPACES = ("ai-threatgen", "ai-common")
POD_LABELS = "part-of in (tsg,tsg-monitoring)"
STORES = {"mongo": "MongoDB", "redis": "Redis"}
OC_TIMEOUT_SECONDS = 60
#: Runs inside an app pod with the app's own clients and settings; prints only offsets, never a password.
STORE_SNIPPET = """
import json, time
from datetime import UTC
from app.core.database import get_mongodb, get_redis_client

def mongo_epoch():
    server = get_mongodb().command("hello")["localTime"]  # naive UTC, as app/core/clock.py reads it
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
    notes: list[str] = field(default_factory=list)


def oc(args: list[str], stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    """Runs one oc command; a failure comes back as a non-zero exit, never an exception."""
    try:
        return subprocess.run(  # noqa: S603 — fixed oc commands, no shell
            ["oc", *args],  # noqa: S607 — oc from PATH, as the runbook uses it
            input=stdin,
            capture_output=True,
            text=True,
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


def offset_from_timing(remote_epoch: float, sent: float, received: float) -> Offset:
    """Remote clock minus ours: the remote read its clock somewhere between `sent` and `received`."""
    return Offset(remote_epoch - (sent + received) / 2, (received - sent) / 2)


def pods_from_listing(listing: dict, namespace: str) -> list[Pod]:
    """The Running pods of one `oc get pods -o json` answer."""
    return [
        Pod(
            item["metadata"]["name"],
            namespace,
            item["spec"]["nodeName"],
            item["spec"]["containers"][0]["name"],
        )
        for item in listing["items"]
        if item.get("status", {}).get("phase") == "Running"
    ]


def running_pods() -> list[Pod]:
    pods = []
    for namespace in NAMESPACES:
        answer = oc(["get", "pods", "-n", namespace, "-l", POD_LABELS, "-o", "json"])
        if answer.returncode:
            raise SystemExit(f"oc get pods -n {namespace}: {last_line(answer.stderr)}. Run oc login first.")
        pods += pods_from_listing(json.loads(answer.stdout), namespace)
    return pods


def measure_pod_clock(pod: Pod) -> None:
    """The pod's clock minus this computer's, from `date` in the pod."""
    sent = time.time()
    answer = oc(["exec", "-n", pod.namespace, pod.name, "-c", pod.container, "--", "date", "+%s.%N"])
    received = time.time()
    try:
        pod.pod_minus_here = offset_from_timing(float(answer.stdout), sent, received)
    except ValueError:
        pod.notes.append(f"no clock read: {last_line(answer.stderr)}")


def measure_stores(pod: Pod) -> None:
    """MongoDB's and Redis' clocks minus the pod's, measured inside the pod (app image only)."""
    command = ["exec", "-i", "-n", pod.namespace, pod.name, "-c", pod.container, "--", "python", "-"]
    answer = oc(command, STORE_SNIPPET)
    try:
        measured = json.loads(last_line(answer.stdout))
    except ValueError:
        return  # no Python or no app in this image: the monitoring pods
    for store, value in measured.items():
        if isinstance(value, list):
            pod.store_minus_pod[store] = Offset(*value)
        else:
            pod.notes.append(f"{STORES[store]} not read: {value}")


def store_minus_here(pods: list[Pod], store: str) -> tuple[Offset, Pod] | None:
    """A store's clock minus this computer's, through the pod with the shortest oc round trip."""
    measured = [pod for pod in pods if pod.pod_minus_here and store in pod.store_minus_pod]
    if not measured:
        return None
    via = min(measured, key=lambda pod: pod.pod_minus_here.error)  # type: ignore[union-attr]
    pod_clock, store_clock = via.pod_minus_here, via.store_minus_pod[store]
    assert pod_clock is not None
    return Offset(store_clock.seconds + pod_clock.seconds, store_clock.error + pod_clock.error), via


def pod_is_off(pod: Pod, max_skew: float) -> bool:
    return pod.pod_minus_here is not None and pod.pod_minus_here.is_off(max_skew)


def nodes_to_fix(pods: list[Pod], max_skew: float) -> dict[str, list[Pod]]:
    """Each node running a pod whose clock is off, with those pods."""
    nodes: dict[str, list[Pod]] = {}
    for pod in pods:
        if pod_is_off(pod, max_skew):
            nodes.setdefault(pod.node, []).append(pod)
    return nodes


def shown(offset: Offset | None, max_skew: float) -> str:
    if offset is None:
        return "-"
    return f"{offset.seconds:+.2f} ±{offset.error:.2f}{' OFF' if offset.is_off(max_skew) else ''}"


def store_lines(pods: list[Pod], max_skew: float) -> list[str]:
    lines = []
    for store, name in STORES.items():
        found = store_minus_here(pods, store)
        if found is None:
            lines.append(f"{name:8} not measured: no app pod answered (see the notes)")
            continue
        offset, via = found
        verdict = f"  OFF: the {name} server needs time sync" if offset.is_off(max_skew) else ""
        lines.append(f"{name:8} {shown(offset, max_skew):22} via {via.name}{verdict}")
    return lines


def report(pods: list[Pod], max_skew: float) -> list[str]:
    """The whole report: stores, one row per pod, notes, and the nodes to fix."""
    lines = [f"Reference: this computer's clock (check: w32tm /query /status). OFF = more than {max_skew} s."]
    lines += store_lines(pods, max_skew)
    lines.append(f"\n{'POD':45} {'NODE':28} {'POD-COMPUTER':20} {'MONGO-POD':20} REDIS-POD")
    for pod in pods:
        here = shown(pod.pod_minus_here, max_skew)
        mongo, redis = (shown(pod.store_minus_pod.get(store), max_skew) for store in STORES)
        lines.append(f"{pod.name:45} {pod.node:28} {here:20} {mongo:20} {redis}")
    lines += [f"note {pod.name}: {note}" for pod in pods for note in pod.notes]
    measured = [pod for pod in pods if pod.pod_minus_here]
    if measured and all(pod_is_off(pod, max_skew) for pod in measured):
        lines.append("Every pod is off from this computer: check this computer's clock first.")
    for node, off_pods in nodes_to_fix(pods, max_skew).items():
        offsets = [pod.pod_minus_here.seconds for pod in off_pods if pod.pod_minus_here]
        average = sum(offsets) / len(offsets)
        lines.append(
            f"Node to fix: {node} ({len(off_pods)} pod(s), about {average:+.0f} s): "
            f"oc debug node/{node} -- chroot /host chronyc tracking"
        )
    return lines


def anything_off(pods: list[Pod], max_skew: float) -> bool:
    stores = [store_minus_here(pods, store) for store in STORES]
    return any(pod_is_off(pod, max_skew) for pod in pods) or any(
        found[0].is_off(max_skew) for found in stores if found
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="UAT clock check: MongoDB, Redis and every TSG pod.")
    parser.add_argument("--max-skew", type=float, default=2.0, help="seconds a clock may be off (default 2)")
    max_skew = parser.parse_args(argv).max_skew
    pods = running_pods()
    print(f"Measuring {len(pods)} pod(s) in {', '.join(NAMESPACES)} ...", file=sys.stderr)
    for pod in pods:
        measure_pod_clock(pod)
        measure_stores(pod)
    print("\n".join(report(pods, max_skew)))
    return 1 if anything_off(pods, max_skew) else 0


if __name__ == "__main__":
    sys.exit(main())
