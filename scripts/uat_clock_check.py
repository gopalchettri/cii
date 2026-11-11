"""UAT clock check, UTC as the standard: a plain log for the support team of the time MongoDB, Redis and every
pod (in every project of ours your login sees) show, each one's gap from UTC, and who fixes each gap
(docs/UAT_CLOCK_SKEW_RUNBOOK.md). Read-only. UTC is this computer's clock, so keep it synced.

After oc login: python uat_clock_check.py [--max-skew 2]. Stdlib only, Python 3.8+. The log is printed and
saved as clock_check_<UTC time>.log in the current folder.
Exit code: 0 no gap, 1 a gap, 2 MongoDB, Redis or every pod could not be read."""

from __future__ import annotations

import argparse
import json
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

STORES = {"mongo": "MongoDB", "redis": "Redis"}
OC_TIMEOUT_SECONDS = 60
PARALLEL_PODS = 8  # each measurement brackets its own oc call, so running them side by side stays correct
CLOCK_SKEW_ALERT_SECONDS = 5  # the ClockSkew alert in observability/prometheus/rules.yml
APP_IMAGE = "tsg-api"  # every TSG app pod's image (deploy/deploy_threatgen.yaml); only it reads MongoDB/Redis
PLATFORM_PROJECT_PREFIXES = ("openshift", "kube-")  # OpenShift's own projects: none of our pods run there
#: oc's error text -> what it means, for pods whose clock could not be read.
PLAIN_REASONS = {
    "container not found": "its container is not running",
    "forbidden": "your login may not run commands in it",
    "executable file not found": "it has no date command",
}
#: Runs inside a TSG pod with the app's own clients and settings; prints offsets and server addresses, never a
#: password.
STORE_SNIPPET = """
import json, time
from datetime import UTC
from app.core.database import get_mongodb, get_redis_client
def mongo_epoch():  # localTime comes back naive UTC, as app/core/clock.py reads it
    server = get_mongodb().command("hello")["localTime"]
    return server.replace(tzinfo=server.tzinfo or UTC).timestamp()
def mongo_address():
    host, port = get_mongodb().client.address
    return f"{host}:{port}"
def redis_epoch():
    seconds, micros = get_redis_client().time()
    return seconds + micros / 1e6
def redis_address():
    settings = get_redis_client().connection_pool.connection_kwargs
    return f"{settings['host']}:{settings['port']}"
result = {}
for name, read, address in (("mongo", mongo_epoch, mongo_address), ("redis", redis_epoch, redis_address)):
    try:
        read()  # the first call connects; the second measures one round trip
        sent = time.time()
        server = read()
        received = time.time()
        result[name] = [server - (sent + received) / 2, (received - sent) / 2]
    except Exception as exc:
        result[name] = repr(exc)[:200]
        continue
    try:
        result[name].append(address())
    except Exception:
        pass  # the address only names the server; the time is what counts
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
    runs_app: bool = False  # runs the TSG image, so it can read MongoDB and Redis
    pod_minus_here: Offset | None = None
    store_minus_pod: dict[str, Offset] = field(default_factory=dict)
    store_address: dict[str, str] = field(default_factory=dict)  # host:port of the server that answered
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


def from_utc(seconds: float) -> str:
    """'11 s ahead of UTC', '0.3 s behind UTC', or 'in step with UTC'."""
    words = how_far(seconds)
    if words == "in step":
        return "in step with UTC"
    return f"{words} of UTC" if words.endswith("ahead") else f"{words} UTC"


def utc_text(epoch: float) -> str:
    """A moment in UTC to the second: '2026-10-30 09:15:13 UTC'."""
    moment = datetime.fromtimestamp(round(epoch), timezone.utc)  # noqa: UP017 — datetime.UTC needs 3.11
    return moment.strftime("%Y-%m-%d %H:%M:%S UTC")


def clock_time(epoch: float, standard: float) -> str:
    """'09:15:13 UTC', with the date in front when it is not the standard's date."""
    shown = utc_text(epoch)
    return shown[11:] if shown[:10] == utc_text(standard)[:10] else shown


def offset_from_timing(remote_epoch: float, sent: float, received: float) -> Offset:
    """Remote clock minus ours: the remote read its clock somewhere between `sent` and `received`."""
    return Offset(remote_epoch - (sent + received) / 2, (received - sent) / 2)


def our_projects(listing: str) -> list[str]:
    """The project names in `oc get projects -o name`, without OpenShift's own (openshift*, kube-*)."""
    names = [line.rsplit("/", 1)[-1] for line in listing.split()]
    return [name for name in names if not name.startswith(PLATFORM_PROJECT_PREFIXES)]


def is_app_image(image: str) -> bool:
    """True for the TSG image, whatever its registry or tag: <registry>/<group>/tsg-api:<tag> or @sha256."""
    return image.rsplit("/", 1)[-1].split("@")[0].split(":")[0] == APP_IMAGE


def pods_from_listing(listing: dict, namespace: str) -> list[Pod]:
    """The Running pods of one `oc get pods -o json` answer."""
    pods = []
    for item in listing["items"]:
        spec, name = item["spec"], item["metadata"]["name"]
        container = spec["containers"][0]
        if item.get("status", {}).get("phase") == "Running":
            runs_app = is_app_image(container.get("image", ""))
            pods.append(Pod(name, namespace, spec["nodeName"], container["name"], runs_app))
    return pods


def running_pods() -> list[Pod]:
    """Every Running pod in our projects this login sees; a project it may not list is named on stderr."""
    projects = oc(["get", "projects", "-o", "name"])
    if projects.returncode:
        raise SystemExit(f"oc get projects: {last_line(projects.stderr)}. Run oc login first.")
    pods = []
    for namespace in our_projects(projects.stdout):
        answer = oc(["get", "pods", "-n", namespace, "-o", "json"])
        if answer.returncode:
            print(f"Skipped project {namespace}: {last_line(answer.stderr)}", file=sys.stderr)
            continue
        pods += pods_from_listing(json.loads(answer.stdout), namespace)
    return pods


def measure(pod: Pod) -> None:
    """The pod's clock minus this computer's (`date` in the pod), then, in a TSG pod, MongoDB's and Redis'."""
    sent = time.time()
    answer = oc(["exec", "-n", pod.namespace, pod.name, "-c", pod.container, "--", "date", "+%s.%N"])
    received = time.time()
    try:
        pod.pod_minus_here = offset_from_timing(float(answer.stdout), sent, received)
    except ValueError:
        printed = last_line(answer.stdout)
        said = f"date printed {printed!r}" if printed else "no answer from date"
        pod.unread = plain_reason(last_line(answer.stderr) or said)
        return
    if pod.runs_app:
        measure_stores(pod)


def measure_stores(pod: Pod) -> None:
    """MongoDB's and Redis' clocks minus the pod's, measured inside a TSG pod with the app's own clients."""
    command = ["exec", "-i", "-n", pod.namespace, pod.name, "-c", pod.container, "--", "python", "-"]
    answer = oc(command, STORE_SNIPPET)
    try:
        measured = json.loads(last_line(answer.stdout))
    except ValueError:
        why = last_line(answer.stderr) or "no answer"
        pod.notes.append(f"MongoDB and Redis not read from this pod: {why}")
        return
    for store, value in measured.items():
        if not isinstance(value, list):
            pod.notes.append(f"{STORES[store]} not read from this pod: {value}")
            continue
        seconds, error, *address = value
        pod.store_minus_pod[store] = Offset(seconds, error)
        if address:
            pod.store_address[store] = address[0]


def store_minus_here(pods: list[Pod], store: str) -> Offset | None:
    """A store's clock minus this computer's, through the pod with the shortest oc round trip."""
    measured = [pod for pod in pods if pod.pod_minus_here and store in pod.store_minus_pod]
    if not measured:
        return None
    via = min(measured, key=lambda pod: pod.pod_minus_here.error)  # type: ignore[union-attr]
    pod_clock, store_clock = via.pod_minus_here, via.store_minus_pod[store]
    assert pod_clock is not None
    return Offset(store_clock.seconds + pod_clock.seconds, store_clock.error + pod_clock.error)


def store_label(pods: list[Pod], store: str) -> str:
    """'MongoDB server 10.228.146.3:27018', or without the address when no pod named it."""
    address = next((pod.store_address[store] for pod in pods if store in pod.store_address), "")
    return f"{STORES[store]} server {address}".strip()


def node_clocks(pods: list[Pod]) -> dict[str, tuple[Offset, list[Pod]]]:
    """Each node's gap from UTC (its pod with the shortest oc round trip) and its pods that were read."""
    nodes: dict[str, tuple[Offset, list[Pod]]] = {}
    for pod in sorted(pods, key=lambda pod: (pod.namespace, pod.name)):
        if pod.pod_minus_here is None:
            continue
        best, on_node = nodes.get(pod.node, (pod.pod_minus_here, []))
        nearest = pod.pod_minus_here if pod.pod_minus_here.error < best.error else best
        nodes[pod.node] = (nearest, [*on_node, pod])
    return dict(sorted(nodes.items()))


def pod_is_off(pod: Pod, max_skew: float) -> bool:
    return pod.pod_minus_here is not None and pod.pod_minus_here.is_off(max_skew)


def reading(label: str, offset: Offset, standard: float, max_skew: float) -> str:
    """'[GAP] MongoDB server 10.228.146.3:27018 shows 09:15:13 UTC: 11 s ahead of UTC'."""
    tag = "[GAP]" if offset.is_off(max_skew) else "[OK] "
    return (
        f"{tag} {label} shows {clock_time(standard + offset.seconds, standard)}: {from_utc(offset.seconds)}"
    )


def reading_lines(pods: list[Pod], standard: float, max_skew: float) -> list[str]:
    """One line per clock: MongoDB, Redis, then every pod by namespace, with its node."""
    lines = ["READINGS"]
    for store in STORES:
        offset, label = store_minus_here(pods, store), store_label(pods, store)
        if offset is None:
            lines.append(f"[N/A] {label}: not read (no TSG pod could reach it; see the notes below)")
        else:
            lines.append(reading(label, offset, standard, max_skew))
    for pod in sorted(pods, key=lambda pod: (pod.namespace, pod.name)):
        label = f"Pod {pod.namespace}/{pod.name} on node {short_name(pod.node)}"
        if pod.pod_minus_here is None:
            lines.append(f"[N/A] {label}: not read ({pod.unread})")
        else:
            lines.append(reading(label, pod.pod_minus_here, standard, max_skew))
        lines += [f"      note: {note}" for note in pod.notes]
    return [*lines, ""]


def gaps_and_fine(pods: list[Pod], max_skew: float) -> tuple[list[list[str]], list[str]]:
    """Each gap as its lines (what, then who fixes it), and the clocks without a gap."""
    gaps, fine = [], []
    for store, name in STORES.items():
        offset, label = store_minus_here(pods, store), store_label(pods, store)
        if offset and offset.is_off(max_skew):
            fix = f"Fix: the {name} server's admins turn on time sync (chrony or NTP) on that server."
            gaps.append([f"{label} is {from_utc(offset.seconds)}.", fix])
        elif offset:
            fine.append(label)
    for node, (offset, node_pods) in node_clocks(pods).items():
        label = f"OpenShift node {short_name(node)}"
        if not offset.is_off(max_skew):
            fine.append(label)
            continue
        names = ", ".join(f"{pod.namespace}/{pod.name}" for pod in node_pods)
        gaps.append(
            [
                f"{label} is {from_utc(offset.seconds)}.",
                f"Our pods on it show the same gap: {names}",
                "Fix: the OpenShift cluster admin checks the node's time sync:",
                f"oc debug node/{node} -- chroot /host chronyc tracking",
            ]
        )
    return gaps, fine


def summary_lines(pods: list[Pod], max_skew: float) -> list[str]:
    """The gaps, numbered, with who fixes each; the clocks without a gap; and what could not be read."""
    gaps, fine = gaps_and_fine(pods, max_skew)
    missing, unread = not_checked(pods), sum(pod.pod_minus_here is None for pod in pods)
    lines = [
        f"SUMMARY: {len(gaps)} gap{'' if len(gaps) == 1 else 's'} found (more than {max_skew:g} s from UTC)"
    ]
    for number, (what, *how) in enumerate(gaps, 1):
        lines += [f"{number}. {what}", *(f"   {line}" for line in how)]
    if fine:
        lines.append(f"No gap: {', '.join(fine)}.")
    if missing:
        lines.append(f"Not checked: {', '.join(missing)}. The [N/A] lines above say why.")
    if unread:
        lines.append(f"Pods not read: {unread} (marked [N/A] above).")
    if len(gaps) > 1 and not fine:
        lines.append("Every clock read has a gap: this computer's clock is probably wrong. Check it first.")
    return [*lines, ""]


def tsg_lines(pods: list[Pod], max_skew: float) -> list[str]:
    """Why pods share their node's gap, and what the gaps mean for TSG, which takes MongoDB's time."""
    lines = [
        "Why a pod shows its node's gap: a pod has no clock of its own; it uses its OpenShift node's clock."
    ]
    mongo = store_minus_here(pods, "mongo")
    if mongo and mongo.is_off(max_skew):
        saved = from_utc(mongo.seconds)
        lines.append(
            f"Impact on TSG: TSG takes MongoDB's time for its jobs, so every time it saves is {saved}."
        )
    tsg = [pod for pod in pods if "mongo" in pod.store_minus_pod]
    if tsg:
        alerting = sum(abs(pod.store_minus_pod["mongo"].seconds) > CLOCK_SKEW_ALERT_SECONDS for pod in tsg)
        alert = f"The ClockSkew alert (a TSG pod more than {CLOCK_SKEW_ALERT_SECONDS} s from MongoDB)"
        lines.append(f"{alert} fires for {alerting} of {len(tsg)} TSG pods.")
    return lines


def not_checked(pods: list[Pod]) -> list[str]:
    """What this run could not read: MongoDB, Redis, or every pod. Any of them leaves the check unfinished."""
    missing = [store_label(pods, store) for store in STORES if store_minus_here(pods, store) is None]
    return missing if any(pod.pod_minus_here for pod in pods) else [*missing, "every pod"]


def report(pods: list[Pod], max_skew: float, standard: float) -> list[str]:
    """The log at one moment (`standard`, UTC by this computer): header, a line per clock, summary, impact."""
    errors = [pod.pod_minus_here.error for pod in pods if pod.pod_minus_here]
    accuracy = (
        f"Each reading is accurate to within {max(errors):.1f} s." if errors else "Nothing could be read."
    )
    namespaces = ", ".join(sorted({pod.namespace for pod in pods})) or "none"
    computer = socket.gethostname()
    header = [
        f"UAT CLOCK CHECK at {utc_text(standard)}",
        f"Standard time: UTC, from this computer ({computer}). Check its sync: w32tm /query /status",
        f"Allowed gap: {max_skew:g} s. {accuracy}",
        f"Checked: MongoDB, Redis, and {len(pods)} pods in namespaces {namespaces}.",
        "",
    ]
    return (
        header
        + reading_lines(pods, standard, max_skew)
        + summary_lines(pods, max_skew)
        + tsg_lines(pods, max_skew)
    )


def anything_off(pods: list[Pod], max_skew: float) -> bool:
    stores = [store_minus_here(pods, store) for store in STORES]
    wrong_store = any(offset.is_off(max_skew) for offset in stores if offset)
    return wrong_store or any(pod_is_off(pod, max_skew) for pod in pods)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="UAT clock check: MongoDB, Redis and every pod against UTC.")
    parser.add_argument("--max-skew", type=float, default=2.0, help="seconds a clock may be off (default 2)")
    max_skew = parser.parse_args(argv).max_skew
    pods = running_pods()
    print(f"Measuring {len(pods)} pod(s) ...", file=sys.stderr)
    with ThreadPoolExecutor(PARALLEL_PODS) as pool:
        list(pool.map(measure, pods))
    standard = time.time()
    log = "\n".join(report(pods, max_skew, standard)) + "\n"
    print(log)
    saved = Path(f"clock_check_{utc_text(standard)[:19].replace(' ', '_').replace(':', '')}_UTC.log")
    saved.write_text(log, encoding="utf-8")
    print(f"Saved to {saved.resolve()}: share this file with the support team.", file=sys.stderr)
    if anything_off(pods, max_skew):
        return 1
    return 2 if not_checked(pods) else 0


if __name__ == "__main__":
    sys.exit(main())
