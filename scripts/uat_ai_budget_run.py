"""UAT token-limit report in one command: finds a Running API pod, streams the AI budget evidence scripts and
today's worker logs into it, runs scripts/ai_budget_evidence.py there (today's runs, read-only on MongoDB, one
5-token limits question per model) and saves the report here as ai_budget_<date>_UTC.md to share.

After oc login, from the UAT Windows server: python uat_ai_budget_run.py [--namespace ai-threatgen]
Keep it beside the scripts it streams (and uat_clock_check.py, whose oc helpers it uses). Stdlib only,
Python 3.8+. Exit code: 0 the report is saved, 2 no API pod was found or the run failed."""

from __future__ import annotations

import argparse
import json
import shlex
import sys
from datetime import datetime, timezone
from pathlib import Path

import uat_clock_check as clock

NAMESPACE = "ai-threatgen"  # deploy/deploy_threatgen.yaml
API_PREFIX, WORKER_PREFIX = "api-", "worker-"  # its Deployments' pods: api-<hash>, worker-scenarios-<hash>
APP_FOLDER = "/app"  # the image's WORKDIR: the report imports the app's own settings from it
FOLDER = "/tmp/ai_budget"  # noqa: S108 — in the pod, not here; removed after the run
RUN_TIMEOUT_SECONDS = 600  # the report reads MongoDB and asks the gateway: more than the clock check's 60 s
SCRIPTS = (
    "ai_budget_evidence.py",
    "ai_budget_measures.py",
    "ai_budget_report.py",
    "ai_budget_sessions.py",
    "ai_budget_waits.py",
    "ai_limits_check.py",
    "ai_capacity_report.py",
)
HERE = Path(__file__).resolve().parent
NO_LIMIT = "no tokens-a-minute limit"  # ai_budget_evidence.py's words when the gateway states none


def app_pods(namespace: str) -> list[clock.Pod]:
    """The Running pods of the TSG image in `namespace`."""
    answer = clock.oc(["get", "pods", "-n", namespace, "-o", "json"])
    if answer.returncode:
        print(f"oc get pods -n {namespace}: {clock.last_line(answer.stderr)}", file=sys.stderr)
        return []
    return [pod for pod in clock.pods_from_listing(json.loads(answer.stdout), namespace) if pod.runs_app]


def in_pod(pod: clock.Pod, command: str, stdin: str | None = None) -> bool:
    """Runs one shell command in the pod; False (and why, on stderr) when it fails."""
    args = ["exec", "-i", "-n", pod.namespace, pod.name, "-c", pod.container, "--", "sh", "-c", command]
    answer = clock.oc(args, stdin)
    if answer.returncode:
        print(f"In {pod.name}: {clock.last_line(answer.stderr) or 'failed'}", file=sys.stderr)
    return answer.returncode == 0


def send(pod: clock.Pod, name: str, text: str) -> bool:
    """Streams `text` into the pod as FOLDER/name (no tar needed)."""
    return in_pod(pod, f"cat > {shlex.quote(f'{FOLDER}/{name}')}", text)


def today_logs(workers: list[clock.Pod], since: datetime) -> dict[str, str]:
    """Each worker pod's log since `since`, by the name it is saved under; a log that fails is skipped."""
    logs = {}
    for pod in workers:
        stamp = since.strftime("%Y-%m-%dT%H:%M:%SZ")
        answer = clock.oc(
            ["logs", "-n", pod.namespace, pod.name, "-c", pod.container, f"--since-time={stamp}"]
        )
        if answer.returncode:
            print(f"Skipped the log of {pod.name}: {clock.last_line(answer.stderr)}", file=sys.stderr)
            continue
        logs[f"{pod.name}.log"] = answer.stdout
    return logs


def report(api: clock.Pod, logs: list[str]) -> str | None:
    """Runs the evidence script in the API pod's app folder; its report, or None when it failed."""
    paths = " ".join(shlex.quote(f"{FOLDER}/{name}") for name in logs)
    command = f"cd {APP_FOLDER} && PYTHONIOENCODING=utf-8 python {FOLDER}/ai_budget_evidence.py" + (
        f" --logs {paths}" if logs else ""
    )
    answer = clock.oc(["exec", "-n", api.namespace, api.name, "-c", api.container, "--", "sh", "-c", command])
    if answer.returncode or not answer.stdout.strip():
        print(f"The report failed in {api.name}: {answer.stderr.strip() or 'no output'}", file=sys.stderr)
        if NO_LIMIT in answer.stderr:
            print("The gateway's answers are above. This runner never assumes a limit (no --budget): ask the "
                  "gateway's team what the key's tokens-a-minute limit is.", file=sys.stderr)  # fmt: skip
        return None
    return answer.stdout


def run(api: clock.Pod, workers: list[clock.Pod], today: datetime) -> str | None:
    """Sends the scripts and today's logs into the API pod, runs the report there; None if a step failed."""
    if not in_pod(api, f"mkdir -p {FOLDER}"):
        return None
    for name in SCRIPTS:
        if not send(api, name, (HERE / name).read_text(encoding="utf-8")):
            return None
    logs = today_logs(workers, today)
    sent = [name for name, text in logs.items() if send(api, name, text)]
    return report(api, sent)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="The UAT token-limit report of today's runs, in one command."
    )
    parser.add_argument("--namespace", default=NAMESPACE, help=f"the TSG project (default: {NAMESPACE})")
    args = parser.parse_args(argv)
    clock.OC_TIMEOUT_SECONDS = RUN_TIMEOUT_SECONDS  # ponytail: oc() reads it at each call; this script alone
    pods = app_pods(args.namespace)
    api = next((pod for pod in pods if pod.name.startswith(API_PREFIX)), None)
    if api is None:
        print(f"No Running API pod ({API_PREFIX}*) in {args.namespace}: is oc logged in?", file=sys.stderr)
        return 2
    now = datetime.now(timezone.utc)  # noqa: UP017 — datetime.UTC needs 3.11
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    workers = [pod for pod in pods if pod.name.startswith(WORKER_PREFIX)]
    print(
        f"Reading today's runs in {api.name}, with the logs of {len(workers)} worker pods...", file=sys.stderr
    )
    try:
        text = run(api, workers, today)
    finally:
        in_pod(api, f"rm -rf {FOLDER}")
    if text is None:
        return 2
    saved = Path(f"ai_budget_{today:%Y-%m-%d}_UTC.md")
    saved.write_text(text, encoding="utf-8")
    print(f"Saved {saved.resolve()}: share this file.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
