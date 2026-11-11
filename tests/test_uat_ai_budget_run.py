"""The one-command UAT token-limit report (scripts/uat_ai_budget_run.py) with a fake oc: it picks the API pod,
streams the scripts and today's worker logs in, runs the report in the app folder, saves it and cleans up;
with no API pod, or a failed run, it exits 2. Each test names the mutation it catches."""

import importlib
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
try:
    runner = importlib.import_module("uat_ai_budget_run")
finally:
    sys.path.remove(str(REPO / "scripts"))

IMAGE = "image-registry.example/ai-threatgen/tsg-api:2026.10.30"


def _pod(name: str, image: str = IMAGE, phase: str = "Running") -> dict:
    containers = [{"name": "app", "image": image}]
    return {"metadata": {"name": name}, "status": {"phase": phase},
            "spec": {"nodeName": "node-1.example", "containers": containers}}  # fmt: skip


class FakeOc:
    """An oc that answers like UAT: `pods` are listed, every exec and log works unless `fails` names it."""

    def __init__(self, pods: list[dict], fails: str = "", why: str = "Traceback: it broke") -> None:
        self.pods, self.fails, self.why, self.calls, self.files = pods, fails, why, [], {}

    def __call__(self, args: list[str], stdin: str | None = None) -> subprocess.CompletedProcess:
        self.calls.append(args)
        command = args[-1]
        if self.fails and self.fails in command:
            return subprocess.CompletedProcess(args, 1, "", self.why)
        if args[:2] == ["get", "pods"]:
            return subprocess.CompletedProcess(args, 0, json.dumps({"items": self.pods}), "")
        if args[0] == "logs":
            return subprocess.CompletedProcess(args, 0, '{"event": "ai.limit_cut"}\n', "")
        if command.startswith("cat > "):
            self.files[command.removeprefix("cat > ")] = stdin
        out = "# UAT threat scenario generation\n" if "ai_budget_evidence.py" in command else ""
        return subprocess.CompletedProcess(args, 0, out, "")


@pytest.fixture
def oc(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """The fake oc in place of uat_clock_check's, in an empty folder, with its timeout put back after."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(runner.clock, "OC_TIMEOUT_SECONDS", runner.clock.OC_TIMEOUT_SECONDS)

    def install(fake: FakeOc) -> FakeOc:
        monkeypatch.setattr(runner.clock, "oc", fake)
        return fake

    return install


def test_the_report_is_made_in_the_api_pod_with_todays_worker_logs(oc, tmp_path: Path) -> None:
    """Mutation: a worker or another image's pod taken as the API pod, a script not sent, the logs not of
    today, the report run outside the app folder, or the folder left in the pod."""
    fake = oc(FakeOc([_pod("worker-scenarios-7d9f-abc"), _pod("redis-0", "redis:7"), _pod("api-5c6b-xyz")]))
    assert runner.main([]) == 0
    today = datetime.now(UTC).strftime("%Y-%m-%d")
    saved = tmp_path / f"ai_budget_{today}_UTC.md"
    assert saved.read_text(encoding="utf-8") == "# UAT threat scenario generation\n"
    folder, log = runner.FOLDER, "worker-scenarios-7d9f-abc.log"
    assert set(fake.files) == {f"{folder}/{name}" for name in (*runner.SCRIPTS, log)}
    assert fake.files[f"{folder}/ai_budget_waits.py"].startswith('"""The AI budget report')
    logs = [call for call in fake.calls if call[0] == "logs"]
    assert logs == [["logs", "-n", "ai-threatgen", "worker-scenarios-7d9f-abc", "-c", "app",
                     f"--since-time={today}T00:00:00Z"]]  # fmt: skip
    (run,) = [call for call in fake.calls if call[-1].startswith("cd /app && PYTHONIOENCODING=utf-8 python")]
    assert run[3] == "api-5c6b-xyz" and "--budget" not in " ".join(run)
    assert (
        run[-1]
        == f"cd /app && PYTHONIOENCODING=utf-8 python {folder}/ai_budget_evidence.py --logs {folder}/{log}"
    )
    assert fake.calls[-1][-1] == f"rm -rf {runner.FOLDER}"
    assert runner.clock.OC_TIMEOUT_SECONDS == runner.RUN_TIMEOUT_SECONDS


def test_no_running_api_pod_exits_2(oc, tmp_path: Path) -> None:
    """Mutation: a worker or a pod not Running used as the API pod."""
    oc(FakeOc([_pod("worker-scenarios-7d9f-abc"), _pod("api-5c6b-old", phase="Pending")]))
    assert runner.main(["--namespace", "ai-threatgen"]) == 2
    assert not list(tmp_path.iterdir())


def test_a_failed_run_exits_2_saves_nothing_and_still_cleans_up(oc, tmp_path: Path) -> None:
    """Mutation: a failed report saved, or the pod's folder left behind."""
    fake = oc(FakeOc([_pod("api-5c6b-xyz")], fails="cd /app && PYTHONIOENCODING=utf-8 python"))
    assert runner.main([]) == 2
    assert not list(tmp_path.iterdir()) and fake.calls[-1][-1] == f"rm -rf {runner.FOLDER}"


def test_no_limit_stated_by_the_gateway_is_never_assumed(oc, tmp_path: Path, capsys) -> None:
    """The owner, 2026-10-30: the 25,000 is read from the gateway. When it states none, the run shows its
    answers and exits 2. Mutation: the reason dropped, or a report saved."""
    gateway = "kimi-k2.5 @ https://gw.test\n  headers no limit headers\n"
    no_limit = gateway + "The gateway named no tokens-a-minute limit (its answers are above)."
    oc(FakeOc([_pod("api-5c6b-xyz")], fails="PYTHONIOENCODING=utf-8 python", why=no_limit))
    assert runner.main([]) == 2
    said = capsys.readouterr().err
    assert gateway in said and "This runner never assumes a limit (no --budget)" in said
    assert not list(tmp_path.iterdir())
