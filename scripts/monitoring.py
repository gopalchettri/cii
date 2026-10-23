"""TSG monitoring on this laptop, no Docker, set up like UAT: the same files in observability/, the same
paths, no login.

    python scripts/monitoring.py install   download the tools once (~500 MB, each SHA-256 checked)
    python scripts/monitoring.py start     start them all (installs first when needed)
    python scripts/monitoring.py status    what is running
    python scripts/monitoring.py stop      stop them all

Then open http://localhost:3000/grafana/ — the TSG dashboard is the home page.
For logs in Grafana, run the API and the worker with CII_LOG_DIR=logs (docs/RUNNING.md).
Grafana's admin password (user admin, only needed to change Grafana): a GRAFANA_ADMIN_PASSWORD line in .env;
without one, a random one kept in grafana-admin-password.txt next to the tools.
Versions come from the `image:` lines of deploy/deploy_common.yaml, so the laptop runs what UAT runs.
"""

from __future__ import annotations

import ctypes
import http.client
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from collections.abc import Callable

from monitoring_commands import COMMANDS, reset_grafana_password
from monitoring_install import REPO, ROOT, install

#: Each program's health address, in start order (the path UAT's readinessProbe uses).
READY = {
    "loki": "http://127.0.0.1:3100/ready",
    "prometheus": "http://127.0.0.1:9090/prometheus/-/ready",
    "alertmanager": "http://127.0.0.1:9093/alertmanager/-/ready",
    "redis_exporter": "http://127.0.0.1:9121/health",
    "alloy": "http://127.0.0.1:12345/-/ready",
    "grafana": "http://127.0.0.1:3000/grafana/api/health",
    "flower": "http://127.0.0.1:5555/flower/healthcheck",
}
PORTS = (3000, 3100, 5555, 9090, 9093, 9121, 12345)


# ---------------------------------------------------------------- run
def _pids() -> dict[str, list[int]]:
    """{name: [process id, start time]} of what start() launched."""
    try:
        saved = json.loads((ROOT / "pids.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {name: entry for name, entry in saved.items() if isinstance(entry, list) and len(entry) == 2}


def _save_pids(started: dict[str, list[int]]) -> None:
    (ROOT / "pids.json").write_text(json.dumps(started), encoding="utf-8")


def _created_at(pid: int) -> int | None:
    """When the process with this id started (Windows FILETIME), or None when no process has the id. The id
    and the start time together name one process: an id Windows has given to another program starts later."""
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = kernel32.OpenProcess(_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        created, exited, kernel, user = (ctypes.c_ulonglong() for _ in range(4))  # FILETIME = 64-bit count
        times = (ctypes.byref(created), ctypes.byref(exited), ctypes.byref(kernel), ctypes.byref(user))
        return created.value if kernel32.GetProcessTimes(handle, *times) else None
    finally:
        kernel32.CloseHandle(handle)


_QUERY_LIMITED_INFORMATION = 0x1000  # the least access that can read a process's times


#: Local addresses only, never through a proxy: urlopen uses the Windows / environment proxy settings, and a
#: corporate proxy that does not skip 127.0.0.1 made every tool look "not started".
_LOCAL = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _ready(url: str) -> bool:
    try:
        with _LOCAL.open(url, timeout=2) as response:  # noqa: S310 — fixed local URLs
            return response.status < 500
    except (OSError, http.client.HTTPException):
        return False


def _port_busy(port: int) -> bool:
    with socket.socket() as probe:
        return probe.connect_ex(("127.0.0.1", port)) == 0


def _busy_ports_after(seconds: float) -> list[int]:
    """Ports still taken once the tools just stopped have let go: Windows frees a port a moment after
    taskkill, so an immediate check refused a restart with "ports in use" by our own stopped tools."""
    deadline = time.monotonic() + seconds
    while True:
        busy = [port for port in PORTS if _port_busy(port)]
        if not busy or time.monotonic() >= deadline:
            return busy
        time.sleep(0.5)


def stop(quiet: bool = False) -> int:
    """Stops what start() launched. A program that would not stop (taskkill: "Access is denied", when it was
    started from an administrator window) stays recorded, so the next stop tries again; the exit code is 1."""
    left: dict[str, list[int]] = {}
    for name, (pid, created) in _pids().items():
        # A recorded id may belong to another program by now (ours ended and Windows reused the id): only the
        # very process start() launched — same id AND same start time — is stopped.
        if _created_at(pid) != created:
            continue
        kill = ["taskkill", "/PID", str(pid), "/T", "/F"]
        result = subprocess.run(kill, capture_output=True, check=False)  # noqa: S603, S607 — fixed command, our pid
        if result.returncode != 0:
            left[name] = [pid, created]
        elif not quiet:
            print(f"  stopped {name}")
    if left:
        _save_pids(left)
        print(f"  could not stop {', '.join(left)}: end it in Task Manager (or from an administrator window)")
        return 1
    (ROOT / "pids.json").unlink(missing_ok=True)
    return 0


def status() -> int:
    for name, url in READY.items():
        print(f"  {name:15} {'ready' if _ready(url) else 'not answering':14} {url}")
    return 0


def _launch_all() -> None:
    """Every command is built (and every setting checked) before the first program starts, and each started
    program is saved at once: a failure part-way never leaves programs that stop() cannot find."""
    commands = {name: build() for name, build in COMMANDS.items()}
    detached = (
        subprocess.DETACHED_PROCESS  # type: ignore[attr-defined]
        | subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
        | subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
    )
    started: dict[str, list[int]] = {}
    for name, (command, extra_env) in commands.items():
        with open(ROOT / "logs" / f"{name}.log", "ab") as log:
            process = subprocess.Popen(  # noqa: S603 — our own installed programs
                command,
                cwd=str(REPO),
                env={**os.environ, **extra_env},
                stdout=log,
                stderr=subprocess.STDOUT,
                creationflags=detached,
            )
        created = _created_at(process.pid)
        if created is None:
            # Without its start time it could never be told apart from a later program with the same id, so
            # stop() would never stop it: stopped now instead of left running untracked.
            process.kill()
            raise SystemExit(f"{name}: Windows did not report its start time; see {ROOT / 'logs' / name}.log")
        started[name] = [process.pid, created]
        _save_pids(started)


def _not_ready_after(seconds: int) -> list[str]:
    waiting, deadline = dict(READY), time.monotonic() + seconds
    while waiting and time.monotonic() < deadline:
        waiting = {name: url for name, url in waiting.items() if not _ready(url)}
        time.sleep(2)
    return list(waiting)


def start() -> int:
    install()
    stop(quiet=True)
    busy = _busy_ports_after(5)
    if busy:
        raise SystemExit(
            f"ports in use by another program: {busy} (v1's monitoring uses the same: stop it first)"
        )
    for folder in ("logs", "data/grafana", "data/loki", "data/prometheus", "data/alertmanager", "data/alloy"):
        (ROOT / folder).mkdir(parents=True, exist_ok=True)  # Grafana does not create its own on Windows
    reset_grafana_password()
    _launch_all()
    failed = _not_ready_after(120)
    for name in failed:
        print(f"  {name} did not start: see {ROOT / 'logs' / (name + '.log')}")
    print(
        "\nOpen http://localhost:3000/grafana/  (no login; home = the TSG dashboard)\n"
        "Also: http://localhost:9090/prometheus/  http://localhost:9093/alertmanager/  http://localhost:5555/flower/"
    )
    return 1 if failed else 0


def _install() -> int:
    install()
    return 0


def main(argv: list[str]) -> int:
    # Every command returns the exit code: `install` alone returns nothing, so it is wrapped.
    commands: dict[str, Callable[[], int]] = {
        "install": _install,
        "start": start,
        "stop": stop,
        "status": status,
    }
    command = commands.get(argv[0] if argv else "")
    if command is None:
        print(__doc__)
        return 2
    return command()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
