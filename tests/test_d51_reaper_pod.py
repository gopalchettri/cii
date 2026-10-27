"""The reaper and the controls sweep have a queue and a worker of their own: no long job takes a thread."""

import re
from pathlib import Path

from app.core.constants import TASK_ROUTES, TaskName
from app.worker.celery_app import queue_of

REPO = Path(__file__).resolve().parents[1]


def test_the_reaper_and_the_sweep_share_their_queue_with_no_long_job() -> None:
    """A library build or an intelligence refresh holds a thread for up to an hour: on the reaper's queue,
    with every thread busy, REAP passes waited past their expiry and were dropped."""
    reaper_queue = queue_of(TaskName.REAP)
    sharing = {task for task, route in TASK_ROUTES.items() if route["queue"] == reaper_queue}
    assert sharing == {TaskName.REAP, TaskName.RETRY_CONTROLS}


def test_the_laptop_serves_the_reapers_queue_with_a_worker_of_its_own() -> None:
    """run.ps1 starts one worker per -Q list: the reaper's queue is a list on its own."""
    workers = re.findall(r"'-Q', '([^']+)'", (REPO / "run.ps1").read_text(encoding="ascii"))
    assert queue_of(TaskName.REAP) in workers
