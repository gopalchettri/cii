"""A test module imported outside pytest's run (a probe script, a test file kept elsewhere) still reaches only the
test databases: its fixtures empty collections, and the live run's data was replaced by them (2026-11-17)."""

import json
import os
import subprocess
import sys

from tests.checkout import REPO


def test_importing_a_test_module_outside_the_tests_folder_names_the_test_databases() -> None:
    """No conftest is loaded for code outside tests/: the package itself sets the test databases."""
    env = {k: v for k, v in os.environ.items() if not k.startswith(("CII_MONGO_DB", "CII_REDIS", "PYTEST_"))}
    probe = (
        "import json, tests.test_attack_writer\n"
        "from app.core.config import get_settings\n"
        "s = get_settings()\n"
        "print(json.dumps([s.mongo_db, s.redis_url, s.redis_celery_broker_url]))\n"
    )
    done = subprocess.run(  # noqa: S603  # our own probe, in a fresh process with no conftest loaded
        [sys.executable, "-c", probe],
        cwd=REPO,  # where .env is, as a probe run from the repository
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert done.returncode == 0, done.stderr[-2000:]
    mongo_db, *redis_urls = json.loads(done.stdout.strip().splitlines()[-1])
    assert mongo_db.startswith("cii_tsg_test_")
    assert all(int(url.rsplit("/", 1)[1]) not in (0, 1) for url in redis_urls)  # never the laptop stack's
