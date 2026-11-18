"""One id per checkout of this repository, so two checkouts on one laptop never share, and wipe, each other's
test databases (2026-10-12: a run in cii-exteranl-intelligence-poc dropped this checkout's databases mid-run:
136 errors in one run, a failure with no visible cause in another). Standard library only: conftest reads it
before the app reads its settings."""

import hashlib
import os
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
#: A parallel run (pytest -n 6) names its workers gw0, gw1, ...: each gets its own databases.
WORKER = os.environ.get("PYTEST_XDIST_WORKER", "")
CHECKOUT = hashlib.sha256(str(REPO).lower().encode()).hexdigest()[:8] + (f"_{WORKER}" if WORKER else "")
