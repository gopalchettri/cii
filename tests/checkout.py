"""One id per checkout of this repository, so two checkouts on one laptop never share, and wipe, each other's
test databases (2026-10-12: a run in cii-exteranl-intelligence-poc dropped this checkout's databases mid-run:
136 errors in one run, a failure with no visible cause in another). Standard library only: conftest reads it
before the app reads its settings."""

import hashlib
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CHECKOUT = hashlib.sha256(str(REPO).lower().encode()).hexdigest()[:8]
