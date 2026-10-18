"""The client scripts/e2e_all_api.py calls the API with: every answer is recorded (CALLED, FAILED), so the run
ends with each operation checked off. Split from that script (the file-size limit)."""

from __future__ import annotations

import sys
import uuid
from pathlib import Path
from typing import Any

import httpx

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from app.core.config import get_settings  # noqa: E402
from app.core.constants import Header  # noqa: E402

#: The status each operation last answered, by (method, OpenAPI path).
CALLED: dict[tuple[str, str], int] = {}
FAILED: list[str] = []


class Api:
    def __init__(self, base: str, identity: dict[str, str]) -> None:
        self.http = httpx.Client(base_url=base, timeout=httpx.Timeout(60, read=300))
        self.identity = identity  # X-User-Id, X-Entity-Id, X-Tenant-Id
        self.admin = {Header.ADMIN_KEY: get_settings().admin_api_key.get_secret_value()}
        self.key = ""
        self.intel_was_on = True  # the run-time intel switch before setup() turned it on: put back at the end

    def call(self, method: str, template: str, expect: tuple[int, ...] = (200,), **given: Any) -> Any:
        """One operation; its answer's JSON (None when it has none). An unexpected status is a failure.
        `given`: admin, idempotent, quiet (print failures only), body, params, then the path's ids."""
        admin, idempotent, quiet = (given.pop(flag, False) for flag in ("admin", "idempotent", "quiet"))
        body, params = given.pop("body", None), given.pop("params", None)
        path = template.format(**given)
        headers = {Header.USER_ID: self.identity[Header.USER_ID]}
        headers |= self.admin if admin else {**self.identity, Header.API_KEY: self.key}
        headers |= {Header.IDEMPOTENCY_KEY: uuid.uuid4().hex} if idempotent else {}
        response = self.http.request(method, path, json=body, params=params, headers=headers)
        CALLED[(method, template)] = response.status_code
        if response.status_code not in expect:
            FAILED.append(f"{method} {path}: {response.status_code} {response.text[:300]}")
            print(f"  BAD {response.status_code} {method:6} {path}\n      {response.text[:300]}")
        elif not quiet:
            print(f"  ok  {response.status_code} {method:6} {path}")
        try:
            return response.json()
        except ValueError:
            return None

    def first_event(self, template: str, **ids: str) -> None:
        """A live-status stream: its first event, then closed."""
        path, line, status = template.format(**ids), "", 0
        headers = {**self.identity, Header.API_KEY: self.key}
        try:
            with self.http.stream("GET", path, headers=headers, timeout=httpx.Timeout(30)) as response:
                status = response.status_code
                line = next((text for text in response.iter_lines() if text.startswith("data:")), "")
        except httpx.HTTPError as exc:
            line = f"stream error: {exc}"
        CALLED[("GET", template)] = status
        print(f"  {'ok ' if status == 200 else 'BAD'} {status} GET    {path}  {line[:120]}")
        if status != 200:
            FAILED.append(f"GET {path}: {status} {line}")
