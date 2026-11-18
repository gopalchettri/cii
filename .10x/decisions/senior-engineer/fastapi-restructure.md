# Senior engineer: approach per feature step (16 Nov 2026)

- One agent per feature in the main tree; one adversarial reviewer reads the diff for API, prompt, stored-data and
  behaviour changes before the suite runs.
- Move with `git mv`, then edit; keep route function names, docstrings, `summary=`, parameter order and response models
  so the OpenAPI text stays byte-identical; keep `__module__` pins on moved models.
- Logic imports crud *modules* (`from app.crud import jobs as job_crud`), never names, so tests can monkeypatch races.
- Tests: `app.dependency_overrides` for stores and settings; monkeypatch `send_job`/publishers; delete builder fakes
  that only fed the container.
- Verification: contract pins, goldens, mypy, ruff, conventions, then the full suite in six parallel shards.
