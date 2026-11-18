# Spec: app/ under 20,000 lines, FastAPI layout (16 Nov 2026)

**Owner's goal:** "bring the codebase to less then 20K lines ... production ready clean clear KISS ... io optimized, no
functional or fundamental gap", the way FastAPI builds an API (ADR-004). Measured: `wc -l` of `app/**/*.py`.

## Where it stands
- Start 34,572. After the six parallel area rewrites (wave 1, merged, suite green except the old layer rules): 29,818.
- Wave 2 (small cuts, mypy merge fixes): about 29,400.
- Measured plan (eight area plans, each adversarially reviewed): A + kept B cuts reach about 25,200; with 120-column
  lines and no docstrings on private helpers about 23,300; under 20,000 also needs about 16 user-visible (C) cuts.

## Approach from here (owner, 16 Nov: "go ahead, one feature at a time")
One feature at a time in the main tree, all its layers in one change, the full suite after each:
1. library curation, 2. admin + API keys, 3. jobs + job monitor, 4. AI usage, 5. service mapper,
6. external intelligence, 7. remediation, 8. scenarios, 9. platform close-out (delete `container.py`, `services/`,
`data_access/`, empty `models/`), 10. style pass (120 columns, no private-helper docstrings), 11. C cuts the owner approves.

Each feature step:
- `api/routes/<feature>.py` (route names, docstrings, `summary=`, parameter order, `response_model`, status unchanged),
  `schemas/<feature>.py` (frozen models, `__module__` pins kept), `crud/<feature>.py` (plain functions),
  `domain/<feature>/` (logic as plain functions), worker tasks with explicit arguments;
- its service class, dependency-holding classes and container getters deleted; tests on `dependency_overrides` or
  monkeypatched module functions;
- the area plan's remaining A and kept B cuts (`scratchpad/areas/<area>.budget.json` minus the review's refutations).

## Gates per step
- Contract pins unchanged: `tests/contract/{openapi,ui_api_frozen,enums,tsg_names,celery,indexes}.json`.
- Prompt goldens and the remediation prompt pin pass (prompt text byte-identical).
- Full suite in six parallel shards, mypy (`tests/test_types.py`), ruff, `tests/test_code_conventions.py`.
- A line count after each step in `status.md`.

## Fixed
API paths/requests/responses/status (except ADR-005's `IntelSource` enum), prompts, stored fields, collection and index
names, Celery task names, sync routes on sync PyMongo/pyodbc, SQL Server only for stored procedures, every app record in
MongoDB, the reranker's cross-process cap of 8, the accepted risks. No commit without the owner's yes.
