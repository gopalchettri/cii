# TSG: Threat Scenario Generator (cii)

TSG writes threat scenarios for a critical asset's risk register. It finds the library threats that fit the asset
and its supporting systems, writes each scenario with the AI, cites evidence from MITRE ATT&CK (Enterprise and ICS),
maps library controls, and writes remediation plans. A person accepts or rejects every result. It also runs the
service mapper. Stack: Python 3.12, FastAPI, Celery on Redis, MongoDB, SQL Server stored procedures.

Two ways to start a run, with the same request and the same answer:

- `POST /v1/sessions`: finds the threats in the threat library first, then writes the scenarios.
- `POST /v1/create_session`: the AI writes the scenarios from its MITRE ATT&CK knowledge, each with its attacker
  group, techniques and mitigations. TSG's own copy of MITRE ATT&CK confirms them; what it does not confirm is not
  shown. The controls still come only from the control library.

MITRE ATT&CK (Enterprise and ICS, no other source) is imported on a saved schedule: weekly on Sunday 02:00 UTC
until an admin changes it, and once right after the first start. The admin web page is served by the API at `/ui/`
(e.g. `http://localhost:8000/ui/`): import now, the schedule, the control links, jobs, API keys and more.

## Run it locally (Windows PowerShell 5.1)

MongoDB, SQL Server and Redis must already be running.

```powershell
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[local,dev]" -c requirements.txt
Copy-Item .env.dev.example .env   # then fill in the blank values
.\run.ps1                         # API, workers, beat and monitoring; waits for /ready
.\run.ps1 status
.\stop.ps1
```

Tests: `python -m pytest -q`.

## More

- `readme_to_run_uat.txt`: run TSG on the UAT Windows machine, step by step.
- `deploy/DEPLOYMENT_GUIDE.md`: deploy on OpenShift.
- `docs/SOLUTION_DESIGN.md`: what TSG does and why; `docs/TSG_END_TO_END_FLOW.md`: one session end to end.
- `docs/API_CONSUMER_GUIDE.md` and `docs/API_DEVELOPER_HANDBOOK.md`: the API.
