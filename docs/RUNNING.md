# How to configure and run TSG v2

This guide takes you from an empty machine to a running TSG v2 on your laptop (the **dev** environment), step by
step. Every step ends with a check, so you know it worked before you go on.

- What the parts are and why they exist: `docs/BLUEPRINT.md` (§3).
- Monitoring (Grafana, alerts, logs): see [Monitoring](#13-monitoring-grafana-alerts-logs).
- UAT and production (OpenShift): see [UAT and production](#14-uat-and-production) at the end.
- Step through the code with breakpoints: [DEBUGGING.md](DEBUGGING.md) — configure VS Code and debug the API, the
  live updates and the Celery jobs end to end, step by step.

Commands are for **Windows PowerShell**, run from the project folder (`cii\`) unless a step says otherwise.

---

## 1. What you will run

```
                 ┌──────────────── your laptop ────────────────┐
  you / Postman ─▶  API  (uvicorn, port 8000)                    │
  (HTTP, SSE)       │      │ sends jobs                          │
                    │      ▼                                     │
                    │  Redis ◀── Worker (celery, threads pool) ──┼──▶ AI models (Azure AI Foundry)
                    │      ▲        metrics on port 9100         │
                    │      └── Beat (celery beat: timers)        │
                    │                                            │
                    │  MongoDB (all TSG data)                    │
                    │  SQL Server (asset data + libraries,       │
                    │              stored procedures only)       │
                 └─────────────────────────────────────────────┘
```

| Part | What it does | You start it with |
|---|---|---|
| **API** | Answers HTTP requests, including the live-update streams (SSE) | `uvicorn app.main:app` (step 9) |
| **Worker** | Runs the slow background jobs (AI work, index builds) and the reaper (`app/worker/reaper.py`: every minute it re-sends a job whose worker died or whose message was lost) | `celery -A app.worker worker` (step 8) |
| **Beat** | A clock: sends the reaper every minute and the index warm-up every 30 minutes | `celery -A app.worker beat` (step 8) |
| **MongoDB** | Stores every TSG record (runs, scenarios, keys, AI call records, vectors) | already installed (step 3) |
| **Redis** | The job queues and live events | already installed (step 3) |
| **SQL Server** | The platform's asset data and the threat/control libraries | already installed (step 3) |
| **Monitoring** | Grafana (one page for alerts, numbers, logs and the audit trail), Prometheus, Alertmanager, Loki, Flower | `python scripts/monitoring.py start` (step 13) |

**Fastest way:** once steps 1–7 are done, `.\run.ps1` starts all of these and `.\stop.ps1` stops them again (see
[Quick start](#quick-start-one-script)).

**What works today.** The foundation is built: health checks, API keys, the AI gateway, the library cache, search,
the worker, live updates (SSE), monitoring and the audit trail of API keys. The scenario and remediation endpoints are not built yet (`docs/BLUEPRINT.md` §26 lists
the build order). This guide gets everything that exists running, so new code drops into a working system.

**How the code is organised.** The code in `app/` is organised in layer folders, one per box of the architecture
picture (`docs/BLUEPRINT.md` §3.1 and §5): `api/` (HTTP), `services/` (use cases), `engine/` (business steps),
`search/` (the library in memory), `ai/` (the AI models), `data_access/` (every database read or write), `models/`
(data shapes), `worker/` (background jobs), `realtime/` (live updates) and `core/` (settings, constants, errors).
Calls go one way, from the top down, and a test (`tests/test_code_conventions.py`, run in step 11) fails if a
lower layer imports a higher one. Example: `/ready` is answered by `app/api/routers/health.py`, which calls
`check_readiness` in `app/services/readiness.py`; if a file in `app/data_access/` imported `app.services`, the
tests would fail and name that file and line.

---

## 2. Before you start (prerequisites)

| You need | Version | Check it with |
|---|---|---|
| Python | 3.12 or newer | `py -3.12 --version` |
| MongoDB | 6.0 or newer, running as a service | `mongosh --eval "db.runCommand({ping: 1})"` → `{ ok: 1 }`; without `mongosh` (after step 4): `.venv\Scripts\python -c "from app.core.database import get_mongodb; print(get_mongodb().command('ping'))"` → `{'ok': 1.0}` |
| Redis | 6 or newer (on Windows: Memurai, or Redis in WSL/Docker) | `redis-cli ping` (Memurai: `memurai-cli ping`) → `PONG` |
| SQL Server | Express or Developer, with the `DevTest5` database | `sqlcmd -S localhost\SQLEXPRESS -E -Q "SELECT DB_ID('DevTest5')"` → a number, not NULL |
| Microsoft ODBC Driver for SQL Server | 17 or 18 | `Get-OdbcDriver -Name "ODBC Driver 1*"` lists it |
| `sqlcmd` | any | `sqlcmd -?` |
| AI access | an Azure AI Foundry resource with a chat model and an embedding model deployed, and its API key | the Foundry portal |
| Disk | about 2.5 GB for the local reranker model (step 5) | — |

---

## 3. Check the three databases are running

Run the three checks from the table above. All three must answer before you go on.

| Store | If the check fails |
|---|---|
| MongoDB | `Start-Service MongoDB` (the service name may differ: `Get-Service *mongo*`) |
| Redis | start Memurai (`Start-Service Memurai`) or your Redis container |
| SQL Server | `Start-Service 'MSSQL$SQLEXPRESS'` |

---

## 4. Install the code

1. Create a virtual environment (a private copy of Python for this project) and activate it:

   ```powershell
   py -3.12 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

   Your prompt now starts with `(.venv)`. Every later command assumes it is active.

2. Install the application with the exact tested versions:

   ```powershell
   python -m pip install --upgrade pip
   pip install -e ".[dev,local]" -c requirements.txt
   ```

   - `-e` = "editable": your code changes take effect without reinstalling.
   - `dev` = test and lint tools (pytest, ruff, mypy). `local` = the local reranker (dev only; never in UAT).
   - `-c requirements.txt` = use the versions the tests passed with, so everyone runs the same code.

**Check:** `pip show cii-tsg` shows the package with `Location` in your project folder.

---

## 5. Get the AI models ready

TSG v2 uses three kinds of model. Each model name you configure must have a **profile** in
`app/ai/profiles.py` (its token limit, timeout, vector size …; the fields a profile has are defined in
`app/models/ai.py`). A name without a profile stops the start-up with a clear message — that is on purpose.

| Kind | Dev model (name to put in `.env`) | Where it runs |
|---|---|---|
| Chat | `openai/Kimi-K2.6` | Azure AI Foundry |
| Embedding | `openai/text-embedding-3-large` | Azure AI Foundry |
| Rerank | a folder path ending in `bge-reranker-v2-m3` | on your laptop (CPU) |

1. **Chat and embedding:** in the Foundry portal, copy the resource endpoint (it looks like
   `https://<resource>.services.ai.azure.com/openai/v1`) and an API key.
2. **Reranker (local):** download the model once:

   ```powershell
   huggingface-cli download BAAI/bge-reranker-v2-m3 --local-dir C:\models\bge-reranker-v2-m3
   ```

   The folder name must stay `bge-reranker-v2-m3` (that is how its profile is found).

**Check:** `Test-Path C:\models\bge-reranker-v2-m3\config.json` → `True`.

---

## 6. Create your `.env` file

All settings come from environment variables; most start with `CII_` (the owner's own run settings, such as
`TOTAL_SCENARIO_COUNT`, do not). On your laptop they live in a file named `.env` in the project folder. It is
git-ignored: **secrets never go into the repository**.

1. Copy the example: `Copy-Item .env.example .env`
2. Open `.env` and fill in each line:

| Variable | What to put | Example (dev) |
|---|---|---|
| `CII_ENV` | `dev`, `uat` or `prod`. **Required on a laptop: `dev`** (`.env.example` already has `CII_ENV=dev`). A missing line counts as `prod`, so the UAT/production checks apply: start-up stops when `CII_CORS_ORIGINS` is `*` or the admin key is shorter than 32 characters | `dev` |
| `CII_LOG_LEVEL` | `DEBUG`, `INFO`, `WARNING` or `ERROR` (a typo stops start-up). It decides the level for the API, the worker and beat | `INFO` |
| `CII_CORS_ORIGINS` | browser origins allowed to call, comma-separated; empty = none | `*` on a laptop only (UAT/prod refuse `*` at start-up) |
| `CII_DB_DSN` | SQL Server connection | `mssql+pyodbc://@localhost\SQLEXPRESS/DevTest5?driver=ODBC+Driver+17+for+SQL+Server&Trusted_Connection=yes&TrustServerCertificate=no` |
| `CII_MONGO_URL` | MongoDB connection | `mongodb://localhost:27017` |
| `CII_MONGO_DB` | database name for TSG data | `cii_tsg` |
| `CII_REDIS_URL` | Redis for live events and caches (database 0) | `redis://:@127.0.0.1:6379/0` |
| `CII_REDIS_CELERY_BROKER_URL` | Redis for the job queues (database 1) | `redis://:@127.0.0.1:6379/1` |
| `CII_CHAT_BASE_URL`, `CII_CHAT_API_KEY` | Foundry endpoint and key (step 5) | `https://<resource>.services.ai.azure.com/openai/v1` |
| `CII_CHAT_MODEL` | chat model name with a profile | `openai/Kimi-K2.6` |
| `CII_CHAT_FALLBACK_MODEL` | second chat model, used only when the first is down; may stay empty | *(empty)* |
| `CII_EMBEDDING_BASE_URL`, `CII_EMBEDDING_API_KEY` | Foundry endpoint and key | same as chat |
| `CII_EMBEDDING_MODEL` | embedding model name with a profile | `openai/text-embedding-3-large` |
| `CII_RERANK_BASE_URL`, `CII_RERANK_API_KEY` | **leave empty** on a laptop = use the local model | *(empty)* |
| `CII_RERANK_MODEL` | the folder from step 5 | `C:/models/bge-reranker-v2-m3` |
| `CII_AI_KEY_HEADER` | a header name, when the AI gateway also wants the key there (UAT: `x-litellm-api-key`). The key then goes in this header and in the normal `Authorization` header. Empty = no extra header | *(empty)* |
| `CII_ADMIN_API_KEY` | a long random secret for the admin endpoints (UAT/prod: at least 32 characters); empty = admin endpoints refuse every call | make one with `python -c "import secrets; print(secrets.token_urlsafe(32))"` |
| `CII_WORKER_METRICS_PORT` | port where a worker shows its metrics (optional) | `9100` |
| `CII_LOG_DIR` | laptop only: also write the log lines to `<folder>\api.log` and one file per worker, `worker-<name>.log` (the name from `-n`, e.g. `worker-dev.log`), so Grafana can show them (step 13); empty = console only (see the note on empty values below). A folder that cannot be written stops the worker | `logs` |
| `CII_MAX_REQUEST_MB` | the largest request body in MB, for every request whatever its type; a bigger one is refused with 413 | `2` |
| `CII_MAX_CONCURRENT_AI_CALLS` | the most AI calls at once across every API and worker process together; `0` = no limit. Not used yet: the AI-call limiter (blueprint M04 A2) is not built yet | `16` (v1's value) |
| `DEBUG_STEP_OUTPUT` | the owner's name, no `CII_` prefix. `true` = every step of a run writes its inputs, results and time to the log (secrets hidden), to follow a run step by step; `false` = only the normal logs. Needs `CII_LOG_LEVEL` `INFO` or `DEBUG` | `false` |
| `DEBUG_STEP_DETAIL` | the owner's name, no `CII_` prefix. `true` = each traced step also writes its inner sub-steps (BM25, similarity, merges, ranking) to the log; only when `DEBUG_STEP_OUTPUT` is `true` | `false` |
| `DEBUG_STEP_TOP` | the owner's name, no `CII_` prefix. How many entries a ranked inner record keeps (best first). A whole number, 1 to 40 | `10` |
| `TOTAL_SCENARIO_COUNT` | the owner's name, no `CII_` prefix. How many scenarios a run may have in total: `0` = one for every valid attack path found; a number N = only the N most relevant. Never padded with made-up ones. A whole number, 0 or more | `0` |
| `INITIAL_SET_SIZE` | the owner's name. How many scenarios are written right after planning, so a reviewer can start reading. Nothing more is written until someone asks for the next set. A whole number, 1 or more | `6` |
| `NEXT_SET_SIZE` | the owner's name. How many more scenarios each "next set" request writes. A batch for reviewing, not a limit: the total still comes from `TOTAL_SCENARIO_COUNT` (for example 18 → 6, then 6, then 6). A whole number, 1 or more | `6` |
| `ASSET_PROPERTIES_REQUIRED` | the owner's name. Asset facts that must be recorded before a run can start: column names of `tsg_GetAssetContext`, comma-separated (for example `location,operating_system`); a start without one is refused with 422 `required_facts_missing`, naming what is missing. Empty = none | *(empty)* |
| `SYSTEM_PROPERTIES_REQUIRED` | the same as `ASSET_PROPERTIES_REQUIRED`, for every supporting system sent (for example `technology_used`) | *(empty)* |
| `CONTROL_SIMILARITY_THRESHOLD` | the owner's name. 0–100: a control is kept for a scenario as "strong" when the reranker scores it this high or higher (50 = the owner's 0.50; writing 0.5 stops start-up). Higher = fewer, closer controls; lower = more | `50` |
| `CONTROL_CANDIDATES` | G227: library controls found and scored for one scenario; at least `MAX_CONTROLS`. Fewer = faster mapping on a laptop CPU reranker | `40` |
| `EVIDENCE_SEARCH_RETRIES` | G229: with external intelligence on, how many more searches (other words, no AI) a threat gets when the first found no usable source; still none → that scenario fails with its reason and a reserve may take its place. 0 to 2 | `1` |
| `THREAT_CONTEXT_COUNTRY` | G232: the country the assets are in, "UAE" or "United Arab Emirates". With external intelligence on, the real attacker groups on a card are ranked (attacked this country, then its region, then your sector) and each source is labelled this country / regional / global | `United Arab Emirates` |
| `NEAR_COPY_TEXT_SIMILARITY` / `NEAR_COPY_PART_SIMILARITY` | G229: how alike (0-100) a new scenario's text and its parts (mechanism, consequence) must be to a finished one of the same run to count as a near copy; a copy is hidden and replaced. Higher = fewer flagged | `30` / `50` |
| `MIN_CONTROLS` / `MAX_CONTROLS` | G225: a scenario's controls, at least / at most | `1` / `10` |
| `THREAT_SCENARIO_WORD_LIMIT` / `RISK_STATEMENT_WORD_LIMIT` | G226: min-max words, both writers | `300-400` / `150-200` |
| `THREAT_SIMILARITY_THRESHOLD` | the owner's name. 0–100: an AI-proposed threat this similar to a library threat IS that threat (dropped as a repeat), and takes a library type this similar. Higher = more AI threats stay new proposals; lower = more are matched to the library | `75` |
| `ACTOR_SIMILARITY_THRESHOLD` | the owner's name. 0–100: when a threat's type links no attacker, only attackers scored this high or higher are offered; `0` = no filter. If none reaches it, the closest still acts, flagged. Linked attackers are never filtered | `0` |
| `GRAFANA_ADMIN_PASSWORD` | Grafana's admin password, needed only to change Grafana (looking needs no login). No `CII_` prefix: the monitoring scripts read it, not the app. Optional on a laptop: empty or no line = a random one. UAT (`.env.uat`): needed to deploy monitoring, 16 or more characters | a password you choose |
| `GF_…` (optional; `.env.example` has 12) | Grafana's own settings, read by the monitoring scripts (step 13.1): who can see and edit, reporting and calls to the internet, look and defaults. List only the ones you set: a missing line means Grafana's own default, named in the `.env.example` comment above each line. Copy the 12 to get the setup step 13 describes | `GF_USERS_DEFAULT_THEME=dark` |

Notes:
- **ODBC Driver 18** encrypts by default. If you have 18 instead of 17, use `driver=ODBC+Driver+18+for+SQL+Server`
  and, on a laptop only, add `&TrustServerCertificate=yes`.
- **Redis with a password:** `redis://:<password>@127.0.0.1:6379/0`.
- **Never run v1 and v2 at the same time.** Both versions name their Redis keys `tsg:…`, and on this laptop they share
  databases 0 and 1 (owner, 2026-10-09). Stop v1 first (its own `stop.ps1`); `.\run.ps1` refuses to start v2 while
  v1's worker or beat runs. In UAT, v2 takes databases 0 and 1 once v1 is stopped (step 14).
- **Behind a proxy?** If your laptop has a proxy set, add `NO_PROXY=llmapi.govai.ae` so the AI calls go direct
  (that is what v1's `LITELLM_BYPASS_PROXY=true` does). v2 needs nothing else.
- Business values (batch sizes, timeouts, retries) are **not** in `.env`; they are constants in
  `app/core/constants/` (one file per topic). Only the two limits in the table (`CII_MAX_REQUEST_MB` and
  `CII_MAX_CONCURRENT_AI_CALLS`) are settings, because they differ per environment (owner, 2026-10-09), and the
  owner's run settings (`TOTAL_SCENARIO_COUNT`, `INITIAL_SET_SIZE`, `NEXT_SET_SIZE`, the two required-fact lists
  and the three similarity thresholds).
- **Which facts a run uses** (owner, 2026-10-11): every column `tsg_GetAssetContext` returns for the asset and its
  systems (step 7.1). The required lists name columns of that procedure; today the asset's are
  `cii_asset_description`, `critical_service`, `sector`, `sub_sector`, `data_handled`, `asset_type`,
  `operating_system`, `location`, `target_rto_hours`, `target_rpo_hours`, `asset_priority`,
  `entity_technology_context`, and a system's are `category_name` and the 29 system facts (for example
  `technology_used`, `vendor_name`, `hosting_location`, `backup_tested`, `rto_target_mins`). `id`, `name`,
  `category_code` and `alias` are always used and cannot be listed (start-up stops). A name the procedure does not
  return refuses every run with 500 `setup_error` naming it. "Recorded" means the AI would see it: `0` and "No"
  count; empty, "N/A", "none" or an unanswered choice do not. Requiring `sector` means every start must send a
  `sector_id`. A change to a list takes effect on the next restart.
- **An empty value means the default.** A line left empty (`CII_LOG_DIR=`) counts as not set, so the app uses the
  default in `app/core/config.py` (for `CII_LOG_DIR`: console only). An environment variable set to an empty value is
  ignored too, so it does **not** override `.env`. Example: `$env:CII_LOG_DIR=""` in a window still leaves the
  `CII_LOG_DIR=logs` line of `.env` in force; change `.env` instead. Pods (UAT, production) have no `.env` file, so
  there an empty value always means the default.
- **Keep every app setting, add no other (Grafana lines are optional).** `.env` holds exactly the settings the app reads
  (`Settings` in `app/core/config.py`) plus, if you want them, `GRAFANA_ADMIN_PASSWORD` and Grafana's `GF_`
  lines (step 13.1): every app setting with its value, even when that equals the default, and an empty value where
  it does not apply (e.g. `CII_RERANK_BASE_URL=` on a laptop). A test
  (`tests/test_config.py::test_env_files_match_settings`, step 11) compares the key names — never the values — of
  `.env`, `.env.uat` and `.env.example` with the settings, and names any line that is missing or not read. Example:
  a line `CII_PUBLIC_URL=…` copied from v1 fails it (v2 never reads it; it was removed from the laptop `.env` on
  2026-10-09, together with `CII_REDIS_CELERY_RESULT_BACKEND_URL`). The Grafana lines are optional (owner,
  2026-10-09): list only the ones you set; a missing line means Grafana's own default.

**Check:**

```powershell
python -c "from app.core.config import get_settings; s = get_settings(); print(s.env, s.chat_model, s.mongo_db)"
```

prints `dev openai/Kimi-K2.6 cii_tsg`. An error names the missing or wrong variable.

---

## 7. Install the stored procedures in SQL Server

TSG reads SQL Server only through its own stored procedures (the files in `scripts/sql/`). Install them once, and
again whenever one of these files changes.

```powershell
Get-ChildItem scripts\sql\*.sql | ForEach-Object {
    sqlcmd -S localhost\SQLEXPRESS -d DevTest5 -E -I -b -i $_.FullName
}
```

- `-E` = log in with your Windows account. `-I` = `QUOTED_IDENTIFIER ON` (the procedures need it).
  `-b` = stop with an error code if a script fails.
- Each file is `CREATE OR ALTER`, so running it again is safe.

**Check:** `sqlcmd -S localhost\SQLEXPRESS -d DevTest5 -E -Q "EXEC dbo.tsg_GetLibraryStamp"` prints 7 lines, one per
library table TSG reads (the 6 threat tables and `Control_Library`), each with a long hexadecimal fingerprint.
`Control_Standard` and `Control_Library_Standard_Map` are not read (owner, 2026-10-09). `Control_Library` must have
the column `AssetType` (the owner renamed `ITOT`); with the old name the install fails with "Invalid column name".
`Threat_Catalogue` must have the column `AssetType` too (G211: `IT`, `OT` or `IT\OT`; empty = fits everywhere)
before `tsg_GetThreatLibrary` is installed; until the new procedure is installed the app logs
`library.threat_asset_type_missing` and treats every threat as untyped.

### 7.1 Choose which asset and system facts a run uses

`scripts/sql/tsg_GetAssetContext.sql` decides (owner, 2026-10-11). Its header says how; its parts are marked:

| Part | What it does | Edit? |
|---|---|---|
| PART 0 LOOKUPS | works out the service, sector and organisation values PART 1 uses | DO NOT EDIT |
| PART 1 ASSET FACTS | one line per asset fact | **SHOW / HIDE HERE** |
| PART 2 SERVICES, PART 3 SECTOR | check the request (404, 422) | DO NOT EDIT |
| PART 4 SUPPORTING SYSTEM FACTS | one line per system fact | **SHOW / HIDE HERE** |
| PART 5 DROPDOWN NAMES | lets the app turn saved dropdown values into names | DO NOT EDIT |

Every line of PART 1 and PART 4 is a fact every step uses: threat finding, writing, controls, remediation. The name
after `AS` is the name the AI sees and the name the required lists use. Each line starts with a comma and has a
plain-English comment saying what the fact is.

- **Hide a fact:** put `--` at the start of its line, e.g. `--, e.location` in PART 1, then install the file again
  (the command above, or just this file:
  `sqlcmd -S localhost\SQLEXPRESS -d DevTest5 -E -I -b -i scripts\sql\tsg_GetAssetContext.sql`). From the next
  run on, no asset's location is used anywhere. Runs already started keep what they froze. **Show it again:**
  remove the `--` and install.
- **Use a new fact:** add a line, e.g. `, ss.recovery_notes` in PART 4, and install. From the next run on, every
  system's recovery notes reach the AI. No app change and no restart.
- **A dropdown column** must return the option's name, not the number saved: the platform saves the option's
  `value` (1, 2, 3 ...), so match `dbo.option_value` on `value` and the option code (the file's RULES show the
  line). The columns the app already translates (marked "dropdown") keep returning the saved number; `priority`
  is the one saved by the option's id, because its values repeat.
- **Never hide** `id`, `name` and `category_code` (marked ALWAYS NEEDED): without them every run stops with 500 `setup_error`
  ("dbo.tsg_GetAssetContext must return id, name, category_code ...").
- **Keep `entity_technology_context` last** in the asset `SELECT`: a long asset text is shortened from its end.
- **Reserved names:** never call a fact `alias`, `criticality` or `*_id` (`category_id`, `type_id`, ...):
  no prompt shows them, so a run stops with "reserved names". Rename with `AS`, e.g. `AS asset_criticality`.
- **Names are required:** a run on an asset or system with no name is refused (422).
- **Whoever edits this file decides what reaches the AI:** a sensitive column added here is sent to it.
- Before a run requires a fact (`ASSET_PROPERTIES_REQUIRED`), make sure the procedure returns that column.

### 7.2 Curator and embeddings calls (admin key)

Threats a person promotes (#27) or a hand-written scenario adds (#11) wait as **pending** until a curator
decides. Approved ones go live in every run within a minute; their vectors come with the next embeddings
build (every 30 minutes, or now with `POST /v1/embeddings`).

```powershell
$h = @{ "X-Admin-Key" = "<CII_ADMIN_API_KEY>"; "X-User-Id" = "curator-1" }
Invoke-RestMethod http://localhost:8000/v1/tsg/library/pending -Headers $h
Invoke-RestMethod http://localhost:8000/v1/tsg/library/decisions -Method Post -Headers $h `
    -ContentType application/json -Body '{"approve": [512], "reject": [513]}'
Invoke-RestMethod http://localhost:8000/v1/embeddings -Method Post -Headers $h
Invoke-RestMethod http://localhost:8000/v1/embeddings/<job_id> -Headers $h
```

- Each id gets one outcome: `approved`, `rejected`, `already_approved`, `already_rejected`, `is_approved`
  (a live threat asked to be rejected: nothing changed) or `not_found`. Sending the same call again is safe.
- At most 100 ids per call, each once, in one list only (else 422).
- One embeddings build at a time: a second one answers 409 with the running build's `job_id`.

---

## Quick start: one script

Once steps 1–7 are done, one command runs everything and one stops it. Use **Windows PowerShell** (5.1), not
PowerShell 7: there the scripts stop at once ("…contained a "#requires" statement for PowerShell editions
'Desktop'"), because under PowerShell 7 `stop.ps1` would find no window to stop.

```powershell
.\run.ps1          # start: API, the two workers, beat, monitoring; then opens Grafana
.\run.ps1 status   # what runs, and what /ready says
.\stop.ps1         # stop everything run.ps1 started (same as .\run.ps1 stop)
```

What `.\run.ps1` does, in order:

1. **Checks first; nothing starts if one fails.** It says what is wrong:
   - MongoDB, SQL Server and Redis must answer. These are the same checks `/ready` runs. Example: "Not
     reachable: redis" when the Redis (Memurai) service is stopped. Start it in an administrator PowerShell
     with `Start-Service Memurai`.
   - Ports 8000, 9100 and 9102 must be free (the API, the job worker's and the maintenance worker's metrics).
   - v1's worker or beat must not be running. v1 and v2 share Redis databases 0 and 1 on this laptop.
   - It must not already be running.
2. **Opens four windows,** titled **TSG api**, **TSG worker**, **TSG maintenance** and **TSG beat**, with the commands of steps 8 and
   9. A window stays open if its program stops, so you can read the error. Each window is noted in
   `.run\processes.json`, so `stop` closes exactly these.
3. **Starts the monitoring tools** (`scripts\monitoring.py start`, step 13). The first time, this downloads them.
4. **Waits for `/ready`** (up to 90 s) and prints its answer.
5. **Opens Grafana** at `http://localhost:3000/grafana/`, the TSG dashboard. It prints the other addresses too.

`.\stop.ps1` (or `.\run.ps1 stop`) works in this order:
- It asks the worker to finish its running jobs first (up to 60 s, `-DrainSeconds`). Why: a killed worker's
  job stays "running" until its lease runs out, about 2 minutes.
- It closes the three windows.
- It stops the monitoring tools.

Both end with exit code 1 when something could not be stopped. They name it: close it by hand (or in Task Manager),
then run `.\stop.ps1` again. `.\run.ps1` ends with exit code 1 when `/ready` is not 200, when the monitoring tools did
not start, or when the program in a window has already ended (it names the window to read; `/ready` does not cover
beat). So a script or CI step sees the failure, not only the warning.

A window started from an administrator window hides its start time from a normal one, so the script cannot tell it
from another program that got the same id. It then stops with "Cannot check window N: it runs as administrator. Run
this from an administrator window." Do that. (Before, `stop` treated such a window as gone and forgot it while it
kept running.)

`.\run.ps1` reads `.env` the way the app does: quotes are removed, an unquoted value ends at a space followed by `#`
(so a password may contain `#`), and when a key has two lines the last one wins.

Two options:
- `-Reload`: the API restarts when you save a code file.
- `-NoBrowser`: do not open Grafana.

Steps 8, 9 and 13 below are the same thing done by hand.

---

## 8. Start the worker and the clock (beat)

Open **three** new PowerShell windows in the project folder and activate the environment in each
(`.\.venv\Scripts\Activate.ps1`).

**Window 1 — the job worker** (threat finding, writing, control mapping):

```powershell
celery -A app.worker worker --pool=threads -c 10 -Q tsg_threats,tsg_scenarios -n dev@%h --loglevel=INFO
```

**Window 2 — the maintenance worker** (the reaper that re-sends lost jobs, and the controls sweep). It has its
own 3 threads so it never waits behind long jobs (G198: with one shared worker, ten stuck mappings held every
thread and a lost job was never re-sent). Its metrics go on port 9102 (9100 is the job worker's, 9101 the VS Code
debug worker's):

```powershell
$env:CII_WORKER_METRICS_PORT = '9102'; celery -A app.worker worker --pool=threads -c 3 -Q tsg_maintenance -n maint@%h --loglevel=INFO
```

- `--pool=threads` is required. Any other pool (prefork, gevent) is refused at start-up on purpose. The one
  exception is `--pool=solo` (one job at a time), accepted for debugging: the VS Code "Debug worker" uses it
  ([DEBUGGING.md](DEBUGGING.md), Part 1 step 4).
- `-c 10` = up to 10 jobs at once. `-n dev@%h` = this worker's name (with `CII_LOG_DIR` set, its log file is
  `worker-dev.log`).
- `CII_LOG_LEVEL` in `.env` decides what the worker and beat log; `--loglevel` does not change it.
- When it is ready you see `celery@… ready.` and the three queues listed. Its metrics are on
  `http://localhost:9100/metrics`.

**Window 3 — beat** (the timer that sends the reaper every minute and the index warm-up every 30 minutes):

```powershell
celery -A app.worker beat --loglevel=INFO
```

Run exactly **one** beat. It keeps its timetable in a file `celerybeat-schedule` (git-ignored).

The reaper's code is in `app/worker/reaper.py`; the worker runs it each time beat asks. Example: you force-stop
the worker (`Ctrl+C` twice) in the middle of a job. About two minutes later the job's lease runs out; at the next
minute the reaper puts the job back in the queue (or fails it after 5 tries), and the worker picks it up again once
you restart it.

**Check:** within 20 seconds the worker has announced itself:

```powershell
python -c "from app.worker.heartbeat import count_online_workers; from app.worker import ROUTED_QUEUES; print(count_online_workers(ROUTED_QUEUES))"
```

prints a count of at least 1 for each of `tsg_maintenance`, `tsg_scenarios` and `tsg_threats`.

---

## 9. Start the API

Window 3:

```powershell
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

- `127.0.0.1`: only this PC can call it (the same as `run.ps1`).
- To restart the API by itself when you save a code file, use `.\run.ps1 -Reload` (it runs the API under
  `watchfiles`). uvicorn's own `--reload` did not survive a restart on this laptop, so it is not used.
- To stop at breakpoints, run it from VS Code instead ("Debug API", [DEBUGGING.md](DEBUGGING.md), Part 3).
- At start-up the API creates its MongoDB indexes (API keys, and the audit trail with its 365-day expiry) and
  checks that every configured AI model has a profile. If either fails, the API does not start and says why.

**Check** (in a browser or another window):

| Open | You should see |
|---|---|
| `http://localhost:8000/health` | `{"status": "ok"}` — the process is alive (it answers at once, even while a store hangs) |
| `http://localhost:8000/ready` | **200** with every store `true` and a worker count ≥ 1 per queue |
| `http://localhost:8000/docs` | the interactive API documentation |
| `http://localhost:8000/metrics` | Prometheus metrics text |

`/ready` answers **503** when any database is down **or** a queue has no worker. The body says which one, for
example `"workers": {"tsg_scenarios": 0, …}` — start the worker (step 8) and try again. `/ready` and `/metrics`
reuse a check that is less than 2 seconds old, so a fix can take 2 seconds to show.

---

## 10. Make your first calls

### 10.1 Create an API key (admin)

Business endpoints need an API key. Create one with your admin key:

```powershell
$admin = @{ "X-Admin-Key" = "<your CII_ADMIN_API_KEY>" }
Invoke-RestMethod -Method Post -Uri http://localhost:8000/v1/tsg/api-clients -Headers $admin `
    -ContentType "application/json" -Body '{"name": "my-laptop", "description": "local testing"}'
```

The answer contains `api_key` (it starts with `tsg_`). **It is shown only once** — copy it now. Only its hash is
stored, so it cannot be recovered; if you lose it, revoke it and create another.

Other admin calls:
- List keys: `Invoke-RestMethod -Uri http://localhost:8000/v1/tsg/api-clients -Headers $admin`
- Revoke: `Invoke-RestMethod -Method Post -Uri http://localhost:8000/v1/tsg/api-clients/<client_id>/revoke -Headers $admin`
  (every API process refuses the key within 60 seconds).

### 10.2 Call a business endpoint

Every business call sends four headers:

| Header | Meaning | Example |
|---|---|---|
| `X-API-Key` | the key from 10.1 | `tsg_Q2…` |
| `X-User-Id` | who is acting (at most 256 characters) | `gopal` |
| `X-Entity-Id` | which organisation (whole number from 1 to 2,147,483,647); you only ever see this entity's records | `86` |
| `X-Tenant-Id` | the tenant (recorded, not used to filter; at most 256 characters) | `shield` |

A longer `X-User-Id` or `X-Tenant-Id` is refused with **422** before anything is stored or logged (an e-mail
address has at most 254 characters). The same limit applies to `X-User-Id` on admin calls.

**Size limits.** Every request body may be at most **2 MB** (`CII_MAX_REQUEST_MB`, a setting in `.env`, step 6),
whatever its type; a larger body is refused with **413**. Why one small limit: the API reads a body before it checks
your key, so one huge body from anyone would pause every open live-update stream for a moment. The limit never
depends on the `Content-Type` header, because the caller chooses that label (owner, 2026-10-09). No endpoint takes
file uploads; one that does later gets its own limit by its address. Today's largest JSON body is a few hundred
bytes, so 2 MB is far more than enough. An id larger than 2,147,483,647 (the
largest number SQL Server's INT holds), in `X-Entity-Id` or in a body, is refused with **422**.

Every answer carries an `X-Request-Id` header. Quote it when you report a problem: it finds every log line of that
request.

### 10.3 Watch a run live (Server-Sent Events)

Live updates are a normal HTTP `GET` that stays open: the server keeps sending events (SSE). Send the same four
headers as any other call. The first event is the run's current status; after that, one event arrives each time
the run changes, and a `: ping` line arrives every 15 seconds of silence so the connection stays open.

```powershell
curl.exe -N http://localhost:8000/v1/sessions/<run id>/events `
  -H "X-API-Key: tsg_…" -H "X-User-Id: gopal" -H "X-Entity-Id: 86" -H "X-Tenant-Id: shield"
```

You see:

```
event: session.updated
data: {"session_id": "…", "session_status": "active", "progress": {"threats": "RUNNING", …}, …}
retry: 3000
```

- `-N` turns off curl's buffering so events appear as they arrive. Stop with `Ctrl+C`.
- A wrong key → 401; another entity's run → 403; an unknown run → 404 — all before any event is sent.
- If the connection drops, open it again: the first event is always the current status, so nothing is lost.
- A browser's `EventSource` cannot send these headers, and the key must never reach a browser. So the platform
  server opens the stream and passes the events on to its page (owner decision, 2026-10-08).
- A run that is deleted sends one `event: session.deleted` and the stream ends.

### 10.4 Review, cancel and delete your work

Your normal key and headers; you only ever see and touch your own entity's runs.

**What is waiting or working?**

```powershell
curl.exe http://localhost:8000/v1/jobs -H "X-API-Key: tsg_…" -H "X-User-Id: gopal" -H "X-Entity-Id: 86" -H "X-Tenant-Id: shield"
```

Each line says what it is (`threats`, `scenarios`, `controls` or `remediation`), its run and asset, its status
(`queued` or `running`), since when, and how far it is (for example 6 of 16 scenarios written).

**Stop a run now** (what is written stays; its AI calls stop within 30 seconds; a later next set or
regenerate carries on from there, and when no set is left a next set restarts only its controls matching):

```powershell
curl.exe -X POST http://localhost:8000/v1/sessions/<run id>/cancel -H "X-API-Key: tsg_…" -H "X-User-Id: gopal" -H "X-Entity-Id: 86" -H "X-Tenant-Id: shield"
```

A remediation plan being written: `POST /v1/remediation/<plan id>/cancel`. Nothing left to stop → 409
`nothing_to_cancel`.

**Remove a run for good** (with its scenarios and plans; this cannot be undone):

```powershell
curl.exe -X DELETE http://localhost:8000/v1/sessions/<run id> -H "X-API-Key: tsg_…" -H "X-User-Id: gopal" -H "X-Entity-Id: 86" -H "X-Tenant-Id: shield"
```

Still working → 409 `cancel_first`: cancel it, then delete. Both are written to the audit log (who and when).

---

## External intelligence: runbook (Built 2026-10-12)

Dev has it on (`EXTERNAL_INTELLIGENCE_ENABLED=true` in `.env`; the code default is OFF, so an environment that forgets the line stays the original TSG); UAT has it on too since 2026-10-13 (owner), with the provisional, not calibrated cut-off 50 (`docs/EXTERNAL_INTELLIGENCE.md`, section 6).

- **First refresh.** Set `EXTERNAL_INTELLIGENCE_ENABLED=true`, restart API and worker, then (admin key)
  `POST /v1/tsg/intel/refresh`, read `GET /v1/tsg/intel/refresh/{job_id}` until `done`, then
  `GET /v1/tsg/intel/health` until `snapshot_id` is set. After that the sources refresh hourly when due.
- **Switch.** `GET /v1/tsg/intel/switch`; `PUT /v1/tsg/intel/switch` with `{"enabled": false}` turns the feature off at once
  (the next batch is written by the original writer); `true` turns it on again and queues a refresh. Off does not delete data.
- **Health.** `GET /v1/tsg/intel/health`: each source's status and last error, the snapshot, `stale`, and the
  `evidence` block (reranker name, threshold, `threshold_calibrated`). `threshold_calibrated: false` means the threshold was not
  calibrated on that reranker: run `scripts\calibrate_evidence_threshold.py` first.
- **Revoke a source.** When Legal withdraws a source an admin calls `POST /v1/tsg/intel/sources/{source}/revoke`: audited
  first, then the source is unapproved and its records and vectors are purged; the next snapshot no longer holds it. With
  the master switch OFF it only deletes what exists. Evidence already written onto scenarios and plans is NOT removed:
  delete or regenerate those if Legal requires it. `POST /v1/tsg/intel/sources/{source}/approve` brings the source back
  (master switch ON only) and queues its refresh.
- **A feed that looks cut short.** A source that suddenly delivers under half of its records shows `failed` ("looks cut
  short") and keeps its data. If the drop is real, revoke and approve the source again to reload it. A worker that lost its
  claim logs `external_intelligence.claim_lost` and stops writing; the next hourly check retries.
- **Enabling in UAT.** 1) calibrate 2) set `EXTERNAL_INTELLIGENCE_ENABLED=true` (or the switch) 3) `POST /v1/tsg/intel/refresh`
  4) check `GET /v1/tsg/intel/health`.

## 11. Run the tests and code checks

The tests use the **real** local MongoDB, Redis and SQL Server, so steps 3, 6 and 7 must be done. They never touch
the data of a running laptop stack (`.\run.ps1`):
- MongoDB and SQL Server: databases of this checkout's own, `cii_tsg_test_<id>` and `cii_tsg_sql_test_<id>` (the
  id comes from the folder, `tests/checkout.py`), so another checkout's run never drops them (G212).
- Redis: the same server as in `.env`, but spare databases **14** (instead of 0) and **15** (instead of 1, the job
  queues). The laptop stack, like v1, uses 0 and 1. Redis databases are numbered, so a second checkout testing at
  the same time sets `CII_TEST_REDIS_DATABASES` to two other EMPTY spare databases (for example `6,7`; on this
  laptop 8-12 hold other data). A run that finds the pair in use by another run, or holding other data, stops at
  once with what to do; it never empties them.
- Logs: one fixed temporary folder, `%TEMP%\cii-test-logs` (emptied at the start of every run), never `logs\`
  (which Grafana reads), so the tests' made-up outages never show there.

The test database and the two Redis databases are emptied at the start and at the end of every run, so a partial run
with `-k` never leaves anything for the next run. If Redis does not answer, the run stops within 5 s instead of
hanging. The worker does not need to be running.

```powershell
.venv\Scripts\python -m pytest -q
python -m ruff check app tests scripts
python -m ruff format --check app tests scripts
python -m mypy app scripts
```

`.venv\Scripts\python` is the project's Python 3.12, which has pytest; with the environment active (step 4),
`python` is the same program. All four must be clean before you commit (today: 1649 tests). Three monitoring checks (`promtool`) run only once the
monitoring tools are installed (step 13); until then pytest reports them as skipped.

---

## 12. Day-to-day

| You want to … | Do this |
|---|---|
| Stop everything | `.\stop.ps1` (started by hand: `Ctrl+C` in each window; the worker finishes its running jobs first, press twice to force) |
| Change a setting | edit `.env`, then restart the API, the worker and beat (settings are read at start-up) |
| Change how Grafana looks or who may edit | edit or add the `GF_` lines in `.env`, then `.\stop.ps1` and `.\run.ps1` (step 13.1) |
| Use another AI model | add its profile to `app/ai/profiles.py` (code review), then change the name in `.env` |
| Pick up a library change made in SQL Server | nothing — every process checks the library every 60 seconds and reloads only when it changed (if that check keeps failing, the `LibraryCheckFailing` alert fires) |
| Watch jobs in a browser | `http://localhost:5555/flower/` once monitoring runs (step 13) |
| Run a second worker on one machine | give it another metrics port and name: `$env:CII_WORKER_METRICS_PORT=9101; celery … -n dev2@%h` (its log file is `worker-dev2.log`, so the two never mix lines) |
| Find the logs of one request | type its `X-Request-Id` in the **Search logs for** box on the Grafana home page (step 13) |
| See who created or revoked an API key | Grafana home page, **Audit trail** panel (kept 7 days there; `tsg_audit` in MongoDB keeps 365 days) |

### Troubleshooting

| You see | Why | Fix |
|---|---|---|
| `No profile for AI model '…'` at start-up | the model name in `.env` has no entry in `app/ai/profiles.py` | fix the name, or add a profile |
| `Field required … db_dsn` (or another field) | a required `CII_` variable is missing | add it to `.env` (step 6) |
| `/ready` 503 with `"workers": {…: 0}` | no worker is serving that queue | start the worker (step 8); check its `-Q` list |
| `/ready` 503 with `"sql": false` | SQL Server stopped, wrong DSN, or missing ODBC driver | step 3; check `CII_DB_DSN`; `Get-OdbcDriver` |
| `Worker pool '…' is not supported` | the worker was started without `--pool=threads` | use the command in step 8 |
| `Worker metrics port 9100 is in use` | another worker (or program) already uses the port | set `CII_WORKER_METRICS_PORT` to a free port |
| A procedure fails with a `QUOTED_IDENTIFIER` error | the script was run without `-I` | rerun step 7 exactly as written |
| `The library database is unreachable` (503) | SQL Server down or too slow to log in (5 s limit) | step 3 |
| `The AI service is busy or unreachable` | wrong endpoint or key, or the provider is down | check the `CII_CHAT_*` / `CII_EMBEDDING_*` values; jobs retry by themselves |
| A browser call fails with a CORS error | the page's origin is not in `CII_CORS_ORIGINS` | add it (comma-separated) and restart the API |
| `The worker cannot start: …` naming a log file | `CII_LOG_DIR` points at a folder the worker cannot write | fix the folder in `.env`, or leave it empty |
| 422 on a business call that sends every header | `X-User-Id` or `X-Tenant-Id` is longer than 256 characters, or `X-Entity-Id` is above 2,147,483,647 | send a shorter value or a valid id |
| 413 on a call | the body is over 2 MB (`CII_MAX_REQUEST_MB`), whatever its type | send a smaller body (or raise the setting in `.env` and restart the API) |
| `test_env_files_match_settings` fails: `.env: missing […], not read by the app […]` | `.env` lacks a setting the app has, or keeps a key the app does not read | add the missing line (copy it from `.env.example`) or delete the unread one |
| `.\stop.ps1` ends with `Could not stop …` (exit code 1) | that window or tool was started from an administrator window, so this one may not end it | close it by hand (or in Task Manager), then run `.\stop.ps1` again |
| `.\run.ps1` or `.\stop.ps1` stops with `Cannot check window N: it runs as administrator` | that window was started from an administrator window; Windows hides its start time from this one, so the script cannot tell whether it is its own | run the same command again from an administrator PowerShell |
| `.\run.ps1` warns `The beat program has ended` (or api, worker; exit code 1) | the program in that window stopped with an error | read the error in window **TSG beat**, fix it, then `.\stop.ps1` and `.\run.ps1` |
| `CII_CORS_ORIGINS may not contain * outside dev` (or `CII_ADMIN_API_KEY must be at least 32 characters outside dev`) at start-up | `CII_ENV` is missing (it then counts as `prod`) or is not `dev` | put `CII_ENV=dev` in `.env` (step 6) |

---

## 13. Monitoring (Grafana, alerts, logs)

**In one sentence:** Grafana is the one place to look — alerts, API, jobs, AI, stores, logs and the audit trail on
one page — and every monitoring page is public, with no login (owner decision, 2026-10-08).

Anyone who can reach the address can read the numbers and logs, and can silence an alert. That was the owner's
choice. The admin password only changes Grafana itself.

### 13.1 On your laptop

`.\run.ps1` (Quick start, above) does all of this for you. These are the steps by hand.

1. Put `CII_LOG_DIR=logs` in `.env` (`.env.example` has it) and restart the API and the worker. Their log lines now also go to
   `logs\api.log` and one file per worker, `logs\worker-<name>.log` (`worker-dev.log` for `-n dev@%h`). Alloy
   reads `api.log`, every `worker*.log` and `beat.log` and sends them to the local log store (Loki).
2. Start the monitoring tools:

   ```powershell
   python scripts/monitoring.py start
   ```

   The first start downloads the tools into `%USERPROFILE%\.tsg\monitoring-v2`: about 500 MB from github.com and
   dl.grafana.com, each file checked against its SHA-256. They are the same versions UAT runs.
   **Check:** `python scripts/monitoring.py status` shows seven lines, each `ready`.
3. Open these pages:

   | Address | What you see |
   |---|---|
   | `http://localhost:3000/grafana/` | **Start here.** The TSG dashboard is the home page |
   | `http://localhost:9090/prometheus/` | raw numbers and the alert rules |
   | `http://localhost:9093/alertmanager/` | firing alerts; mute (silence) one |
   | `http://localhost:5555/flower/` | every background job, with its arguments and result |
   | `http://localhost:8000/metrics` | the API's own numbers (also `/health`, `/ready`) |

4. Stop them with `python scripts/monitoring.py stop`. v1's monitoring uses the same ports: stop one before you
   start the other.

What the script does for you:

| It … | Why |
|---|---|
| checks every setting before it starts the first program | a missing setting starts nothing, instead of leaving half the tools running |
| saves each started program in `pids.json` (process id + start time) at once | `stop` finds every program it started |
| stops only the very process it started (same id **and** same start time) | after a reboot, the old id can belong to another program, even the API |
| runs Loki on `127.0.0.1` only (ports 3100 and 9095) | nobody else on the network can read or push logs |
| keeps a tool it could not stop in `pids.json` and ends with exit code 1 | the next `stop` tries again, instead of forgetting a tool that still runs |
| gives Grafana every `GF_` line of `.env`, except the ones it sets itself (below) | you change Grafana in `.env`, and the links and the home dashboard keep working |

The script is three files: `scripts/monitoring.py` (start, stop, status), `scripts/monitoring_commands.py` (each
program's command line and settings) and `scripts/monitoring_install.py` (pinned versions, download, SHA-256
check, unpack). You only ever run `monitoring.py`.

The dashboard's rows, top to bottom:

| Row | Example of what it answers |
|---|---|
| Overview | "Is anything firing? Are MongoDB, SQL Server and Redis UP? Does every queue have a worker?" |
| API | "How many requests per second? What share are server errors? Which route is slow?" |
| Jobs and queues | "How many jobs succeed, retry or fail? How many wait in each queue?" |
| AI | "How many AI calls fail, per model? How many tokens per minute?" |
| Dependencies and platform | "Can Prometheus reach every program? Did a pod restart?" (pods: UAT only) |
| Logs and audit | errors and warnings; a search box (type a request id, a run id or any text); the audit trail, e.g. `key.minted by gopal on api_client 12bc… request 7f3a…` |

The **Alerts and silences** link at the top shows the firing alerts in Grafana. To mute (silence) one, use
`/alertmanager/`: Grafana's anonymous viewers cannot silence. The server-error share leaves out `/health`, `/ready`
and `/metrics`, like the `Api5xxHigh` alert.

Grafana's admin user is `admin`. Its password is the `GRAFANA_ADMIN_PASSWORD` line in `.env`. Without that line (or
with it empty), a random one is kept in `%USERPROFILE%\.tsg\monitoring-v2\grafana-admin-password.txt`.

**Change Grafana's settings.** Grafana's settings are yours to change (owner, 2026-10-09). Every
`GF_<SECTION>_<NAME>=value` line in `.env` goes to Grafana. `.env.example` lists 12, in three groups: who can see and
edit (anonymous viewing and its role, Explore for viewers, sign-up), reporting, analytics and calls to the internet
(all off), and look and defaults (theme, time zone, fastest auto-refresh). Any other Grafana setting can be added the
same way (Grafana's configuration documentation lists them). A change applies at the next `.\stop.ps1` then
`.\run.ps1`.

The lines are optional (owner, 2026-10-09): `.env` lists only the settings you set, and a missing line means
Grafana's own default. The comment above each line in `.env.example` names that default. Examples: without
`GF_AUTH_ANONYMOUS_ENABLED=true` everyone must log in; without `GF_USERS_VIEWERS_CAN_EDIT=true` viewers cannot use
Explore; without `GF_PLUGINS_PREINSTALL_DISABLED=true` Grafana downloads plugins at start; the `GF_ANALYTICS_*` and
`GF_NEWS_NEWS_FEED_ENABLED` lines default to `true`, which means calls to grafana.com.

Example: to make Grafana light and show Dubai time, change these two lines in `.env`, then run `.\stop.ps1` and
`.\run.ps1`:

```text
GF_USERS_DEFAULT_THEME=light
GF_DATE_FORMATS_DEFAULT_TIMEZONE=Asia/Dubai
```

The scripts set a few settings themselves, because the links, the `/grafana` path and the home dashboard depend on
them; a line for one of these is ignored: `GF_SERVER_ROOT_URL`, `GF_SERVER_SERVE_FROM_SUB_PATH`,
`GF_SERVER_HTTP_ADDR`, `GF_SERVER_HTTP_PORT`, `GF_PATHS_*`, `GF_SECURITY_ADMIN_PASSWORD` (use
`GRAFANA_ADMIN_PASSWORD`), `GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH` and `GF_LOG_MODE`.

### 13.2 In UAT (OpenShift)

The same files (`observability/`) and the same paths are used. The app's own image and deployments come with
blueprint M15; until then the monitoring runs but has no app pods to watch.

1. Copy every image named in `deploy/observability.yaml` into the image mirror (STEP 0 at the top of that file).
2. Fill in the Grafana lines of `.env.uat` (repo root, git-ignored, never committed; the same file the app's UAT
   settings come from): `GRAFANA_ADMIN_PASSWORD`, 16 or more characters (the script refuses a shorter one, because
   the admin login is on a public page), and any `GF_` lines you want (optional, as in 13.1: copy the 12 of
   `.env.example` to get the setup above, then change any). Nothing else is typed: the script takes the queues'
   Redis database from the number at the end of `CII_REDIS_CELERY_BROKER_URL` (e.g. `1` for `…/1`), and
   redis-exporter reads the Redis URL from the app's own
   Secret, so the Redis password is kept in one place only. The old `deploy\monitoring.env` is retired and no longer
   read.
3. Log in and pick the project (`oc login …`, `oc project <namespace>`), then run:

   ```powershell
   .\deploy\observability.ps1 -RouteHost <the app's host> -AppImage <registry>/tsg:<version>
   ```

   The script reads `.env.uat` and builds two Secrets from it: `tsg-monitoring` (the admin password and the queue
   database) and `tsg-grafana-settings` (the `GF_` lines; applied empty when there are none), through a temporary
   file, never on the command line.
   It waits up to 60 s for the router to accept each Route (a new Route has no status for a few seconds), and stops
   with a clear message when one was not accepted (its host is used by another namespace).
   At the end it waits (up to 300 s each) until every monitoring program runs again, so "applied" means running.
4. **Check:** open `https://<host>/grafana/`. Also `/prometheus/`, `/alertmanager/`, `/flower/` and `/loki/` on the
   same host, and the API's `/metrics`, `/health` and `/ready`.

Run the script again after any change in `observability/` or in the Grafana lines of `.env.uat`: it rebuilds the
settings and restarts the monitoring pods. A changed Grafana password takes effect on that restart (a start-up step
sets it, because Grafana itself reads the password only when it first creates its database).

### 13.3 Alerts

The 18 alert rules are in `observability/prometheus/rules.yml`; `docs/BLUEPRINT.md` §22.3 explains each one. No alert
channel (e-mail, Teams …) is set yet (D-05): a firing alert shows on the Grafana home page and at `/alertmanager/`.

These four catch what the other alerts cannot see (a part with no running copy has nothing to scrape, so
`TargetDown` stays silent):

| Alert | Fires when |
|---|---|
| `ApiNotRunning`, `WorkerNotRunning` | no API (or no worker) has answered Prometheus for 5 minutes, even when none runs at all |
| `QueueDepthUnknown` | redis-exporter cannot reach Redis for 10 minutes, so the queue lengths are unknown |
| `PodNotStarting` (UAT) | a pod has waited 10 minutes to start (crash loop, image pull error, bad config, or Pending) |

**`LibraryCheckFailing`** fires when the library check (every 60 seconds) failed 10 or more times in 15 minutes, for
5 minutes. Library edits made in SQL Server are then not picked up; TSG keeps serving the last library it loaded.
Look at SQL Server first (step 3), then at the log lines `library.check_failed` and `dependency.unavailable`. One
failed check is a blip and fires nothing.

---

## 14. UAT and production

The same code runs in UAT and production on OpenShift. Only the configuration changes (blueprint §18, §23). The
container image, manifests and CI pipeline are **Planned** (blueprint §26, Phase 10).

| Topic | Laptop (dev) | UAT / production |
|---|---|---|
| Settings | `.env` file | OpenShift ConfigMap (non-secret) + Secret (secret), loaded with `envFrom`. UAT's values (secrets too) live only in `.env.uat` at the repo root; it is git-ignored, **never commit it** |
| SQL Server | `localhost\SQLEXPRESS`, `DevTest5` | UAT: `10.228.146.2`, port 1444, database `EYShieldDB_Copy`, ODBC Driver 17, `Encrypt=yes`, `TrustServerCertificate=yes` |
| SQL login | your Windows account | UAT: `Desc_Produser` (a login with EXECUTE on the `tsg_*` procedures) |
| MongoDB | `localhost:27017`, `cii_tsg` | UAT: `10.228.146.3`, port 27018, `authSource=admin`, `directConnection=true`, database `cii_tsg` (v1 uses `tsg_embeddings`; the two never mix). No TLS option in UAT, exactly as v1 (internal network; TLS recommended for production) |
| Redis | `127.0.0.1:6379`, databases 0 and 1 (shared with v1 on this laptop: never run both at once) | UAT: `10.228.146.4`, port 6379, plain `redis://` (no TLS, internal network, exactly as v1; TLS recommended for production). Database 0 = live updates and caches (`CII_REDIS_URL`); database 1 = job queues (`CII_REDIS_CELERY_BROKER_URL`). Database 2 (v1's job results) is **not** used: v2 keeps every job status in MongoDB |
| AI gateway | Azure AI Foundry + local reranker | UAT: LiteLLM at `https://llmapi.govai.ae` (same URL in `CII_CHAT_BASE_URL`, `CII_EMBEDDING_BASE_URL`, `CII_RERANK_BASE_URL`); `CII_AI_KEY_HEADER=x-litellm-api-key` |
| AI models | `openai/Kimi-K2.6`, `openai/text-embedding-3-large`, `bge-reranker-v2-m3` | chat `litellm_proxy/kimi-k2.5`, fallback `litellm_proxy/glm-5` (12,288 output tokens, JSON mode, thinking off); embedding `litellm_proxy/qwen3-embedding-8b-mig` (4,096 numbers, batches of 32, texts cut to 4,000 characters, 4 batches at once); rerank `litellm_proxy/qwen3-reranker-8b-mig`. These values are in `app/ai/profiles.py`, not in `.env` |
| Installed extras | `.[dev,local]` | none (no local reranker, no test tools) |
| Processes | one worker on all queues | separate deployments: `worker-threats`, `worker-scenarios` (10 threads each), `worker-maintenance` (3 threads: one for each long task kind on its queue, plus one so the reaper always finds a free thread), exactly one `beat` (memory limit 512Mi: loading the worker code takes about 255 MB), two `api` pods |
| `CII_ENV` | `dev` (required) | `uat` in UAT, `prod` in production; a missing value counts as `prod` |
| Start order | any | workers and beat **before** the API: an API pod is ready only when every queue has a worker |
| API command | `python -m uvicorn app.main:app --host 127.0.0.1 --port 8000` (`.\run.ps1 -Reload` to restart on save) | `uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers --no-access-log` (no `--reload`) |
| Health probes | — | readiness `/ready` every 10 s (timeout 7 s, 3 failures), liveness `/health` |
| Stored procedures | step 7 | the DBA runs the changed `scripts/sql/*.sql` before the new app version is rolled out |
| Monitoring | `python scripts/monitoring.py start` (13.1) | `.\deploy\observability.ps1` (13.2) |

Before v2 first runs in UAT:

- **Stop v1 first.** v1 and v2 both name their Redis keys `tsg:…`, so they must never run on the same Redis
  database at the same time; v2 takes databases 0 and 1 once v1 is stopped. Scale **every** v1 pod down before v2's
  workers start: in namespace `ai-threatgen` the api, both workers, beat and flower; in namespace `ai-remediation`
  its 2 worker pods (all of them read broker database 1). (v1 will be removed.)
- **The DBA installs the procedures.** Every procedure file `scripts/sql/tsg_<Name>.sql` (a copy beside them, such as `tsg_GetAssetContext copy.sql`, is a backup and is never installed) (`tsg_GetAssetContext`, `tsg_GetControlLibrary`,
  `tsg_GetLibraryStamp`, `tsg_GetThreatLibrary`) go into `EYShieldDB_Copy` before v2 runs. `Control_Library` there
  must have the column `AssetType` (renamed from `ITOT` by the owner, 2026-10-09), or `tsg_GetControlLibrary` fails
  with "Invalid column name 'AssetType'". `tsg_GetControlLibrary` changed on 2026-10-11 (a second result set,
  the retired controls): re-run its script before the new app version; until then the app logs
  `library.retired_controls_missing` and sends a retired register control without its name.
- **The pods use the corporate proxy**, as v1 does: every pod that calls the AI (api, every worker, beat) gets
  `HTTP_PROXY` and `HTTPS_PROXY` = `http://10.61.192.2:8080` and a `hostAliases` entry `10.231.255.253` →
  `llmapi.govai.ae` (set in the manifests, blueprint M15). v2 needs no code for this.
- **The image installs ODBC Driver 17**, as v1's does (`msodbcsql17`): the UAT connection string names Driver 17.
- **v1's UAT deployment values** (egress rules, replicas, resources, probes, shutdown grace, disruption budgets,
  registry and pull secret, route) are listed in blueprint M15 "UAT requirements" item 5. v2's manifests use them
  unless M15 decides otherwise.
- **Temperature follows the task**, as in v1 (blueprint R-2, M04 A1d): 0.0 where the same input must give the same answer
  (finding and checking threats); none at all for writing scenarios, so a regenerated scenario really differs.
- **Thinking stays off** (`reasoning_effort="none"`). v1's `REASONING_EFFORT=low` line is switched off by
  `thinking=false`, so v1 sends "none" too (owner, blueprint D-03).
