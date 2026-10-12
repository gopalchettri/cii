# How to debug TSG v2 in VS Code

Version 4.0 · 2026-10-10

**Before you start:** TSG already runs on this laptop ([RUNNING.md](RUNNING.md) done once), `.env` has
`CII_ENV=dev`, and TSG v1 is not running.

Three parts:

1. Configure the VS Code files (once).
2. How to put a breakpoint.
3. Debug the whole solution, step by step.

---

## Part 1 — Configure the VS Code files (once)

The files below are already in the project. Check that each one has this content. If one is missing, create it
(File → New File, save it under that name) and paste the content.

### Step 1. Open the project

1. VS Code → **File → Open Folder…** → choose the folder **`cii`**.
2. VS Code asks "Do you trust the authors of the files in this folder?" → **Yes, I trust the authors**.

### Step 2. `.vscode/extensions.json` — the extensions to install

```json
{
  "recommendations": ["ms-python.python", "ms-python.debugpy", "humao.rest-client"]
}
```

VS Code offers to install them → click **Install**. (Missed it? Ctrl+Shift+X → type `@recommended` → install all
three.)

| Extension | Why |
|---|---|
| Python | runs Python, shows the tests |
| Python Debugger | the breakpoints |
| REST Client | sends the API calls in `debug/tsg.http` |

### Step 3. `.vscode/settings.json` — Python, tests and the API address

```json
{
  "python.defaultInterpreterPath": "${workspaceFolder}/.venv/Scripts/python.exe",
  "python.testing.pytestEnabled": true,
  "python.testing.unittestEnabled": false,
  "python.testing.pytestArgs": ["tests", "-p", "no:cacheprovider"],
  "rest-client.environmentVariables": {
    "$shared": {
      "baseUrl": "http://localhost:8000",
      "grafana": "http://localhost:3000/grafana/",
      "flower": "http://localhost:5555/flower/"
    },
    "laptop": {},
    "uat": {
      "baseUrl": "https://set-the-uat-host-in-vscode-settings.invalid",
      "grafana": "https://set-the-uat-host-in-vscode-settings.invalid/grafana/",
      "flower": "https://set-the-uat-host-in-vscode-settings.invalid/flower/"
    }
  }
}
```

| Setting | What it does |
|---|---|
| `python.defaultInterpreterPath` | uses the project's Python (`.venv`) |
| `python.testing.…` | shows the tests in the Testing panel (beaker icon) |
| `rest-client.environmentVariables` | the API address for `debug/tsg.http`: `baseUrl` = `http://localhost:8000` (the `uat` lines are for calling UAT; not needed here) |

Check: the status bar (bottom right) shows `('.venv': venv)`. If not: Ctrl+Shift+P → **Python: Select
Interpreter** → `.venv\Scripts\python.exe`.

### Step 4. `.vscode/launch.json` — how VS Code starts TSG for debugging

```json
{
  // Debug TSG v2 in VS Code: docs/DEBUGGING.md, Part 3. Needs the "Python" and "Python Debugger" extensions.
  // Stop the normal TSG first (Terminal > Run Task > TSG: stop): it uses the same port 8000 and job queues.
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Debug API",
      "type": "debugpy",
      "request": "launch",
      "python": "${workspaceFolder}/.venv/Scripts/python.exe",
      "module": "uvicorn",
      // No --reload: it runs the app in a child process, where breakpoints never stop.
      "args": ["app.main:app", "--host", "127.0.0.1", "--port", "8000"],
      "cwd": "${workspaceFolder}",
      "env": { "CII_LOG_DIR": "logs" },
      "console": "integratedTerminal",
      "justMyCode": true
    },
    {
      "name": "Debug worker",
      "type": "debugpy",
      "request": "launch",
      "python": "${workspaceFolder}/.venv/Scripts/python.exe",
      "module": "celery",
      // solo pool: one task at a time on the main thread, so a breakpoint stops exactly one job.
      // Metrics port 9101: never clashes with a normal worker still running on 9100.
      "args": [
        "-A", "app.worker", "worker", "--pool=solo",
        "-Q", "tsg_threats,tsg_scenarios,tsg_maintenance",
        "-n", "debug@%h", "--loglevel=INFO"
      ],
      "cwd": "${workspaceFolder}",
      "env": { "CII_LOG_DIR": "logs", "CII_WORKER_METRICS_PORT": "9101" },
      "console": "integratedTerminal",
      "justMyCode": true
    },
    {
      "name": "Debug current test file",
      "type": "debugpy",
      "request": "launch",
      "python": "${workspaceFolder}/.venv/Scripts/python.exe",
      "module": "pytest",
      // Open a file in tests/ first. The tests use their own databases (cii_tsg_test, Redis 14/15).
      "args": ["${file}", "-q", "-p", "no:cacheprovider"],
      "cwd": "${workspaceFolder}",
      "console": "integratedTerminal",
      "justMyCode": false
    }
  ],
  "compounds": [
    {
      "name": "Debug API + worker",
      "configurations": ["Debug API", "Debug worker"],
      "stopAll": true
    }
  ]
}
```

| Configuration | Starts | Use it to |
|---|---|---|
| **Debug API** | the API on port 8000 | stop inside a request |
| **Debug worker** | one Celery worker for all three queues, one job at a time | stop inside a background job |
| **Debug API + worker** | both together | debug the whole solution (Part 3) |
| **Debug current test file** | the test file open in the editor | stop inside a test |

You may change two things:

- `"env"`: settings for the debug session only; they win over `.env`. Example: add `"CII_LOG_LEVEL": "DEBUG"` for
  more detail in the log.
- `"justMyCode": false`: also stop inside FastAPI, pymongo or Celery code.

Check: Ctrl+Shift+D → the list at the top shows the four names.

### Step 5. `.vscode/tasks.json` — ready-made commands

Nothing to change. Run a task with **Terminal → Run Task…** → type `TSG` → choose it. This guide uses:

| Task | Does |
|---|---|
| TSG: start / TSG: stop | starts / stops the normal TSG (API, worker, beat and monitoring) |
| TSG: make a test run (laptop) | creates a test run in your laptop database |
| TSG: watch a run's live updates | shows the live updates of that test run |
| TSG: send a status change to the test run (laptop) | changes the test run's status |
| TSG: delete the test run (laptop) | deletes the test run |
| TSG: run the reaper now | sends a background job to the worker |
| TSG: rebuild the library indexes now | sends another background job |
| TSG: replay a run's inner steps | writes one run's search and ranking sub-steps to a log ([Following a run step by step](#following-a-run-step-by-step)) |

### Step 6. `debug/.env` — your identity for the API calls

1. Open a terminal (Ctrl+`) and run:
   ```powershell
   Copy-Item debug\.env.example debug\.env
   ```
2. Open `debug/.env` and write your name after `TSG_USER_ID=`. Leave the other lines as they are (`TSG_API_KEY` is
   filled in Part 3, step 3).
3. Save. Git never commits this file.

The configuration is done.

---

## Part 2 — How to put a breakpoint

A breakpoint is a red dot on a line of code. When TSG reaches that line, it pauses and VS Code shows you the values.

1. Open the file (Ctrl+P → type the file name → Enter).
2. Find the line (Ctrl+F).
3. Click in the empty space **left of the line number**: a red dot appears. (Or put the cursor on the line and press
   F9.) Click the dot again to remove it.
4. When TSG pauses there, the line turns yellow. Then use:

   | Key | Does |
   |---|---|
   | F10 | run this line, pause at the next one |
   | F11 | go into the function called on this line |
   | Shift+F11 | finish this function, pause in the one that called it |
   | F5 | continue to the next breakpoint |
   | Ctrl+Shift+F5 | restart (do this after you change code) |
   | Shift+F5 | stop debugging |

5. While paused, look on the left of the Run and Debug view (Ctrl+Shift+D):
   - **VARIABLES**: every value in the paused function;
   - **CALL STACK**: which functions led here (click one to see its values);
   - **BREAKPOINTS**: all your breakpoints; untick one to switch it off.

   And at the bottom, **DEBUG CONSOLE**: type any expression (e.g. `request.headers`) and press Enter.
6. To pause only in some cases: right-click the dot → **Edit Breakpoint** → type a condition, e.g. `entity_id == 86`.
7. To remove all breakpoints: **Run → Remove All Breakpoints**.

VARIABLES shows API keys in clear text: never screenshot or share them.

---

## Part 3 — Debug the whole solution, step by step

### Step 1. Stop the normal TSG

**Terminal → Run Task… → TSG: stop**. The debugger needs port 8000 and the job queues for itself.

### Step 2. Start TSG in the debugger

1. Ctrl+Shift+D → choose **Debug API + worker** at the top → press **F5**.
2. Wait for two terminals: one shows `Uvicorn running on http://127.0.0.1:8000`, the other the worker's `ready`.
3. Open `debug/tsg.http`. Click **Send Request** above **1. Health** → the answer on the right says `200`.
4. Send **2. Ready** → `200`. (If it says `503` with `"workers"` at 0, wait 20 seconds and send it again.)

### Step 3. Get your API key (first time only)

1. Send **3. Admin: mint an API key**. VS Code asks for the admin key at the top: paste the value of
   `CII_ADMIN_API_KEY` from `.env` → Enter.
2. Copy the `api_key` value from the answer (it starts with `tsg_`) into `debug/.env` after `TSG_API_KEY=` → save.
3. Send **5. Check my key and headers work** → `404` "Session 'check-my-key' does not exist." This means your key
   works.

### Step 4. Follow one request through the whole API

This follows call **5** through every layer: the request arrives → the key is checked → the database is read → the
rule is applied → the error answer is built → the request is logged.

1. Put these 6 breakpoints:

   | # | File | Line (Ctrl+F) | Layer |
   |---|---|---|---|
   | 1 | `app/api/middleware.py` | `return request_id` | the request arrives and gets its id |
   | 2 | `app/api/dependencies.py` | `return Principal(client_id, user_id, entity_id, tenant_id)` | the API key is checked |
   | 3 | `app/data_access/sessions.py` | `record = get_mongodb()[Collection.SESSIONS]` | the database is read |
   | 4 | `app/services/session_status.py` | `if status is None:` | the rule is applied |
   | 5 | `app/api/errors.py` | `assert isinstance(exc, AppError)` | the error answer is built |
   | 6 | `app/api/middleware.py` | `log.info(` | the request is logged |

2. Send call **5**. TSG pauses at each breakpoint in turn. Look at VARIABLES, then press F5:

   | Pause | Look at | You see |
   |---|---|---|
   | 1 | `request_id` | a new id (32 letters and digits) |
   | 2 | `client_id`, `user_id`, `entity_id` | your key's id, your name, `86` |
   | 3 | `session_id` | `check-my-key` |
   | 4 | `status` | `None` (no run has that id) |
   | 5 | `exc.status`, `exc.detail` | `404`, "Session 'check-my-key' does not exist." |
   | 6 | `route`, `status` | `/v1/sessions/{session_id}/events`, `404` |

3. The answer appears in REST Client: `404`.
4. **Run → Remove All Breakpoints**.

### Step 5. Debug any other call

For any call in `debug/tsg.http`: put one breakpoint on the **first line inside** the function below, send the call,
then press F10 line by line and watch VARIABLES.

| Call | File | Function |
|---|---|---|
| 1 Health | `app/api/routers/health.py` | `report_liveness` |
| 2 Ready | `app/api/routers/health.py` | `report_readiness` |
| 2b Metrics | `app/api/routers/health.py` | `export_prometheus_metrics` |
| 3 Mint a key | `app/services/api_clients.py` | `mint_api_client` |
| 4 List keys | `app/data_access/api_clients.py` | `list_clients` |
| 5, 6a, 6b (key check, 401) | `app/api/dependencies.py` | `get_authenticated_principal` |
| 6c, 6g (422) | `app/api/errors.py` | `answer_invalid_request` |
| 6d (403) | `app/services/session_status.py` | `find_status_for_caller` |
| 6e, 6f (404, 405) | `app/api/errors.py` | `answer_http_error` |
| 7 Own request id | `app/api/middleware.py` | `_bind_request_context` |
| 8 Revoke a key | `app/services/api_clients.py` | `revoke_api_client` |

- **6d** needs a test run first: **Terminal → Run Task… → TSG: make a test run (laptop)**.
- **3 and 8**: mint a spare key with 3 and revoke that one with 8 (8 asks for its `client_id`, from the answer of 3).
  Keep your own key in `debug/.env`.

### Step 6. Debug the live updates

1. Put one breakpoint: `app/api/routers/events.py`, the line
   `yield ServerSentEvent(event=Event.SESSION_UPDATED, raw_data=str(update))`.
2. **Run Task → TSG: make a test run (laptop)** (skip if you made one for 6d).
3. **Run Task → TSG: watch a run's live updates** → `laptop`. Its terminal shows the run with `"status": "running"`.
   Leave it open.
4. **Run Task → TSG: send a status change to the test run (laptop)** → `done`.
5. TSG pauses at the breakpoint: VARIABLES `update` holds the new status. Press F5: the live-updates terminal shows
   `"status": "done"`.
6. Click in the live-updates terminal → Ctrl+C. Then **Run Task → TSG: delete the test run (laptop)**.

### Step 7. Debug the background jobs (Celery worker)

1. Put one breakpoint: `app/worker/reaper.py`, the line `now = datetime.now(UTC)` (first line of `reap_jobs`).
2. **Run Task → TSG: run the reaper now**.
3. TSG pauses inside the worker. Press F10 line by line, then F5.
4. The other job works the same way: breakpoint in `app/worker/tasks/library_indexes.py` on the line
   `get_library_search().snapshot(wait=True)`, then **Run Task → TSG: rebuild the library indexes now**.

### Step 8. Debug what a call cannot reach (tests)

Some paths only happen when something breaks: a crash, a database that is down. The tests create these cases for
you, on their own test databases.

1. Click the **Testing** icon (the beaker) on the left. The tests appear under `tests`.
2. Put the breakpoint, find the test, click its **Debug Test** icon.

| To see | Breakpoint (file → function) | Test (file → test) |
|---|---|---|
| a crash → 500 | `app/api/errors.py` → `answer_unexpected_error` | `tests/test_request_context.py` → `test_a_crash_is_counted_and_carries_the_request_id` |
| a request that is too large → 413 | `app/api/middleware.py` → `receive_within_size_limit` | `tests/test_request_context.py` → `test_a_body_over_the_limit_is_refused_with_413` |
| a database that is down → 503 | `app/api/errors.py` → `answer_store_unavailable` | `tests/test_store_unavailable.py` → `test_unreachable_store_answers_503_with_retry_after` |
| a job that fails, and one that succeeds | `app/worker/jobs.py` → `run_leased_job` | `tests/test_worker.py` → `test_an_unexpected_error_fails_the_job_and_a_success_finishes_it` |

### Step 9. Stop debugging

1. Press **Shift+F5**.
2. **Terminal → Run Task… → TSG: start**: the normal TSG is back.

---

## Following a run step by step

Two settings in `.env` make every step log what it was given and what it produced (redacted, bounded):

| Setting | Does |
|---|---|
| `DEBUG_STEP_OUTPUT=true` | each traced step logs its inputs, results, output, time and error (`app/core/tracing.py`) |
| `DEBUG_STEP_DETAIL=true` | adds the inner sub-steps (BM25, similarity, merge by rank, per category, ranking passes); only with `DEBUG_STEP_OUTPUT=true` |
| `DEBUG_STEP_TOP=10` | how many entries a ranked sub-step keeps (1-40) |

Restart TSG after changing them. The lines go to `logs/api.log` and `logs/worker-dev.log` (`CII_LOG_DIR`,
`CII_LOG_LEVEL=INFO`).

A run made with them off can still show its search and ranking: **Run Task → TSG: replay a run's inner steps**, or

```powershell
.venv\Scripts\python scripts\replay_run_steps.py <run id>
```

It re-runs that run's landscape, library search and path ranking with the app's own code, read-only (vectors from
MongoDB only, no AI call, nothing written), into `logs/replay-<first 8 of the run id>.log`, and says whether the
library changed since the run and whether the ranking came out the same. The merge (`threats.merge`) cannot be
replayed: its input was never stored.

To see it: open `app/ux/tsg_console.html` → **How it runs** → **Load run data** → pick the log files (the replay
file, and `worker-dev.log` for the steps it does not replay) → click a step, then a sub-step.

---

## Good to know

- You changed code: press Ctrl+Shift+F5 to restart the debugger with it (it does not reload by itself).
- A key is remembered for 60 seconds: a second call within that time does not read the database for the key.
- Paused in the worker for more than 60 seconds: **2. Ready** shows 0 workers. Press F5 and it recovers.
- Paused in the API for more than 15 seconds: afterwards the log may show one `event.hub_reconnecting` line. Normal.
- A library change rebuilds the search indexes in a background thread (`library-indexes`); searches keep using the
  older ones meanwhile. To stop inside that build, put the breakpoint in `app/search/service.py` → `_build`.
