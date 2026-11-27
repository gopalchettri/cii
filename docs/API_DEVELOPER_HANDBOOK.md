# TSG API: Developer Handbook

This handbook follows three requests through the API in this repository, from model to HTTP response (Recipes A–C), then shows how to run, test, and hand over a change. Every other operation is built the same way.

The target is the current **CII Threat Scenario Generator v2** API: FastAPI, MongoDB, SQL Server stored procedures, Redis, Celery, AI gateways, and SSE. [SOLUTION_DESIGN.md](SOLUTION_DESIGN.md) explains *why* the product works this way. The source files named below show the exact current implementation. The Service Mapper, with its own worker on `tsg_servicemapper`, is described in [service_mapper/SERVICE_MAPPER.md](service_mapper/SERVICE_MAPPER.md).

## Read this before you start

The API cannot be implemented correctly from a route name alone. Obtain the approved endpoint contract, SQL schema/data ownership, local store addresses, and AI credentials from the feature or environment owner. For an existing endpoint, `tests/contract/openapi.json` and its route/schema/tests are the approved contract. For a new endpoint, record method, path, caller, owner, request, response, errors, retry behavior, persistence, and background work before editing. Do not guess these values.

All commands below use **Windows PowerShell** from the repository root. Use Windows PowerShell **5.1** for `run_dev.ps1` and `run_uat.ps1`; the scripts reject PowerShell 7. Work in the current checkout without discarding unrelated uncommitted changes. A failed build or test command is a gate: fix its stated problem before moving on.

Set up once: Python 3.12, and development SQL Server, MongoDB, and Redis. Use `.[dev,local]` instead of `.[dev]` when the local reranker model is needed (`CII_RERANK_BASE_URL` empty). Fill `.env` from `.env.example` and `app/core/config.py` with real development values; never run with `<secret>` or `<resource>` placeholders, and never print or commit secrets.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]" -c requirements.txt
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
```

Record Ruff and mypy output **before** editing, so you can tell the diagnostics your work adds from those already there:

```powershell
.\.venv\Scripts\python.exe -m ruff check app tests scripts
.\.venv\Scripts\python.exe -m mypy app
```

Never run the application or pytest against production stores.

## Cookbook — Follow three requests all the way through

Recipes A–C trace implementations in the current code. Follow each recipe's file order and gate; do not paste their code into duplicate modules.

### Recipe A — Build an authenticated `GET` from model to HTTP response

Target: `GET /v1/tsg/api-clients?active=true`. It lists active API clients for an administrator, without exposing a secret or its hash.

**A1. Fix the contract before coding.** Method/path: GET `/v1/tsg/api-clients`. Required header: `X-Admin-Key`. Optional query: `active` is `true`, `false`, or absent. Success: 200 `{"items":[...],"total":N}`. Wrong admin key: 401; admin key unset in configuration: 403. No caller `X-API-Key` is involved.

**A2. Define the output in `app/schemas/admin.py`.** FastAPI serializes through this response model, so fields absent from the model are not sent. It does not contain `api_key` or `key_hash`:

```python
class ApiClientOut(BaseModel):
    client_id: str
    name: str
    description: str | None = None
    key_prefix: str
    active: bool
    created_at: datetime
    created_by: str | None = None
    revoked_at: datetime | None = None
    revoked_by: str | None = None


class ApiClientList(BaseModel):
    items: list[ApiClientOut]
    total: int
```

**A3. Make one database read in `app/crud/admin.py`.** A crud function is a plain function that takes the database. `_WITHOUT_KEY_HASH` keeps the secret's hash out of every read. An absent `active` means no filter; `active=true/false` filters. `_as_client()` turns MongoDB `_id` into public `client_id`:

```python
INDEXES = [
    {"keys": "key_hash", "unique": True},
    {"keys": "name", "unique": True, "partialFilterExpression": {"active": True}},
]
_WITHOUT_KEY_HASH = {"key_hash": 0}


def list_api_clients(db: Database, active: bool | None) -> list[dict[str, Any]]:
    where = {} if active is None else {"active": active}
    listed = db[Collection.API_CLIENTS].find(where, _WITHOUT_KEY_HASH).sort("created_at", -1)
    return [_as_client(stored) for stored in listed]
```

The two unique indexes, made at start-up by `create_all_indexes()` through `store(db)`, prevent duplicate key hashes and duplicate active names. The write beside it, `create_api_client()`, stores only the key's hash and turns a taken active name into 409.

**A4. Take the database through `DbDep`.** `app/api/deps.py` holds the shared `Annotated` dependencies. A route names one as a parameter type and never builds a client; tests swap them with `app.dependency_overrides`:

```python
DbDep = Annotated[Database, Depends(get_mongodb)]
```

**A5. Expose the route in `app/api/routes/admin.py`.** `Depends(require_admin_api_key)` sits on the admin router, so every admin route shares the check. The route calls the crud function and wraps its page; no service class sits in between:

```python
router = APIRouter(dependencies=[Depends(require_admin_api_key)])
keys = APIRouter(prefix="/v1/tsg/api-clients", tags=[ApiTag.API_KEYS])


@keys.get("", response_model=ApiClientList, summary="2. List API keys")
def list_api_clients(db: DbDep, active: bool | None = None) -> dict:
    items = admin_crud.list_api_clients(db, active)
    return {"items": items, "total": len(items)}
```

`mint_api_client()` in the same file is the write: it calls `admin_crud.create_api_client(db, body.name, body.description, actor)`, writes the audit row and answers `Cache-Control: no-store`. The file ends by adding `keys`, `embeddings`, `monitor` and `curation` to `router`. Register `admin_router` once in `app/main.py:create_app()`. `app/api/deps.py:require_admin_api_key()` performs the comparison; `app/api/errors.py` formats a failure. Add/update the API tag description in `app/api/openapi_docs.py` if the group changes.

**A6. Test the route with the real test client.** `tests/test_api_clients.py` contains the key setup and auth cases (`test_admin_key_is_required` covers the 401). A focused test should mint two clients, revoke one, call this route with `active=true`, and assert: 200; `total == len(items)`; only the active client remains; neither `api_key` nor `key_hash` appears anywhere. If adding this coverage, import `uuid` in that test file and place this function beside the existing API-client tests:

```python
def test_active_list_filters_revoked_clients_and_hides_secrets(client: TestClient) -> None:
    active = _mint_api_client_via_api(client, f"list-active-{uuid.uuid4().hex}")
    revoked = _mint_api_client_via_api(client, f"list-revoked-{uuid.uuid4().hex}")
    assert client.post(f"{URL}/{revoked['client_id']}/revoke", headers=ADMIN).status_code == 200

    response = client.get(f"{URL}?active=true", headers=ADMIN)
    assert response.status_code == 200, response.text
    body = response.json()
    ids = {item["client_id"] for item in body["items"]}
    assert active["client_id"] in ids
    assert revoked["client_id"] not in ids
    assert body["total"] == len(body["items"])
    assert all(item["active"] and "api_key" not in item and "key_hash" not in item for item in body["items"])
```

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_api_clients.py -q
```

**A7. Send it manually.** Start the stack (see *Start the real local stack* below), then use the `GET /v1/tsg/api-clients?active=true` block in `debug/tsg.http`. Supply the configured development `X-Admin-Key` when prompted. Expect 200, `items`, `total`, and `X-Request-Id`; no secret or hash. A wrong key must produce `application/problem+json` and 401.

### Recipe B — Build a `202` job and a status endpoint

Target: `POST /v1/embeddings` starts a library vector build; `GET /v1/embeddings/{job_id}` reports its result. This is the **admin-job** pattern. Session and remediation jobs use the leased pattern in Recipe C instead.

**B1. Fix the two HTTP contracts.** Start: admin key, no body, 202 `{"job_id":"...","status":"queued"}`. A second active build is 409 `job_in_progress` with `details.job_id`. Broker unavailable is 503 and the record becomes failed. Status: admin key, 200 `AdminJobOut` with queued/running/done/failed and a result or error; unknown ID is 404.

**B2. Define two models in `app/schemas/jobs.py`.** `AdminJobStarted` has `job_id: str` and `status: Status`. `AdminJobOut` has `job_id`, `kind`, `status`, `requested_by`, timestamps, optional `result`, and optional `error`. It is returned from MongoDB, not from Celery's result backend.

**B3. Enforce “one active build” in `app/crud/admin_jobs.py`.** `AdminJobRepository` has a unique partial index on `kind` where `active=True` (`one_active_per_kind`), plus a TTL on `created_at`. It implements `create_admin_job()`, `get_admin_job()`, `update_admin_job_running()`, and `update_admin_job_finished()`. A duplicate message cannot start work twice because the running update requires `status=QUEUED` and `active=True`. Ending the record unsets `active`, so a later build may start; `create_admin_job()` fails and replaces an abandoned one (heartbeat run out, or never started).

The critical claim is an atomic repository update, which also stamps the first heartbeat:

```python
def update_admin_job_running(
    self, job_id: str, now: datetime, task_id: str | None = None, worker: str | None = None
) -> bool:
    changes = {"status": Status.RUNNING, "started_at": now, "task_id": task_id, "worker": worker}
    return self.update(changes | _heartbeat(now), _id=job_id, active=True, status=Status.QUEUED) > 0
```

**B4. Persist before sending, in the route.** `start_embeddings_build(actor: AdminUser)` in `app/api/routes/admin.py` (`@embeddings.post("", status_code=202, response_model=AdminJobStarted)`) makes an ID and queued record, then calls the shared `queue_admin_job()` in `app/crud/admin.py`; the intelligence import uses it too:

```python
job_id, kind = uuid.uuid4().hex, AdminJobKind.EMBEDDINGS_BUILD
job = {"_id": job_id, "kind": kind, "status": Status.QUEUED, "requested_by": actor}
admin_crud.queue_admin_job(
    get_admin_job_repository(),
    send_admin_job,
    TaskName.BUILD_LIBRARY_INDEXES,
    job,
    AdminJobMessage.IN_PROGRESS,
    AdminJobMessage.NOT_SENT,
)
```

`queue_admin_job()` adds `created_at` and the request ID, inserts the active record, returns 409 with the winner's `job_id` when one already exists, sends the Celery message, and fails the record plus answers 503 if sending fails. Its decision branches, in order:

```python
job_id = job["_id"]
active_id = jobs.create_admin_job(job | {"created_at": utc_now(), "request_id": current_request_id()})
if active_id != job_id:
    raise Conflict(in_progress, reason=ConflictReason.JOB_IN_PROGRESS, details={"job_id": active_id})
sent = False
try:
    sent = send(task, job_id)
finally:
    if not sent:
        error = {"code": ErrorCode.UNAVAILABLE, "message": not_sent}
        jobs.update_admin_job_finished(job_id, utc_now(), error=error)
if not sent:
    raise Unavailable(not_sent)
```

The route then audits the start and returns `{"job_id": job_id, "status": Status.QUEUED}`.

**B5. Read the status in the same file.** The admin router's key dependency covers both routes. The read asks for the embedding-build kind only, returns the stored status, and raises `NotFound` for an unknown ID:

```python
embeddings = APIRouter(prefix="/v1/embeddings", tags=[ApiTag.EMBEDDINGS])


@embeddings.get("/{job_id}", response_model=AdminJobOut, summary="2. Read a build")
def read_embeddings_build(job_id: Annotated[str, Path(max_length=64)]) -> dict:
    record = get_admin_job_repository().get_admin_job(job_id, AdminJobKind.EMBEDDINGS_BUILD)
    if record is None:
        raise NotFound(AdminJobMessage.NOT_FOUND.format(job_id=job_id))
    return {"job_id": record.pop("_id"), **record}
```

**B6. Register the worker in three places, in order.** In `app/core/constants/jobs.py`, route `TaskName.BUILD_LIBRARY_INDEXES` to `Queue.MAINTENANCE`. In `app/worker/celery_app.py:TASK_MODULES`, include `app.worker.admin.library_indexes`. In `app/worker/admin/library_indexes.py`, decorate `build_library_indexes` with that task name. The task calls the getters inside the function, claims the saved job with `update_admin_job_running`, builds the snapshot/vectors, then saves `DONE` and counts or `FAILED` and an error. `run_dev.ps1` and `run_uat.ps1` already start a `tsg_maintenance` worker. `/ready` should see that worker.

```python
@celery_app.task(name=TaskName.BUILD_LIBRARY_INDEXES)
def build_library_indexes(job_id: str | None = None) -> None:

    if job_id is None:  # beat's scheduled build has no admin-job record
        get_library_search().snapshot(wait=True)
        return
    run_embeddings_job(
        job_id,
        get_admin_job_repository(),
        get_library_cache(),
        get_library_search(),
        get_embedding_repository(),
        get_audit_repository(),
    )
```

`run_embeddings_job()` is in the same file. It returns immediately if the atomic running claim fails, and writes a terminal `result` or `error` only while this job still owns its active record.

**B7. Test every state transition.** Run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_embeddings_builds.py -q
```

The tests cover 202 queued, 409 second build, stale job replacement, 503 failed send, worker completion/failure, a redelivered message, and the status read. For manual verification, send the two embedding calls from Swagger (`/docs`) with the admin key: save `job_id` from POST, poll GET until `done` or `failed`, and inspect `result.counts` or `error`. A second POST while one runs should name the first job in its 409 response.

### Recipe C — Build a caller-owned long job with SQL, MongoDB, Celery, and reads

Target: `POST /v1/sessions` creates a scenario run, workers generate scenarios, and `GET /v1/sessions/{session_id}` plus `/results` expose persisted progress/results. This is the pattern to use for long-running entity-owned work.

**C1. Fix the request contract.** The caller supplies all four headers: `X-API-Key`, `X-User-Id`, `X-Entity-Id`, `X-Tenant-Id`. The JSON body contains a positive `asset_id` and `supporting_system_id` (one positive ID or a nonempty list of distinct positive IDs); optional service/sector/subsector IDs are bounded SQL IDs. Unknown fields are 422. Optional `Idempotency-Key` is bounded. A new run returns `202 RunBoard`; replay of the same key/body returns 200 and the same ID. Another run of the same asset never blocks a start (D43).

**C2. Create the shape in `app/schemas/scenarios.py`.** `StartRunRequest` has `extra="forbid"`, a `SqlId` type constrained to SQL Server INT, `supporting_system_ids` with the wire alias `supporting_system_id`, and validators to accept one ID and reject empty/repeated lists. `RunBoard` is the response; `SessionStatus` is the projected stored status used by ownership checks. The core request shape is:

```python
SqlId = Annotated[int, Field(gt=0, le=c.Limits.MAX_SQL_INT)]


class StartRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    asset_id: SqlId
    supporting_system_ids: list[SqlId] = Field(validation_alias="supporting_system_id")
    service_id: SqlId | None = None
    sector_id: SqlId | None = None
    subsector_id: SqlId | None = None

    @field_validator("supporting_system_ids", mode="before")
    @classmethod
    def accept_a_single_id(cls, value: object) -> object:
        return [value] if isinstance(value, int) else value
```

Keep the `check_supporting_systems()` validator in the existing file too: it rejects an empty list, duplicate IDs, and a configured maximum. Its messages come from `SessionMessage`.

**C3. Authenticate before reading data.** `Caller` invokes `get_authenticated_principal()` in `app/api/deps.py`. It checks the active API key and all identity headers, then returns `Principal(client_id,user_id,entity_id,tenant_id)`. Pass `principal.entity_id` to the SQL repository. Never use an `entity_id` from JSON to authorize a run.

**C4. Read and validate SQL facts in `app/crud/scenarios.py`.** `get_asset_context()` executes `StoredProcedure.GET_ASSET_CONTEXT` with named `EntityID`, `AssetID`, `SystemIDs`, `ServiceID`, `SectorID`, and `SubsectorID`. The procedure returns five result sets; `AssetContextRows` in `app/schemas/scenario_internal.py` holds them. `build_run_context()` in `app/domain/scenario/session.py` refuses missing/unauthorized/unlinked facts and freezes the stable context. A refusal happens **before** MongoDB insertion.

```python
asset, services, sector, systems, options = get_stored_procedure_client().execute_procedure(
    c.StoredProcedure.GET_ASSET_CONTEXT,
    EntityID=entity_id,
    AssetID=request.asset_id,
    SystemIDs=json.dumps(request.supporting_system_ids),
    ServiceID=request.service_id,
    SectorID=request.sector_id,
    SubsectorID=request.subsector_id,
)
return AssetContextRows(
    asset=asset[0] if asset else None,
    services=services,
    sector=sector[0] if sector else None,
    systems=systems,
    options=options,
)
```

**C5. Make MongoDB arbitrate races.** `ThreatScenarioSessionRepository` in `app/crud/scenarios.py` has a partial unique index on `(entity_id,idempotency_key)` when a key exists. Sessions of one asset are isolated, so nothing limits how many run at once (D43); `create_indexes()` drops the old `(entity_id,asset_id)` index `entity_id_1_asset_id_1` when a database still has it. `create_scenario_session()` inserts a queued record and reports a key clash. Do not implement uniqueness with a read-then-insert check alone; two HTTP requests can read the same empty state.

```python
_SESSION_INDEXES = (
    {
        "keys": [("entity_id", 1), ("idempotency_key", 1)],
        "unique": True,
        "partialFilterExpression": {"idempotency_key": {"$exists": True}},
    },
    {"keys": [("entity_id", 1), ("status", 1), ("created_at", 1)]},
    {
        "keys": [("entity_id", 1), ("created_at", 1)],
        "name": "controls_waiting_by_entity",
        "partialFilterExpression": {"counts.controls_waiting": {"$gt": 0}},
    },
)
```

**C6. Write the steps in this exact order in `_start_run()`.** It is the one helper both starts call: `create_threat_scenario_session()` (`POST /v1/sessions`) and `create_attack_scenario_session()` (`POST /v1/create_session`, which passes `pipeline=c.RunPipeline.ATTACK`: the AI writes the scenarios from MITRE ATT&CK and the stored `tsg_attack` data confirms them). (1) Look for an earlier request with this key and replay it; when the key is derived (the caller sent none), refuse the repeat with 409 `duplicate_request` (`app/domain/shared/idempotency.py`) instead. (2) If intelligence is on, refuse a run when no active evidence snapshot has data; an attack run is refused instead when `tsg_attack` is empty and, once step 4 knows the asset, when it lacks the ATT&CK matrix the asset needs (both 409 `intel_no_data`). (3) Get SQL facts for the caller's entity. (4) Build and freeze the run context. (5) Build and insert the queued session. (6) If an insert raced, replay the matching winner or raise the named 409. (7) Send the record's own job task with the stored ID/epoch: `TaskName.FIND_THREATS`, or `TaskName.WRITE_SCENARIOS` for an attack run, which has no threat finding. (8) Audit the start. (9) Return `(RunBoard, created)`. The exact code is in `app/domain/scenario/runs.py`; its helpers `_replay` and `_refuse_without_data` implement the branches:

```python
if replayed := _replay(principal, request, idempotency_key, derived, pipeline):
    return rules.build_status_board(replayed), False
_refuse_without_data(pipeline)
asset_context = get_asset_context(principal.entity_id, request)
context = build_run_context(request, asset_context)
if pipeline is not None:
    _refuse_without_data(pipeline, context)
record = _new_run_record(principal, request, idempotency_key, context, pipeline)
clash = get_threat_scenario_session_repository().create_scenario_session(record)
if clash and (replayed := _replay(principal, request, idempotency_key, derived, pipeline)):
    return rules.build_status_board(replayed), False
if clash is c.RunClash.IDEMPOTENCY_KEY:  # the run that took the key was deleted since
    message = c.SessionMessage.IDEMPOTENCY_KEY_RUN_GONE
    raise Conflict(message, reason=c.ConflictReason.IDEMPOTENCY_KEY_CONFLICT)
send_job(record["job"]["task"], record["_id"], record["job"]["epoch"])
metrics.RUNS.labels(c.RunKind.GENERATED).inc()
get_audit_repository().create_audit_record(
    c.AuditAction.RUN_STARTED,
    caller_actor(principal),
    audit_target(c.AuditTarget.SESSION, record["_id"]),
    after={"asset_id": record["asset_id"], "supporting_system_ids": record["request"]["supporting_system_ids"]},
)
return rules.build_status_board(session_status_from_record(record)), True
```

**C7. Make the route one call.** In `app/api/routes/scenarios.py`, `start_run()` receives `views.StartRunRequest`, `Response`, `Caller` and `IdempotencyKey`. It calls `runs.create_threat_scenario_session()` once, returns the board, and sets status 200 only when `created=False`:

```python
@router.post("/v1/sessions", status_code=202, response_model=views.RunBoard, summary="1. Start a run")
def start_run(
    body: views.StartRunRequest, response: Response, principal: Caller, idempotency_key: IdempotencyKey
) -> views.RunBoard:
    board, created = runs.create_threat_scenario_session(
        principal, body, idempotency_key.value, derived=idempotency_key.derived
    )
    if not created:
        response.status_code = 200
    return board
```

`create_session()`, right below it in the same file, is the same route for `POST /v1/create_session`: it calls `runs.create_attack_scenario_session()` and nothing else differs.

`IdempotencyKey` (`app/api/deps.py`) is the one dependency of all five idempotent routes (`POST /v1/sessions`, `POST /v1/create_session`, `POST /v1/remediation`, `POST /v1/service-mapper`, `POST /v1/service-mapper/{mapping_id}/regenerate`). It returns `RequestIdempotencyKey(value, derived)`: the caller's `Idempotency-Key`, else `derived-` + SHA-256 of the caller (tenant, entity, user, client), method, path, a fixed 60 s window (`Idempotency.DERIVED_WINDOW_SECONDS`, MongoDB's clock) and the raw body. `derived` says the caller sent none: only then is a repeat refused (409 `duplicate_request`, `details` the first record's ids and `started_seconds_ago`); a key the caller sends always replays, an echoed `derived-...` one too. It stores the key on `request.state`, so `RequestContextMiddleware` echoes it in the `Idempotency-Key` response header (CORS-exposed in `app/main.py`) and logs it as `idempotency` on the `http.request` line (not `..._key`: the log masking hides such fields), the same value on the first request and every repeat. Example: a double click with no key gets 202, then 409 `duplicate_request` naming the run; the same two calls with `Idempotency-Key: k-42` get 202, then 200 with the same run.

`GET /v1/sessions/{session_id}` uses `CallersRun` (`valid_session()` in `app/api/deps.py`), which calls `runs.get_threat_scenario_session_status()`: 404 unknown, 403 another entity's. `GET .../results` uses the same dependency plus `Offset`/`Limit`.

**C8. Run three tasks, not one long HTTP call.** `app/worker/scenario/tasks.py:find_threats` takes `(record_id,epoch)` and, under `run_leased_job()`, calls `plan_run()` in the same file with `find_threats()` from `app/domain/scenario/plan.py`. `plan_run()` stores the plan and hands the lease to `WRITE_SCENARIOS`; `write_scenario_batch()` (`write_job.py`) writes versions; `map_threat_scenario_controls()` (`controls_job.py`) maps controls. Task routes send the first to `tsg_threats`, the writer to `tsg_scenarios` and control mapping to `tsg_controls`; a stage's hand-over is sent ahead of new work (`Worker.NEXT_STAGE_PRIORITY`). The task body must check the lease before persisting an answer; a stale delivery may continue running after a replacement worker claims the record.

```python
@celery_app.task(name=c.TaskName.FIND_THREATS, bind=True)
def find_threats(self: Task, record_id: str, epoch: int) -> None:

    def plan_it(lease: JobLease) -> None:
        models = (
            ai.chat.get_scenario_chat_model(),
            get_library_search(),
            ai.rerank.get_rerank_model(),
            ai.embeddings.get_embedding_model(),
        )
        plan_run(lease, partial(plan.find_threats, *models), get_intelligence_switch())

    run_leased_job(self, c.Collection.SESSIONS, record_id, epoch, plan_it, fields=PLAN_JOB_FIELDS)
```

**C9. Read stored status, not Celery results.** `runs.get_threat_scenario_session_status()` (through `CallersRun`) reads a small session projection and checks ownership. `build_status_board()` in `app/domain/scenario/session.py` turns it into `RunBoard`. `runs.list_threat_scenarios_of_session()` reads paged current versions with their old versions (`include_replaced`, default `true`; `false` leaves them out). The GET routes remain useful when Redis event delivery is delayed.

**C10. Run the tests in this order.**

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_runs.py -q
.\.venv\Scripts\python.exe -m pytest tests/test_worker.py tests/test_scenario_writing.py -q
.\.venv\Scripts\python.exe -m pytest tests/test_realtime.py -q
```

`tests/test_runs.py` verifies 202 with a queued claimable record, exact frozen SQL facts, refused facts, 422 bad input, two parallel starts on one asset, same-key replay, and status/results views. Then perform the manual end-to-end call below. Keep the `session_id` from POST; poll its status and read scenarios. If a worker fails, inspect `job.error` and the request ID in logs rather than reissuing a new start with another key.

**C11. Know which failure to investigate.**

| Observation | Check first |
| --- | --- |
| 401 before the route runs | API key and all four identity headers in `app/api/deps.py` |
| 403/404 asset or session | Caller entity, `tsg_GetAssetContext` result, or `CallersRun` ownership check |
| 409 idempotency_key_conflict | The (entity_id, idempotency_key) unique index and `_replay` in `app/domain/scenario/runs.py` |
| 409 duplicate_request | No `Idempotency-Key` was sent and the same request came in the same 60 s window: the `idempotency` field of both `http.request` lines is the same |
| 422 missing facts | Request validation and `build_run_context()` error details |
| 202 stays queued | `tsg_threats` worker heartbeat, broker, reaper, stored job due time |
| Threats done but scenarios not written | `WRITE_SCENARIOS` route/worker, lease handoff and `job.error` |
| Scenarios exist but controls wait | `MAP_CONTROLS` task and the `RETRY_CONTROLS` sweep on `tsg_reaper` |

Every other operation follows the same order: schema → crud → domain rules → route with its `Depends` → worker (if needed) → test → HTTP proof.

## Run, test, and hand over

### Wire the app once

Routes take the settings and the pooled stores through the `Depends` aliases in `app/api/deps.py`. A long-lived object (a repository, a search index, a job object) has a `@singleton` getter (`app/core/singletons.py`) next to its class; a new one gets its getter there. `create_all_indexes()` includes every MongoDB collection. `application_lifespan()` in `app/main.py` creates indexes and builds the AI gateways; `prepare_worker()` in `app/worker/lifecycle.py` does the same for a worker. `app/main.py` includes all routers in the documented Swagger order (library curation is part of admin):

```text
health → admin → external intelligence → sessions → review →
remediation → jobs → session/plan events → service mapper → AI usage
```

Run `.\.venv\Scripts\python.exe -m ruff check app tests scripts` and `.\.venv\Scripts\python.exe -m mypy app` after wiring. Fix every new diagnostic; report any still-existing baseline errors separately. `tests/test_code_conventions.py` checks layer directions, database call placement, shape placement, singleton placement, and code size.

### Start the real local stack

Ensure SQL Server, MongoDB, Redis, and required AI endpoints work, then use **Windows PowerShell 5.1**:

```powershell
.\run_dev.ps1 -NoBrowser
.\run_dev.ps1 status
Invoke-RestMethod http://127.0.0.1:8000/health
Invoke-RestMethod http://127.0.0.1:8000/ready
```

The web UI is then at `http://127.0.0.1:8000/ui/`: the files in `app/ui`, mounted by `app/api/ui.py` in `create_app()`. It is a mount, not a router, so it is not in the OpenAPI document. Plain ES modules, no build: `app.js` (shell, sign-in, routing `#/<page>/<param>`, the page table), `api.js` (every call), `session.js` (the tab's sign-in, the only file that uses browser storage), `stream.js` (live events via `fetch`), `poll.js`, `dom.js` (every builder), `export.js` (Word, print), `scenario_view.js` (the run pages' cards and drawer) and one file per page in `pages/`. A page may call only routes that exist and may hold nothing the content policy forbids (`tests/test_admin_ui.py` checks every file; `tests/admin_ui_checks.mjs` and `tests/admin_ui_shell_checks.mjs` run the modules and the shell under node).

`/ready` reports the live workers on each **routed** queue (only MongoDB decides its status). The local script starts the API; one worker on `tsg_threats,tsg_scenarios,tsg_controls` (plus `tsg_remediation`, which gets a worker of its own when `CII_RERANK_BASE_URL` points to a remote reranker); one each on `tsg_servicemapper`, `tsg_maintenance` and `tsg_reaper` (`reaper@`, metrics port 9104); and beat. SQL Server health appears in the response but does not alone fail readiness. Stop with `.\run_dev.ps1 stop`.

### Run tests without touching application data

`tests/conftest.py` uses a checkout-specific MongoDB test database, a checkout-specific SQL test database, and spare Redis databases (default 14,15, set by `CII_TEST_REDIS_DATABASES`: never 0, 1 or one your `.env` uses). It may drop and recreate the test databases and flush the chosen Redis databases. A run claims both Redis databases (renewed while it lasts) and stops at once when another run holds either one. Check the target addresses and spare numbers first. Then run narrow tests for the changed area and the full suite:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_code_conventions.py -q
.\.venv\Scripts\python.exe -m pytest tests/test_runs.py -q
.\.venv\Scripts\python.exe -m pytest -q
```

Every pytest command needs SQL Server, MongoDB, and Redis reachable, because `tests/conftest.py` has a session-wide autouse database fixture. Narrow tests by area:

| Area | Command |
| --- | --- |
| Settings, repositories, library | `.\.venv\Scripts\python.exe -m pytest tests/test_config.py tests/test_base_repository.py tests/test_library.py -q` |
| Probes | `.\.venv\Scripts\python.exe -m pytest tests/test_health.py -q` |
| API keys and admin jobs | `.\.venv\Scripts\python.exe -m pytest tests/test_api_clients.py tests/test_embeddings_builds.py -q` |
| Library curation and AI models | `.\.venv\Scripts\python.exe -m pytest tests/test_library_curation.py tests/test_model_profiles.py -q` |
| Workers and leases | `.\.venv\Scripts\python.exe -m pytest tests/test_worker.py -q` |
| Session start and reads | `.\.venv\Scripts\python.exe -m pytest tests/test_runs.py -q` |
| Scenario writing, review, job control | `.\.venv\Scripts\python.exe -m pytest tests/test_scenario_writing.py tests/test_review.py tests/test_job_control.py -q` |
| Remediation | `.\.venv\Scripts\python.exe -m pytest tests/test_remediation_api.py tests/test_remediation_plan.py tests/test_remediation_manual.py tests/test_remediation_schedule.py -q` |
| External intelligence | `.\.venv\Scripts\python.exe -m pytest tests/external_intelligence -q` |
| Live updates | `.\.venv\Scripts\python.exe -m pytest tests/test_realtime.py -q` |
| Service Mapper | `.\.venv\Scripts\python.exe -m pytest tests/test_service_mapper.py -q` |

A connection or login failure is an environment failure; record it and repair the store, then rerun. If a restricted execution environment blocks local Redis, run the integration suite on the approved development machine with the same disposable database settings and record its output.

### Check the outside contract deliberately

`tests/test_outside_contract.py` pins OpenAPI, stored enums/names, Celery routes/schedule, and MongoDB indexes. For a **deliberate approved** contract change, check that `tests/contract/` has no unrelated pending edits, regenerate the pins, inspect **every** diff, then rerun without the writer variable:

```powershell
$env:TSG_WRITE_CONTRACT = '1'
.\.venv\Scripts\python.exe -m pytest tests/test_outside_contract.py -q
Remove-Item Env:TSG_WRITE_CONTRACT
git diff -- tests/contract
.\.venv\Scripts\python.exe -m pytest tests/test_outside_contract.py -q
```

The writer rewrites **all** pins. Remove the environment variable even if its first pytest run fails. Keep only the intended contract diff; do not accept an unrelated route, enum, queue, or index change merely to pass a test.

### Perform a manual end-to-end call

`debug/tsg.http` (VS Code REST Client) holds the health, API-key and live-update calls and a few refusals; `debug/.env.example` lists its variables and ignored `debug/.env` holds development identity values. Send the other calls from Swagger (`/docs`) with the same headers. Keep real keys out of screenshots and PR text. Use a real development identity and linked asset/system IDs supplied for the test entity. Follow this sequence:

| Step | Request to send | Expected result and next value |
| ---: | --- | --- |
| 1 | `GET /health`, then `GET /ready` | 200; proceed when ready is `ready`. |
| 2 | `POST /v1/tsg/api-clients` with `X-Admin-Key` and `{"name":"junior-dev-smoke"}` | 201; copy the one-time `api_key` into ignored `debug/.env`. Use another unique name on a later run. |
| 3 | `POST /v1/sessions` with `X-API-Key`, `X-User-Id`, `X-Entity-Id`, `X-Tenant-Id`, `Idempotency-Key`, and `{"asset_id":<owned_asset_id>,"supporting_system_id":[<linked_system_id>]}` | 202; save `session_id`. Repeating the same key and body returns 200 and the same ID; the same body without a key, twice in the same 60 s window, returns 202 then 409 `duplicate_request`. Both answers carry an `Idempotency-Key` header. Replace the angle-bracket ID placeholders with actual numbers before sending. |
| 4 | `GET /v1/sessions/{session_id}` until `progress.overall` reaches `awaiting_review`, `awaiting_next_set`, `complete`, `error`, or `cancelled`; then `GET /v1/sessions/{session_id}/results` | 200; save a returned `scenario_id`. If the run has no scenario, inspect its persisted status/error and worker logs before proceeding. |
| 5 | `POST /v1/sessions/{session_id}/accept` with `{"scenario_ids":["<scenario_id>"]}` | 200; the selected scenario is accepted. Replace the placeholder with the returned ID. |
| 6 | `POST /v1/remediation` with `{"is_manual":false,"session_id":"<session_id>","scenario_id":"<scenario_id>"}` | 202; save `remediation_id` and the returned session/scenario IDs. |
| 7 | `GET /v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan/status` until `latest_status` is `done`, `failed`, or `cancelled`; if done, `GET /v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan` | 200; a done result contains a readable plan. For failed/cancelled, record the status error and investigate the job. |
| 8 | Retry the supported idempotent call; send a missing key, malformed body, unknown ID, and other entity's ID to the applicable route | Replay does not duplicate work; refusals have expected status and `application/problem+json`. |

At each step, check the actual response model, `X-Request-Id`, audit entry for a mutation, worker state for a queued action, and the stored result. If a step fails, use its request ID to find the sanitized API/worker log and inspect the saved job state before changing code.

### Final handover gate

- [ ] Every operation in `tests/contract/openapi.json` is registered and has the correct auth dependency; `/metrics` is intentionally hidden from OpenAPI.
- [ ] Every mutation has explicit ownership, atomic persistence, audit, retry/idempotency behavior, and a response the client can follow.
- [ ] Every long job has a stored queued record, a registered/routed task, a staffed queue, lease fencing, recovery, terminal status, and a status endpoint.
- [ ] Every new SQL procedure has its `scripts/sql/tsg_<Name>.sql` file, `StoredProcedure` member, grant in `scripts/sql/grants.sql`, repository call, and test schema coverage; every new MongoDB collection has indexes at startup.
- [ ] Ruff and convention tests pass; mypy has no new errors relative to the recorded baseline; relevant tests and the full suite pass against disposable stores.
- [ ] Any OpenAPI/stored-name/Celery/index pin change is intentional and reviewed; local startup and the manual smoke pass.
- [ ] Update `debug/tsg.http`, `.env.example`, `run_dev.ps1` and `run_uat.ps1`, and `deploy/` manifests if the contract, configuration, task routes, or workers changed; update `observability/` (shipped with `oc apply -k observability`) if a metric, alert, or dashboard changed.

If a gate is blocked, hand over the exact command, sanitized error, and missing environment dependency. A route-level test is not proof that the job, storage, and worker path works end to end.

## Appendix — The rules to apply to every change

1. **A route is thin.** It declares FastAPI path/method, typed input, `Depends`, `response_model`, and success status; it calls crud and domain functions directly. No service class only passes a call on.
2. **Schemas are wire shapes; domain functions are decisions.** Put request/response models in `app/schemas/`; an AI answer's shape or a dataclass may sit beside the domain code that uses it. Put business comparisons, view construction, and state transitions in `app/domain/`. Do not move HTTP or driver objects into domain functions.
3. **All storage calls belong to `app/crud/`**. SQL goes through named stored procedures only. MongoDB writes use specific predicates; indexes enforce unique rules. A lost SQL write answer is resolved through the SQL operation record rather than retried blindly.
4. **Ownership is independent of existence.** `Caller` proves the API client/identity. `CallersRun` and `CallersPlan` prove an owned resource. For entity-list paths, compare `{listed_entity_id}` with the principal's entity before listing.
5. **Errors have one format.** Use exceptions in `app/core/exceptions.py` and message/reason constants in `app/core/constants/`; the global handler in `app/api/errors.py` produces the problem body and request ID. 503 includes `Retry-After` where supported.
6. **A Celery message is only a pointer.** Save state first, publish ID/epoch second, fence worker updates by lease, and let the reaper recover missed deliveries. A new `Queue` enum member has no worker until routes, local startup, deployment, and readiness are wired.
7. **A public change changes a pin.** Review `tests/contract/openapi.json`, `celery.json`, `enums.json`, `tsg_names.json`, and `indexes.json` only for the fields the feature intentionally changes.
