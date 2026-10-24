# Build the TSG API: Developer Handbook

This **build runbook** gives the implementation sequence for the API in this repository. Follow the stages in order. Each stage names the files to implement, the calls that must connect, and the check that proves the stage. For a feature request that affects only one stage, complete its prerequisites, change that stage, then run the final checks.

The target is the current **CII Threat Scenario Generator v2** API: FastAPI, MongoDB, SQL Server stored procedures, Redis, Celery, AI gateways, and SSE. [SOLUTION_DESIGN.md](SOLUTION_DESIGN.md) explains *why* the product works this way. The source files named below show the exact current implementation. The Service Mapper is implemented, with its own worker on `tsg_servicemapper`; [service_mapper/SERVICE_MAPPER.md](service_mapper/SERVICE_MAPPER.md) describes the built flow, and Recipe D below is the original build recipe, kept for reference.

## Read this before step 1

The API cannot be implemented correctly from a route name alone. Obtain the approved endpoint contract, SQL schema/data ownership, local store addresses, and AI credentials from the feature or environment owner. For an existing endpoint, `tests/contract/openapi.json` and its router/model/tests are the approved contract. For a new endpoint, record method, path, caller, owner, request, response, errors, retry behavior, persistence, and background work before editing. Do not guess these values.

All commands below use **Windows PowerShell** from the repository root. Use Windows PowerShell **5.1** for `run.ps1`; the script rejects PowerShell 7. Work in the current checkout without discarding unrelated uncommitted changes. A failed build or test command is a gate: fix its stated problem before moving on. Stage 1's mypy command is a **baseline measurement**; record its existing diagnostics, then fix any new ones your work adds.

## The sequence at a glance

| Stage | Build | Working result |
| ---: | --- | --- |
| 1 | Local prerequisites and baseline | Python, configuration, three stores, and a known starting status |
| 2 | Shared core and SQL contract | Valid settings, database clients, errors, constants, eight TSG procedures |
| 3 | MongoDB repositories and indexes | Collection ownership, safe atomic writes, startup indexes |
| 4 | FastAPI shell and public probes | Middleware, problem responses, `/health`, `/ready`, `/metrics` |
| 5 | Admin key bootstrap and caller authentication | Mint/revoke a key; authenticate an entity-scoped request |
| 6 | Library, search, and AI gateways | Read threat/control library; build/search embeddings; curate proposals |
| 7 | Celery runtime and recoverable jobs | Registered tasks, staffed queues, leases, reaper, worker heartbeats |
| 8 | Scenario start and reads | `POST /v1/sessions`, status, results, scenario and entity lists |
| 9 | Scenario generation, review, and job control | Threat/write/control jobs; accept/reject/next set; cancel/delete |
| 10 | Remediation | Plan request, worker, status/result, review/regenerate/cancel/lists |
| 11 | External intelligence | Switch, source refresh, evidence snapshot, health and source controls |
| 12 | SSE and Service Mapper | Live session/plan updates; the Service Mapper and its mapper-only worker (Recipe D, built) |
| 13 | Compose, run, test, and hand over | All routers registered; contract pins, integration tests, manual smoke |

Stages 2–12 describe **implementation order**. This checkout already contains every stage, the Service Mapper included. When reproducing a completed stage, read the named source and tests and avoid duplicate modules.

## Stage 1 — Prepare the machine and record the baseline

1. Open the repository root. Run `git status --short`; write down every pre-existing modification. Do not reset or overwrite it.
2. Install Python 3.12, SQL Server with the approved development database, MongoDB, and Redis. Obtain the approved DSN, MongoDB URL, Redis URLs, AI gateway addresses/keys, and a test identity with an asset and supporting system owned by that entity.
3. Create the virtual environment and install the Python package. Use the first install when `CII_RERANK_BASE_URL` points to a remote reranker; use `.[dev,local]` instead if the local sentence-transformers model is required.

```powershell
git status --short
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]" -c requirements.txt
```

4. Create `.env` only if it is absent. Fill it using `.env.example` and `app/core/config.py`. Do not run with `<secret>` or `<resource>` placeholders. Do not print or commit secrets.

```powershell
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
```

5. Ensure the app uses a dedicated development MongoDB database and approved SQL database. The app Redis URLs normally use database 0 (cache/events) and 1 (Celery broker). Tests default to **spare Redis databases 14 and 15**, which they claim and flush; confirm those databases hold no unrelated data before running pytest. Set `CII_TEST_REDIS_DATABASES` to a different two empty numbers if needed.
6. Record the baseline from Ruff and mypy now, before editing. If mypy reports diagnostics in the current checkout, save that output and distinguish those lines from any new diagnostics introduced by your work.

```powershell
.\.venv\Scripts\python.exe -m ruff check app tests scripts
.\.venv\Scripts\python.exe -m mypy app
```

**Gate:** Python imports the installed package; `.env` has actual development values; you know which working-tree changes and type errors precede your work. Do not run the application or pytest against production stores.

## Cookbook — Follow four requests all the way through

Recipes A–C trace implementations in the current code. Recipe D is the **original build recipe for the Service Mapper**, now implemented; where it differs from the code and [service_mapper/SERVICE_MAPPER.md](service_mapper/SERVICE_MAPPER.md), the code wins. Follow each recipe's file order and gate; do not paste code for A–C into duplicate modules.

### Recipe A — Build an authenticated `GET` from model to HTTP response

Target: `GET /v1/tsg/api-clients?active=true`. It lists active API clients for an administrator, without exposing a secret or its hash.

**A1. Fix the contract before coding.** Method/path: GET `/v1/tsg/api-clients`. Required header: `X-Admin-Key`. Optional query: `active` is `true`, `false`, or absent. Success: 200 `{"items":[...],"total":N}`. Wrong admin key: 401; admin key unset in configuration: 403. No caller `X-API-Key` is involved.

**A2. Define the output in `app/models/admin/api_clients.py`.** FastAPI serializes through this response model, so fields absent from the model are not sent. It does not contain `api_key` or `key_hash`:

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

**A3. Make one repository read in `app/data_access/admin/api_client_repository.py`.** Configure a named projection that excludes the hash. `MongoRepository.list()` handles the actual query; the service must never request an unfiltered full record. The existing constructor is:

```python
def __init__(
    self,
    collection: str | MongoCollection = Collection.API_CLIENTS,
    clock: Callable[[], float] = time.monotonic,
) -> None:
    super().__init__(
        collection,
        indexes=[
            {"keys": "key_hash", "unique": True},
            {"keys": "name", "unique": True, "partialFilterExpression": {"active": True}},
        ],
        field_lists={"without_key_hash": {"key_hash": 0}},
        schema_version=1,
    )
    self._clock = clock
    self._verified: dict[str, tuple[str, float]] = {}
```

The imports and surrounding class are in that file. The two unique indexes prevent duplicate key hashes and duplicate active names; `without_key_hash` prevents the read from fetching the secret's hash.

**A4. Coordinate the read in `app/services/admin/admin_service.py`.** This is the full service method. An absent `active` means no filter; `active=true/false` filters. The repository returns MongoDB `_id`; `_as_client()` turns it into public `client_id`:

```python
def list_api_clients(self, active: bool | None) -> list[dict[str, Any]]:
    where = {} if active is None else {"active": active}
    listed = self._api_clients.list("without_key_hash", sort="-created_at", **where)
    return [_as_client(stored) for stored in listed]
```

**A5. Wire the object once in `app/container.py`.** `get_api_client_repository()` constructs `ApiClientRepository`; `get_admin_service()` passes it and the other admin dependencies into `AdminService`. The router depends on `get_admin_service`, never on a freshly constructed repository.

```python
@singleton
def get_api_client_repository() -> ApiClientRepository:
    return ApiClientRepository()


@singleton
def get_admin_service() -> AdminService:
    return AdminService(
        get_api_client_repository(), get_admin_job_repository(), get_audit_repository(), send_admin_job
    )
```

**A6. Expose the route in `app/api/routers/admin.py`.** Put `Depends(require_admin_api_key)` on this router so every admin route shares the check. The route body only calls the service and wraps its page:

```python
router = APIRouter(dependencies=[Depends(require_admin_api_key)])
Service = Annotated[AdminService, Depends(get_admin_service)]

_API_CLIENTS, _EMBEDDINGS = "/v1/tsg/api-clients", "/v1/embeddings"


@router.get(
    _API_CLIENTS,
    tags=[ApiTag.API_KEYS],
    response_model=ApiClientList,
    summary="2. List API keys",
)
def list_api_clients(service: Service, active: bool | None = None) -> dict:
    items = service.list_api_clients(active)
    return {"items": items, "total": len(items)}
```

Register `admin_router` once in `app/main.py:create_app()`. `app/api/dependencies.py:require_admin_api_key()` performs the comparison; `app/api/errors.py` formats a failure. Add/update the API tag description in `app/api/openapi_docs.py` if the group changes.

**A7. Test the route with the real test client.** `tests/test_api_clients.py` contains the key setup and auth cases. A focused test should mint two clients, revoke one, call this route with `active=true`, and assert: 200; `total == len(items)`; only the active client remains; neither `api_key` nor `key_hash` appears anywhere. Also assert 401 without a valid admin key. Run:

If adding this coverage, import `uuid` in that test file and place this function beside the existing API-client tests:

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

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_api_clients.py -q
```

**A8. Send it manually.** Start the stack in Stage 13, then use the `GET /v1/tsg/api-clients?active=true` block in `debug/tsg.http`. Supply the configured development `X-Admin-Key` when prompted. Expect 200, `items`, `total`, and `X-Request-Id`; no secret or hash. A wrong key must produce `application/problem+json` and 401.

### Recipe B — Build a `202` job and a status endpoint

Target: `POST /v1/embeddings` starts a library vector build; `GET /v1/embeddings/{job_id}` reports its result. This is the **admin-job** pattern. Session and remediation jobs use the leased pattern in Recipe C instead.

**B1. Fix the two HTTP contracts.** Start: admin key, no body, 202 `{"job_id":"...","status":"queued"}`. A second active build is 409 `job_in_progress` with `details.job_id`. Broker unavailable is 503 and the record becomes failed. Status: admin key, 200 `AdminJobOut` with queued/running/done/failed and a result or error; unknown ID is 404.

**B2. Define two models in `app/models/admin/admin_jobs.py`.** `AdminJobStarted` has `job_id: str` and `status: Status`. `AdminJobOut` has `job_id`, `kind`, `status`, `requested_by`, timestamps, optional `result`, and optional `error`. It is returned from MongoDB, not from Celery's result backend.

**B3. Enforce “one active build” in `app/data_access/admin/admin_job_repository.py`.** The repository has a unique partial index on `kind` where `active=True`, plus a TTL on `created_at`. Implement `create_admin_job()`, `get_admin_job()`, `update_admin_job_running()`, and `update_admin_job_finished()`. A duplicate message cannot start work twice because the running update requires `status=QUEUED` and `active=True`. Ending the record unsets `active`, so a later build may start.

The critical claim is an atomic repository update:

```python
def update_admin_job_running(self, job_id: str, now: datetime) -> bool:
    changes = {"status": Status.RUNNING, "started_at": now}
    return self.update(changes, _id=job_id, active=True, status=Status.QUEUED) > 0
```

**B4. Persist before sending in `app/services/admin/admin_service.py`.** `create_embeddings_build()` makes an ID and queued record, then calls the shared `queue_admin_job()` helper. The current method's core is:

```python
job_id = uuid.uuid4().hex
job = {
    "_id": job_id,
    "kind": AdminJobKind.EMBEDDINGS_BUILD,
    "status": Status.QUEUED,
    "requested_by": requested_by,
}
queue_admin_job(
    self._admin_jobs,
    self._send_admin_job,
    TaskName.BUILD_LIBRARY_INDEXES,
    job,
    AdminJobMessage.IN_PROGRESS,
    AdminJobMessage.NOT_SENT,
)
```

`queue_admin_job()` adds `created_at`, inserts the active record, returns 409 with the winner's `job_id` when one already exists, sends the Celery message, and fails the record plus answers 503 if sending fails. Implement its decision branches in this order:

```python
job_id = job["_id"]
active_id = jobs.create_admin_job(job | {"created_at": datetime.now(UTC)})
if active_id != job_id:
    raise Conflict(in_progress, reason=ConflictReason.JOB_IN_PROGRESS, details={"job_id": active_id})
sent = False
try:
    sent = send(task, job_id)
finally:
    if not sent:
        error = {"code": ErrorCode.UNAVAILABLE, "message": not_sent}
        jobs.update_admin_job_finished(job_id, datetime.now(UTC), error=error)
if not sent:
    raise Unavailable(not_sent)
```

The service audits the successful start and returns `{"job_id": job_id, "status": Status.QUEUED}`. `get_embeddings_build(job_id)` reads only the embedding-build kind, returns the stored status, and raises `NotFound` for an unknown ID.

**B5. Put the two thin routes in `app/api/routers/admin.py`.** The admin router's key dependency covers both:

```python
@router.post(
    _EMBEDDINGS,
    tags=[ApiTag.EMBEDDINGS],
    status_code=202,
    response_model=AdminJobStarted,
    summary="1. Build the library's search vectors now",
)
def start_embeddings_build(service: Service, actor: AdminUser) -> dict:
    return service.create_embeddings_build(actor)


@router.get(
    f"{_EMBEDDINGS}/{{job_id}}",
    tags=[ApiTag.EMBEDDINGS],
    response_model=AdminJobOut,
    summary="2. Read a build",
)
def read_embeddings_build(job_id: Annotated[str, Path(max_length=64)], service: Service) -> dict:
    return service.get_embeddings_build(job_id)
```

**B6. Register the worker in three places, in order.** In `app/core/constants/jobs.py`, route `TaskName.BUILD_LIBRARY_INDEXES` to `Queue.MAINTENANCE`. In `app/worker/celery_app.py:TASK_MODULES`, include `app.worker.admin.library_indexes`. In `app/worker/admin/library_indexes.py`, decorate `build_library_indexes` with that task name. The task imports the container inside the function, claims the saved job with `update_admin_job_running`, builds the snapshot/vectors, then saves `DONE` and counts or `FAILED` and an error. `run.ps1` already starts a `tsg_maintenance` worker. `/ready` should see that worker.

```python
@celery_app.task(name=TaskName.BUILD_LIBRARY_INDEXES)
def build_library_indexes(job_id: str | None = None) -> None:
    from app import container

    if job_id is None:  # beat's scheduled build has no admin-job record
        container.get_library_search().snapshot(wait=True)
        return
    run_embeddings_job(
        job_id,
        container.get_admin_job_repository(),
        container.get_library_cache(),
        container.get_library_search(),
        container.get_embedding_repository(),
        container.get_audit_repository(),
    )
```

`run_embeddings_job()` is in the same file. It returns immediately if the atomic running claim fails, and writes a terminal `result` or `error` only while this job still owns its active record.

**B7. Test every state transition.** Run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_embeddings_builds.py -q
```

The tests cover 202 queued, 409 second build, stale job replacement, 503 failed send, worker completion/failure, and the status read. For manual verification, use the two embedding requests in `debug/tsg.http`: save `job_id` from POST, poll GET until `done` or `failed`, and inspect `result.counts` or `error`. A second POST while one runs should name the first job in its 409 response.

### Recipe C — Build a caller-owned long job with SQL, MongoDB, Celery, and reads

Target: `POST /v1/sessions` creates a scenario run, workers generate scenarios, and `GET /v1/sessions/{session_id}` plus `/results` expose persisted progress/results. This is the pattern to use for long-running entity-owned work.

**C1. Fix the request contract.** The caller supplies all four headers: `X-API-Key`, `X-User-Id`, `X-Entity-Id`, `X-Tenant-Id`. The JSON body contains a positive `asset_id` and `supporting_system_id` (one positive ID or a nonempty list of distinct positive IDs); optional service/sector/subsector IDs are bounded SQL IDs. Unknown fields are 422. Optional `Idempotency-Key` is bounded. A new run returns `202 RunBoard`; replay of the same key/body returns 200 and the same ID. An active run for the asset returns 409.

**C2. Create the shape in `app/models/scenario/views.py`.** `StartRunRequest` has `extra="forbid"`, a `SqlId` type constrained to SQL Server INT, `supporting_system_ids` with the wire alias `supporting_system_id`, and validators to accept one ID and reject empty/repeated lists. `RunBoard` is the response; `SessionStatus` is the projected stored status used by ownership checks. The core request shape is:

```python
SqlId = Annotated[int, Field(gt=0, le=Limits.MAX_SQL_INT)]


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

**C3. Authenticate before reading data.** `Caller` invokes `get_authenticated_principal()` in `app/api/dependencies.py`. It checks the active API key and all identity headers, then returns `Principal(client_id,user_id,entity_id,tenant_id)`. Pass `principal.entity_id` to the SQL repository. Never use an `entity_id` from JSON to authorize a run.

**C4. Read and validate SQL facts in `app/data_access/scenario/asset_repository.py`.** `get_asset_context()` executes `StoredProcedure.GET_ASSET_CONTEXT` with named `EntityID`, `AssetID`, `SystemIDs`, `ServiceID`, `SectorID`, and `SubsectorID`. The procedure returns five result sets; `AssetContextRows` in `app/models/scenario/asset_context.py` holds them. `freeze_context()` in `app/domain/scenario/plan.py` refuses missing/unauthorized/unlinked facts and creates the stable context. A refusal happens **before** MongoDB insertion.

```python
asset, services, sector, systems, options = self._procedures.execute_procedure(
    StoredProcedure.GET_ASSET_CONTEXT,
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

**C5. Make MongoDB arbitrate races.** `ThreatScenarioSessionRepository` in `app/data_access/scenario/threat_scenario_session_repository.py` has a partial unique index on `(entity_id,asset_id)` for active runs and another on `(entity_id,idempotency_key)` when a key exists. `create_scenario_session()` inserts a queued record and reports which unique rule lost. Do not implement uniqueness with a read-then-insert check alone; two HTTP requests can read the same empty state.

```python
_SESSION_INDEXES = (
    {
        "keys": [("entity_id", 1), ("asset_id", 1)],
        "unique": True,
        "partialFilterExpression": {"active": True},
    },
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

**C6. Write the service steps in this exact order in `ThreatScenarioService.create_threat_scenario_session()`.** (1) If a key was sent, look for a matching earlier request and replay it. (2) If intelligence is on, refuse a run when no active evidence snapshot has data. (3) Get SQL facts for the caller's entity. (4) Freeze the context. (5) Build and insert the queued session. (6) If an insert raced, replay the matching winner or raise the named 409. (7) Send `TaskName.FIND_THREATS` with the stored ID/epoch. (8) Audit the start. (9) Return `(RunBoard, created)`. The exact existing method is in `app/services/scenario/threat_scenario_service.py`; its helpers `_replay`, `_refuse_without_intel_data`, and `_announce_start` implement the branches.

The success path is visible in these existing lines; retain the clash branches between `create_scenario_session()` and `_announce_start()`:

```python
if idempotency_key and (replayed := self._replay(principal, request, idempotency_key)):
    return build_board(replayed), False
self._refuse_without_intel_data()
asset_context = self._assets.get_asset_context(principal.entity_id, request)
context = freeze_context(request, asset_context)
record = _new_run_record(principal, request, idempotency_key, context)
clash = self._sessions.create_scenario_session(record)
if clash and idempotency_key and (replayed := self._replay(principal, request, idempotency_key)):
    return build_board(replayed), False
if clash is RunClash.ACTIVE_RUN:
    active_id = self._active_session_id(principal.entity_id, request.asset_id)
    message = SessionMessage.ACTIVE_SESSION_EXISTS.format(asset_id=request.asset_id)
    raise Conflict(
        message, reason=ConflictReason.ACTIVE_SESSION_EXISTS, details={"active_session_id": active_id}
    )
if clash is RunClash.IDEMPOTENCY_KEY:
    raise Conflict(
        SessionMessage.IDEMPOTENCY_KEY_RUN_GONE,
        reason=ConflictReason.IDEMPOTENCY_KEY_CONFLICT,
    )
self._announce_start(principal, record, context)
return build_board(session_status_from_record(record)), True
```

**C7. Make the router one call.** In `app/api/routers/scenario.py`, `start_run()` receives `StartRunRequest`, `Caller`, the injected `ThreatScenarioService`, `Response`, and `Idempotency-Key`. It calls the service once, returns the board, and sets status 200 only when `created=False`:

```python
@router.post("/v1/sessions", status_code=202, response_model=RunBoard, summary="1. Start a run")
def start_run(
    body: StartRunRequest,
    response: Response,
    principal: Caller,
    scenarios: Scenarios,
    idempotency_key: Annotated[
        str | None, HeaderParam(alias=Header.IDEMPOTENCY_KEY, max_length=Limits.MAX_IDEMPOTENCY_KEY_CHARS)
    ] = None,
) -> RunBoard:
    board, created = scenarios.create_threat_scenario_session(principal, body, idempotency_key)
    if not created:
        response.status_code = 200
    return board
```

`GET /v1/sessions/{session_id}` uses `CallersRun`, which performs 404/403 ownership before `get_threat_scenario_session()`. `GET .../results` uses the same dependency plus `Offset`/`Limit`.

**C8. Run three tasks, not one long HTTP call.** `app/worker/scenario/tasks.py:find_threats` takes `(record_id,epoch)` and calls `PlanJob.plan_threat_scenario_session()` under `run_leased_job()`. `PlanJob` stores the plan and hands the lease to `WRITE_SCENARIOS`; `ScenarioWriteJob` writes versions; `ControlsJob` maps controls. Task routes send the first to `tsg_threats`, the writer to `tsg_scenarios` and control mapping to `tsg_controls`; a stage's hand-over is sent ahead of new work (`Worker.NEXT_STAGE_PRIORITY`). The task body must check the lease before persisting an answer; a stale delivery may continue running after a replacement worker claims the record.

```python
@celery_app.task(name=TaskName.FIND_THREATS, bind=True)
def find_threats(self: Task, record_id: str, epoch: int) -> None:
    from app import container

    def plan(lease: JobLease) -> None:
        container.get_plan_job().plan_threat_scenario_session(lease)

    run_leased_job(self, Collection.SESSIONS, record_id, epoch, plan, fields=("context",))
```

**C9. Read stored status, not Celery results.** `ThreatScenarioService.get_threat_scenario_session_status()` reads a small session projection and checks ownership. `app/domain/scenario/results.py:build_board()` turns it into `RunBoard`. `list_threat_scenarios_of_session()` reads paged current versions; `include_replaced=true` adds old versions. The GET routes remain useful when Redis event delivery is delayed.

**C10. Run the tests in this order.**

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_runs.py -q
.\.venv\Scripts\python.exe -m pytest tests/test_worker.py tests/test_scenario_writing.py -q
.\.venv\Scripts\python.exe -m pytest tests/test_realtime.py -q
```

`tests/test_runs.py` verifies 202 with a queued claimable record, exact frozen SQL facts, 403 foreign asset, 422 bad input, 409 active-run race, 200 same-key replay, and status/results views. Then perform the manual session sequence in Stage 13.5. Keep the `session_id` from POST; poll its status and read scenarios. If a worker fails, inspect `job.error` and the request ID in logs rather than reissuing a new start with another key.

**C11. Know which failure to investigate.**

| Observation | Check first |
| --- | --- |
| 401 before a service call | API key and all four identity headers in `app/api/dependencies.py` |
| 403/404 asset or session | Caller entity, `tsg_GetAssetContext` result, or `CallersRun` ownership check |
| 409 active run/idempotency | Session unique indexes and the service replay branch |
| 422 missing facts | Request validation and `freeze_context()` error details |
| 202 stays queued | `tsg_threats` worker heartbeat, broker, reaper, stored job due time |
| Threats done but scenarios not written | `WRITE_SCENARIOS` route/worker, lease handoff and `job.error` |
| Scenarios exist but controls wait | `MAP_CONTROLS` task and maintenance `RETRY_CONTROLS` sweep |

After these recipes, use Stages 2–13 as the component-by-component build order for the rest of the 45 operations. The same model → repository → domain/service → route → provider → worker (if needed) → test → HTTP proof sequence applies to each.

### Recipe D — Build Service Mapper end to end, with its own worker

**Outcome:** replace the six canned Service Mapper routes with a persisted, entity-owned mapping job. The API resolves the selected service, freezes one request's inputs, sends **only the mapping ID and job epoch** to a worker consuming **only `tsg_servicemapper`**, validates the AI's exact JSON before saving it, supports review and regeneration, and streams real status changes. Work through D1–D16 in order. The current router and models exist; the mapper repository, task, job, SQL inventory read, and dedicated worker do not. None of the code in this recipe is implemented merely because `Queue.SERVICEMAPPER` already exists.

**D1. Record the contract and trust boundary.** Keep the existing six paths in `app/api/routers/service_mapper.py`:

| Call | Input | Persisted outcome / error |
| --- | --- | --- |
| `POST /v1/service-mapper` | Caller, `Idempotency-Key`, selected service | 202 `{mapping_id,status:"queued",generation:1}`; same key/body replays; same key with changed body returns 409 |
| `GET /v1/service-mapper/{mapping_id}` | Caller, ID | Current status, selected identity, exact dependency analysis when done, and reviewable recommendations; 404 unknown, 403 other entity |
| `GET /v1/entities/{listed_entity_id}/services` | Caller, entity ID | SQL-backed, entity-scoped canonical inventory; 403 other entity |
| `POST /v1/service-mapper/{mapping_id}/regenerate` | Caller, ID, optional idempotency key | 202 new generation; 409 while one is queued/running; replay returns same generation |
| `PATCH /v1/service-mapper/recommendations/{recommendation_id}/decision` | Caller, action/comment | Atomic accept/reject; 409 already decided or superseded |
| `GET /v1/service-mapper/{mapping_id}/events` | Caller, ID | Current status immediately, then live `status` SSE events until terminal; 403/404 before opening |

The AI output is **data**, not a review decision. `verified_inventory` confirms only candidate identity in the inventory, not that the dependency exists. Client-supplied free text is never authoritative inventory or evidence. Only the API's approved SQL source may assign an inventory ID. Add contract fields deliberately, then update OpenAPI pins; the current `Recommendation.confidence` is a `high/medium/low` enum and cannot hold the prompt's numeric score. Preserve it for old clients as a derived display band and add the numeric `confidence_score`, `verification_status`, `evidence`, `applicability`, and `applies_to_entities`. Add `analysis: DependencyAnalysis | None` to `MappingView` to expose the **exact prompt JSON** after completion. While queued/running/failed, `analysis` is null. Existing `MappingView.service` and `recommendations` remain available.

**D2. Extend and validate the request before any I/O.** In `app/models/service_mapper/service_map.py`, retain the current exactly-one-of-`service_id`/`service_name` validator. Add required `sector: str` and `subsector: str` (trimmed, nonempty, length-bounded). `sector` must be one of the 15 exact labels in D4. `service_name` may be absent for the ID path because D3 obtains the canonical name. Do not derive the required names from `sector_id` and `sub_sector_id`: those are optional IDs, and the present test schema has no service-to-sector link. If `sector_id` or `sub_sector_id` is sent, D3 must validate its name against SQL taxonomy; a mismatched ID/name pair is 422. Keep `ConfigDict(extra="forbid")`. Do not add raw `entity_context` or `service_inventory` request fields until an authorization and provenance rule exists; D3 builds these optional runtime inputs from trusted application data. Document the changed POST body in OpenAPI:

```json
{
  "entity_id": 123,
  "service_id": 456,
  "sector": "<exact permitted sector label>",
  "subsector": "<actual operational subsector>"
}
```

For an unsaved selected service, send `service_name` instead of `service_id`. The values above illustrate the **HTTP shape only**; never embed a particular service, sector, or subsector in mapper code or prompts. A client with an old body lacking the two required names receives 422 until it is migrated.

Add these fields to the existing class; the pre-existing `service_id`/`service_name` fields and XOR validator stay:

```python
sector: PermittedSector
subsector: str = Field(min_length=1, max_length=255)


@field_validator("sector", "subsector", mode="before")
@classmethod
def strip_classification(cls, value: object) -> object:
    return value.strip() if isinstance(value, str) else value
```

Import `field_validator` as the current file already does, and use the D4 sector enum for `PermittedSector`. The frozen runtime identity is the validated, trimmed request identity; the AI must copy it exactly. In the service, reject a `service_id` that D3 cannot find; the request validator cannot check SQL ownership.

**D3. Provide an authoritative inventory read.** Add `GET_SERVICE_MAPPER_CONTEXT = "tsg_GetServiceMapperContext"` to `StoredProcedure` in `app/core/constants/planning.py`. Create `scripts/sql/tsg_GetServiceMapperContext.sql` and add an `EXECUTE` grant in `scripts/sql/grants.sql`. `tests/sql_test_database.py` automatically installs files matching `tsg_*.sql`; update the expected procedure inventory in `tests/test_sql_procedures.py`. Extend `tests/sql/schema.sql` and `tests/sql/seed.sql` only for facts the procedure actually needs. The reviewed, read-only procedure takes `@EntityID INT`; return one result set of the entity's non-deleted service `id,name` pairs and one result set of active sector/subsector `id,name,parent_id` pairs. In the current test schema, entity membership is `ctm_scan_entity_bu.group_id -> onboarding_services.id` through `ctm_scan_entity_bu.service_id`; `onboarding_sectors` contains `parent_id`. Confirm the same ownership joins against the real platform schema before deploying the procedure. **Do not claim a service-to-sector association from these tables; none is present in `tests/sql/schema.sql`.** If production has an approved association, add it explicitly to the procedure and tests. If no trusted inventory is available, pass no inventory and produce only proposed candidates with null IDs.

A SQL timeout or failed procedure is an unavailable request (503), never an empty inventory. Pass no inventory only when the authoritative source genuinely has no applicable entries or the product has explicitly configured a source-free mode; record that fact in the snapshot.

Use this test-schema query as the procedure's starting point, and compare every table/column and ownership rule with production before applying it there:

```sql
CREATE OR ALTER PROCEDURE dbo.tsg_GetServiceMapperContext @EntityID INT
AS
BEGIN
    SET NOCOUNT ON;
    SELECT DISTINCT s.id, s.name
    FROM dbo.ctm_scan_entity_bu AS b
    JOIN dbo.onboarding_services AS s ON s.id = b.service_id
    WHERE b.group_id = @EntityID AND s.is_deleted = 0
    ORDER BY s.name, s.id;

    SELECT id, name, parent_id
    FROM dbo.onboarding_sectors
    WHERE is_deleted = 0
    ORDER BY name, id;
END;
```

The second result set is a taxonomy, **not** a claimed classification of an inventory service. If entity facts are required, add a separately sourced, entity-scoped result set with explicit provenance; do not assemble context by querying arbitrary tables in a router.

In `scripts/sql/grants.sql`, add `GRANT EXECUTE ON dbo.tsg_GetServiceMapperContext TO [$(AppUser)];` alongside the existing eight grants. Follow the script's existing admin deployment command so the application still has procedure-only SQL access.

In new `app/data_access/service_mapper/service_inventory_repository.py`, call `StoredProcedureClient.execute_procedure(StoredProcedure.GET_SERVICE_MAPPER_CONTEXT, EntityID=principal.entity_id)`. For `service_id`, find that ID in this entity's returned inventory; return 404 if absent and use its canonical name when present. Validate optional `sector_id`/`sub_sector_id` against the returned taxonomy and the supplied names. For `service_name`, keep the supplied name exactly after trimming; never silently substitute a same-sounding inventory entry. Create an immutable `MappingInput` with `service_name`, `sector`, `subsector`, optional trusted entity facts, inventory rows, and source/version metadata. The GET entity-services route reads this provider and returns **an empty array if genuinely empty**, never `MapperSample` data. **Gate:** a foreign service ID cannot be selected and cannot appear in another entity's inventory response.

**D4. Version the prompt and sector vocabulary.** The full user-supplied prompt is preserved in [SERVICE_MAPPER_DEPENDENCY_PROMPT.md](SERVICE_MAPPER_DEPENDENCY_PROMPT.md). Create `app/domain/service_mapper/prompts/dependencies.txt` from that file. Keep its objective, directness rules, direction from selected-service perspective, inventory/evidence rules, entity applicability, confidence/status definitions, exact output schema, empty-array allowance, and no-fabrication rule. In the runtime file, replace Section 1's `{{...}}` placeholders and the selected-service example values in Section 8 with instructions to **copy the three identity values exactly from the JSON user message**. Send actual request values in that separately JSON-encoded user message rather than interpolating untrusted text into system instructions. Save a prompt version/hash on every generation. Define the allowed labels once in `app/core/constants/service_mapper.py` and import that set in request validation and AI output validation:

```text
Advanced & Strategic Manufacturing; Community Development;
Consumer, Health & Essential Goods Manufacturing; Economy; Education;
Emergency & Public Safety; Energy; Environment & Sustainability; Health;
Information and Communication Technology; Public Administration;
Space & Advanced Technology; Tourism; Transport; Urban Planning
```

Construct the user data with `json.dumps` and include `entity_context` and `service_inventory` **only when available**. Store a per-generation snapshot of those exact values **and the static prompt text/hash** so a retry uses the same instructions even during a deployment. A new regeneration may use a new approved prompt version. Another request's context must never be read from process globals, an AI conversation, or a reused cache entry. Treat inventory descriptions and entity text as untrusted data that cannot override instructions. Set input size limits before queueing so the prompt fits `ChatModel.max_prompt_chars`; return a clear 422 for oversized data rather than truncating inventory and falsely calling it complete.

**D5. Model the exact AI result, independently of the HTTP review view.** Add `app/models/service_mapper/dependency_analysis.py` with strict Pydantic models. Use the property names in the prompt exactly; `extra="forbid"` applies at **every nesting level**. The selected-service model has exactly `service_name`, `sector`, `subsector`, `operational_context`. Each item has exactly the eleven properties shown below. Both arrays may be empty:

```python
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class PermittedSector(StrEnum):
    ADVANCED_MANUFACTURING = "Advanced & Strategic Manufacturing"
    COMMUNITY_DEVELOPMENT = "Community Development"
    CONSUMER_MANUFACTURING = "Consumer, Health & Essential Goods Manufacturing"
    ECONOMY = "Economy"
    EDUCATION = "Education"
    EMERGENCY = "Emergency & Public Safety"
    ENERGY = "Energy"
    ENVIRONMENT = "Environment & Sustainability"
    HEALTH = "Health"
    ICT = "Information and Communication Technology"
    PUBLIC_ADMINISTRATION = "Public Administration"
    SPACE = "Space & Advanced Technology"
    TOURISM = "Tourism"
    TRANSPORT = "Transport"
    URBAN_PLANNING = "Urban Planning"


class SelectedService(BaseModel):
    model_config = ConfigDict(extra="forbid")
    service_name: str = Field(min_length=1)
    sector: PermittedSector
    subsector: str = Field(min_length=1)
    operational_context: str = Field(min_length=1)


class DependencyItem(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)
    service_name: str = Field(min_length=1)
    service_id: int | None = Field(strict=True)
    sector: PermittedSector
    subsector: str = Field(min_length=1)
    dependency_type: Literal["Direct"]
    dependency_reason: str = Field(min_length=1)
    applicability: str = Field(min_length=1)
    applies_to_entities: list[int | str]
    confidence: float = Field(strict=True, ge=0, le=1)
    verification_status: Literal["verified_inventory", "evidence_supported", "inferred_candidate"]
    evidence: list[str]


class DependencyAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")
    selected_service: SelectedService
    upstream_services: list[DependencyItem]
    downstream_services: list[DependencyItem]
```

Keep the `PermittedSector` enum in `app/core/constants/service_mapper.py` and import it into this model and D2 (the snippet shows it together so the shape is readable). Reject a JSON array, Markdown fence, extra property, string confidence, unknown sector, missing field, invalid ID type, or a score outside 0–1. `ChatModel` already parses a JSON object and allows **one corrective re-ask**; D6/D10 must still validate the final parsed object. Do not use `answer_item_problems()` for this contract because that helper filters unknown keys and would accept extra output fields.

**D6. Check claims that a schema cannot check.** Add `app/domain/service_mapper/validate_analysis.py` with `validate_analysis(analysis, frozen_input) -> list[str]`. It must report all of these before any recommendation becomes visible:

1. `selected_service.service_name`, `sector`, and `subsector` equal the frozen runtime values exactly; no AI rewrite.
2. Every candidate has a meaningful operational name, allowed sector, nonempty subsector, concrete reason and operating condition. A candidate cannot be the selected service or duplicated within one direction. A candidate sits in **one direction only**, where its direct relationship is strongest (owner, 2026-10-22).
3. For each non-null `service_id`, the ID exists in the **frozen** inventory and its `service_name` is the canonical inventory name. `verified_inventory` requires that match. A null ID cannot be `verified_inventory`; a matched ID must not be overwritten by an invented value.
4. Every `applies_to_entities` value appears in the supplied entity context and is justified by it. If context is absent, the array must be empty. Every evidence entry refers to a supplied source or is a concise description of real supplied evidence; no fake document IDs, links, or observations.
5. `evidence_supported` needs genuine supporting evidence; `inferred_candidate` must not claim verified organizational existence. Confidence remains an estimate and never changes verification status.
6. The dependency text must state the **direct operational edge** in the chosen direction. Code can check format/identity/provenance, but semantic directness needs a human review. Do not auto-accept a model-generated edge.

Return concise problems for the AI's one corrective re-ask. If the second answer still fails, mark the mapping `failed` with a safe `ai_answer_unusable` code; store no partial or invalid recommendations. Never “fix” a wrong direction or unsupported ID by silently changing the model's answer.

**D7. Persist one bounded mapping aggregate.** Add `Collection.SERVICE_MAPPINGS = "tsg_service_mappings"` in `app/core/constants/common.py` and `app/data_access/service_mapper/service_mapping_repository.py` using the project's `MongoRepository` conventions. One document contains `_id`, `entity_id`, creator/client IDs, create idempotency key and request fingerprint, selected-service identity, `status`, `generation`, `job`, current `input_snapshot`, historical generations with prompt version/analysis, and recommendation review records. Give recommendations generated opaque unique IDs so the existing decision route can locate them. Add indexes for `entity_id + created_at`, unique `entity_id + idempotency_key` where a key exists, and `recommendations.recommendation_id` for lookup. A unique multikey index does **not** prevent duplicate IDs inside one document; generate collision-resistant IDs and check duplicates before writing. Add the repository to `container.create_all_indexes()` and `JobRepository` indexes for this collection at worker startup. Set a maximum of 10 retained generations and return a named 409 `generation_limit_reached` on the next regenerate; reject any new document whose BSON encoding would exceed 12 MiB, leaving room below MongoDB's 16 MiB hard limit. Check prompt character size against `ChatModel.max_prompt_chars` before insertion and enforce bounded names, reasons, evidence text, and item counts in the Pydantic models. **Reject an oversized answer rather than truncate defensible results.** Persist full analysis and the review projection in the same fenced update so GET never sees half a round.

The queued document must have `job = new_job(TaskName.MAP_SERVICES, epoch=1, now=now)` and `status=queued` **before** `send_job`. Compute the idempotency fingerprint from normalized request values and entity ID; same key/fingerprint returns the existing mapping, same key/different fingerprint is 409. `send_job` takes only `(mapping_id, epoch)`; inventory, prompt text, and caller headers never go through Celery. A broker send failure leaves the queued record for the existing reaper to resend.

**D8. Implement all six service methods against the repository.** Replace canned logic in `app/services/service_mapper/service_mapper_service.py` and remove `MapperSample` from the runtime path. Keep the method names the router calls. `create_service_mapping` checks `principal.entity_id`, resolves D3 context, stores the frozen input and queued job, sends the task, publishes status, then returns 202. `get_service_mapping` queries by mapping ID and enforces entity ownership before returning current status and persisted result. `list_entity_services` reads D3. `regenerate_service_mapping` requires a terminal round, re-resolves the selected ID and a **fresh** inventory/context snapshot, keeps the selected identity fixed, and starts generation + 1 by atomic compare-and-set; if a canonical selected service has changed, return a conflict and require a new mapping. Mark only undecided recommendations from the previous generation `superseded`; keep prior accepted/rejected history. Replayed regenerate keys return their already-created generation. `decide_service_mapping_recommendation` finds the owning mapping, checks the caller's entity and latest generation, then uses one conditional MongoDB update from `proposed` to accepted/rejected with reviewer, time, and comment. An already-decided or superseded item returns 409, including under concurrent PATCH calls. Record start, regeneration, and review actions through the existing audit repository with entity/client/user IDs. A human decision is an audit action; it does **not** turn `inferred_candidate` into verified evidence.

**D9. Register the mapper-only task and queue.** In `app/core/constants/jobs.py`, add `TaskName.MAP_SERVICES = "tsg_map_services"` and `TaskName.MAP_SERVICES: {"queue": Queue.SERVICEMAPPER}` to `TASK_ROUTES`. Do not add any other task to this queue. Add `"app.worker.service_mapper.tasks"` to `TASK_MODULES` in `app/worker/celery_app.py`. Create `app/worker/service_mapper/tasks.py` with the same two-argument pattern as `app/worker/scenario/tasks.py`:

```python
@celery_app.task(name=TaskName.MAP_SERVICES, bind=True)
def map_services(self: Task, record_id: str, epoch: int) -> None:
    from app import container

    def work(lease: JobLease) -> None:
        container.get_service_mapper_job().map_services(lease)

    run_leased_job(
        self,
        Collection.SERVICE_MAPPINGS,
        record_id,
        epoch,
        work,
        fields=("generation", "input_snapshot"),
    )
```

Add `Collection.SERVICE_MAPPINGS: publish_service_mapping_status` to `JOB_COLLECTIONS` in `app/worker/jobs.py`. This enrolls the mapper in lease renewal, late acknowledgment, outage retries, reaper recovery, stale-epoch fencing, and failure notifications. Add a `get_service_mapper_job()` provider in `app/container.py`. The mapping job in `app/worker/service_mapper/mapping_job.py` reads only `lease.record`/repository data for that generation, calls D10, then writes the complete result through `lease.update_job(...)` with `ended_job_fields(Status.DONE)`; a late or duplicate delivery must not overwrite a newer generation. Use `JobFailed` for a final unusable AI answer and let temporary AI/store outages follow the existing `run_leased_job` retry path.

**D10. Call the AI through the existing gateway.** Add `AiTask.SERVICE_MAPPER` and temperature `0.0` to `app/core/constants/common.py`, so AI-call records and metrics identify this workload. In `app/domain/service_mapper/generate.py`, build one JSON user message from the frozen snapshot and call the existing checked gateway. The core of the function is:

```python
payload = {key: snapshot[key] for key in ("service_name", "sector", "subsector")}
for optional in ("entity_context", "service_inventory"):
    if snapshot.get(optional) is not None:
        payload[optional] = snapshot[optional]
user_prompt = json.dumps(payload, ensure_ascii=False)
system_prompt = snapshot["prompt_text"]


def read_answer(raw: dict[str, object]) -> tuple[DependencyAnalysis | None, list[str]]:
    try:
        analysis = DependencyAnalysis.model_validate(raw)  # never filter unknown keys
    except ValidationError as exc:
        return None, [f"{'.'.join(map(str, error['loc']))}: {error['msg']}" for error in exc.errors()]
    return analysis, validate_analysis(analysis, snapshot)


analysis = ask_ai_and_check(chat, AiTask.SERVICE_MAPPER, (system_prompt, user_prompt), read_answer)
```

Import `json`, `ValidationError`, `DependencyAnalysis`, `validate_analysis`, and `ask_ai_and_check` in that module. The service snapshots the prompt text before queueing; the worker uses that snapshot on every retry. Validation problems trigger the gateway's one corrective re-ask. The worker saves the validated model using `model_dump(mode="json")`, never raw model text. The AI call may propose an unmatched service with `service_id:null`; only the validated inventory matcher may retain a canonical ID. An empty upstream or downstream list is a successful result.

**D11. Map the result into existing review responses.** In `app/models/service_mapper/service_map.py`, add `analysis` to `MappingView` and the additive recommendation fields from D1. For each upstream item, set `direction=upstream`; for downstream, `direction=downstream`. Copy `service_id` to `related_service_id`, `dependency_reason` to `reason`, compute `cross_sector` by comparing the exact sector labels, set `ai_generated` according to whether the ID is null, and set `status=proposed`, `decision=null`. Derive the legacy display band from the numeric score: `high` for `>=0.75`, `medium` for `>=0.45`, otherwise `low`; these are UI bands, not calibrated probabilities. Ensure the full numeric score, verification status, applicability, entity list, and evidence are also returned. `MappingView.analysis` is the exact three-key prompt result; review IDs, statuses, and metadata live outside it.

**D12. Replace canned SSE with saved-state updates.** Add `Realtime.SERVICE_MAPPING_CHANNEL = "tsg:events:service-mapper:{mapping_id}"` in `app/core/constants/jobs.py` and `publish_service_mapping_status()` in `app/realtime/publisher.py`. The existing `EventHub` subscribes to `tsg:events:*`, so it needs no extra Redis subscription. Follow `_status_stream()` in `app/api/routers/scenario.py`: authorize the mapping and API key **before** opening the stream, emit the current `StatusEvent`, listen on the mapper channel, reread MongoDB on every notification or reconnect, recheck access while connected, and stop after terminal status. A pub/sub message is only a hint to reread; it never supplies the analysis. Remove `sample_events()` from the runtime path. **Gate:** two API clients cannot stream one another's mapping, and a reconnect sees the latest stored status.

**D13. Start a separate local mapper worker.** In `run.ps1`, add a `servicemapper` program with `-Q tsg_servicemapper`, its own `-n` name and `--pool=threads`, and a distinct `CII_WORKER_METRICS_PORT` (for example 9103). Add its name to the script's warm-stop worker list and status handling; check the startup loop already iterates `$Programs.Keys`. Keep beat and `tsg_maintenance` separate. A direct manual worker command is:

```powershell
.\.venv\Scripts\python.exe -m celery -A app.worker worker --pool=threads -c 4 -Q tsg_servicemapper -n mapper@%h --loglevel=INFO
```

`ROUTED_QUEUES` is derived from `TASK_ROUTES`, so `/ready` will require a recent heartbeat on `tsg_servicemapper` as soon as D9 is added. Start this worker **before** relying on a ready API. Check `celery -A app.worker inspect registered` includes `tsg_map_services`, and `inspect active_queues` shows the mapper worker consuming `tsg_servicemapper` only.

**D14. Deploy a separate mapper worker.** Copy the worker deployment pattern in `deploy/deploy_threatgen.yaml` into a new `worker-servicemapper` Deployment in the `ai-threatgen` project with `-Q tsg_servicemapper`, its own resource limits, metrics port, heartbeat, and targeted liveness probe. Add the second mapper worker in `deploy/deploy_remediation.yaml`, matching the repository's current two-project worker redundancy. Both roll out **before** the API: the apply order (`deploy/DEPLOYMENT_GUIDE.md`) applies `deploy_remediation.yaml`, then `deploy_threatgen.yaml`, and waits for the API last. Check `deploy/networkpolicy_threatgen.yaml` and `deploy/networkpolicy_remediation.yaml` selectors permit the new worker's Redis, MongoDB, SQL, AI, metrics, and DNS paths; update Prometheus service discovery/alerts if they use an explicit worker list. Do not copy the maintenance schedule into the new worker: beat/reaper continue on maintenance. **Gate:** one live mapper worker per project, mapped task appears on only its queue, `/ready` includes the mapper queue and passes, metrics scrape works, and a stopped mapper worker causes queued work to recover through the reaper when one returns.

**D15. Test from the innermost rule outward.** Add `tests/test_service_mapper_models.py` for all required fields, exact schema, 15 sectors, score bounds and extra-key rejection. Add `tests/test_service_mapper_domain.py` for direction, duplicate/self/reciprocal, inventory ID and canonical name, evidence, entity applicability, empty arrays, and second-answer failure using a fake `ChatModel`; include prompt-injection text in the frozen context and confirm it cannot change the contract. Add `tests/test_service_mapper_repository.py` for entity isolation, unique idempotency keys, fingerprint conflict, compare-and-set review, generation supersession, indexes, and stale epochs. Add `tests/test_service_mapper_worker.py` for queued→running→done, outage retry, invalid JSON→failed without partial recommendations, late duplicate delivery, lease loss, reaper resend, and fresh inventory on regeneration. Add `tests/test_service_mapper_api.py` for all six routes, 401/403/404/409/422, 202 and replay, returned exact `analysis`, and SSE reconnect/terminal behavior. Use the SQL test schema/seed to prove canonical inventory and foreign-ID rejection; do not call a live AI model in automated tests.

Run Ruff and targeted tests, then the full suite and contract check using the commands in Stage 13. `tests/test_outside_contract.py` pins OpenAPI, enums, task routes, and indexes; use `TSG_WRITE_CONTRACT=1` only after reviewing the intended diff, then run it again without that flag. The new queue, task, fields, and endpoint schemas must appear in pins. Mypy must have no **new** errors compared with Stage 1's baseline.

**D16. Manually prove the full path.** With SQL, MongoDB, Redis, API, maintenance worker, beat, and the dedicated mapper worker running, obtain a caller key for an entity with an actual inventory service. Fill the request from that real service; do not paste a service example from this handbook. In PowerShell:

```powershell
$entityId = 123       # replace with the caller's real entity ID
$serviceId = 456      # replace with a service ID returned by GET /v1/entities/$entityId/services
$headers = @{ 'X-API-Key' = '<caller key>'; 'X-Entity-Id' = "$entityId"; 'X-User-Id' = '<user id>'; 'X-Tenant-Id' = '<tenant id>'; 'Idempotency-Key' = '<unique key>' }
$body = @{ entity_id = $entityId; service_id = $serviceId; sector = '<exact permitted label>'; subsector = '<actual subsector>' } | ConvertTo-Json
$accepted = Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8000/v1/service-mapper' -Headers $headers -ContentType 'application/json' -Body $body
$accepted
Invoke-RestMethod -Uri "http://127.0.0.1:8000/v1/service-mapper/$($accepted.mapping_id)" -Headers $headers
```

Poll GET or connect to `/events` until `done` or `failed`. For `done`, compare `analysis.selected_service` to the request and canonical SQL name, inspect both dependency arrays, confirm any non-null IDs exist in the frozen inventory, then accept or reject one **proposed** recommendation via PATCH. Repeat POST with the same key/body and confirm the same mapping ID; try the same key with changed body and confirm 409. Call regenerate; confirm generation increments and that only undecided previous proposals become superseded. Stop the mapper worker during a second job, restart it, and confirm lease/reaper recovery. The final handover includes the request/response example with secrets redacted, worker/queue status, test result, and any remaining SQL-schema assumption.

## Stage 2 — Implement the shared core and SQL boundary

Do this before implementing a feature router. The entire API depends on these modules:

1. In `app/core/constants/`, define public header names, status/error/reason enums, collection names, task/queue names, limits, and stored-procedure names. Export names through `app/core/constants/__init__.py`. Stored values and Redis/Celery names are externally pinned in `tests/contract/`; do not rename them casually.
2. In `app/core/config.py`, define and validate each `.env.example` setting. A new setting needs an example line and a config test in `tests/test_config.py`. `app/ai/profiles.py` must contain a profile for each configured model name.
3. In `app/core/database.py`, construct MongoDB, Redis, and SQL clients once. SQL callers use `StoredProcedureClient.execute_procedure(StoredProcedure, **named_parameters)`. The API does not issue ad hoc SQL.
4. In `app/core/exceptions.py`, define application exceptions with fixed HTTP status/code; in `app/api/errors.py`, translate them to `application/problem+json`. The body contains `type`, `title`, `status`, `detail`, `code`, `request_id`, and optional `reason`/`errors`/`details`. Reuse these classes; do not handcraft error JSON in each router.
5. In `app/core/logging.py`, `app/core/metrics.py`, and `app/api/middleware.py`, establish request IDs, structured access logs, body size limits, metrics, and error logging. Use `LogEvent` constants and redact secrets.
6. Install the eight `tsg_*.sql` files in `scripts/sql/` into the **approved development SQL database**, then apply `scripts/sql/grants.sql` for the app login. `StoredProcedure` in `app/core/constants/planning.py` must name the same eight procedures. `tsg_GetAssetContext` proves entity/asset ownership and returns five result sets; library procedures read, import, resolve, list, and decide threats/controls. New SQL work needs a `tsg_<Name>.sql` file, enum member, grant, repository call, and disposable SQL test.

If the database owner supplied a Windows-integrated admin connection and `sqlcmd`, replace the three placeholders below with those **approved development** values and run this from the repository root. The script stops on the first failing procedure; grant only after all succeed. For SQL authentication or a managed deployment, have the database owner execute the equivalent files in this order.

```powershell
$SqlServer = '<approved-dev-server>'
$SqlDatabase = '<approved-dev-database>'
$AppUser = '<approved-app-db-user>'
$ProcedureFiles = Get-ChildItem -LiteralPath scripts\sql -Filter 'tsg_*.sql' |
    Where-Object { $_.BaseName -match '^tsg_[A-Za-z0-9_]+$' } |
    Sort-Object Name
foreach ($File in $ProcedureFiles) {
    sqlcmd -S $SqlServer -d $SqlDatabase -E -I -b -i $File.FullName
    if ($LASTEXITCODE -ne 0) { throw "Procedure install failed: $($File.Name)" }
}
sqlcmd -S $SqlServer -d $SqlDatabase -E -I -b -v "AppUser=$AppUser" -i scripts\sql\grants.sql
if ($LASTEXITCODE -ne 0) { throw 'TSG grant install failed' }
```

Do **not** run `tests/sql/schema.sql` or `tests/sql/seed.sql` on the development database; they belong to the disposable test database only.

The test SQL database is **not** your development database. `tests/sql_test_database.py` creates a checkout-specific database from `tests/sql/schema.sql`, `tests/sql/seed.sql`, and every correctly named `tsg_<Name>.sql` file. It drops and recreates that test database when used.

**Gate:** `tests/test_config.py`, `tests/test_base_repository.py`, and `tests/test_health.py` describe core behavior. Run their narrow tests only after the local MongoDB and spare Redis databases are reachable; the autouse fixture in `tests/conftest.py` needs them even for a seemingly pure test.

## Stage 3 — Implement repositories and indexes before services

Follow the data owner, not the URL path:

| Store | Repository files | Record or responsibility |
| --- | --- | --- |
| SQL Server | `app/data_access/scenario/asset_repository.py`; `app/data_access/library/{threat,control,sql_operation}_repository.py` | Asset ownership/facts, curated library, safe SQL writes |
| MongoDB admin | `app/data_access/admin/{api_client,admin_job,audit,embedding,query_vector,ai_call}_repository.py` | API keys, admin jobs, audit, AI/search records |
| MongoDB sessions | `app/data_access/scenario/{threat_scenario_session,threat_scenario}_repository.py` | Session state and scenario versions |
| MongoDB plans | `app/data_access/remediation/remediation_repository.py` | Remediation records and versions |
| MongoDB jobs | `app/data_access/jobs/{job,work_control}_repository.py` | Leases, delivery fencing, cancellation and deletion |
| MongoDB intelligence | `app/data_access/external_intelligence/` | Feed state, records, snapshots, runtime switch |

1. Use `MongoRepository` in `app/data_access/base.py` for named projections/conditions, create/get/list/count/update/delete. Give each repository its collection, schema version, indexes, and methods that express the data operation.
2. For a read, choose only the fields the service needs and include the ownership filter or perform the established owner check before returning the row. For a mutation, use an atomic conditional update with record ID, owner, and expected state/version; handle “zero rows changed” as a race or conflict.
3. Add unique indexes for invariants such as one active run per asset and one idempotency record per key. Create indexes in each repository's `create_indexes()`, then add that repository to `app/container.py:create_all_indexes()`. Startup, not a request handler, creates indexes.
4. Do not call MongoDB driver methods or `execute_procedure()` from `api`, `services`, `domain`, or `worker`; `tests/test_code_conventions.py` enforces this. Do not use an empty filter for update/delete.
5. For SQL writes whose response can be lost, follow `SqlOperationRepository` rather than blindly retrying a procedure. A timeout may mean the first write succeeded; the operation record resolves that ambiguity.

**Gate:** Repository tests such as `tests/test_base_repository.py`, `tests/test_runs.py`, `tests/test_remediation_store.py`, `tests/test_library.py`, and `tests/test_library_curation.py` prove projections, indexes, ownership, unique rules, and SQL procedure shapes. Every new collection appears in `create_all_indexes()`.

## Stage 4 — Build the FastAPI shell, authentication, and probes

1. In `app/main.py:create_app()`, create the `FastAPI` app and register the error handlers, `AnswerUnexpectedErrors`, CORS, and `RequestContextMiddleware` in the existing order. `application_lifespan()` calls `container.set_up_api()`, creates the shared `EventHub`, and closes it on shutdown.
2. In `app/api/dependencies.py`, implement `get_authenticated_principal()` from `X-API-Key`, `X-User-Id`, `X-Entity-Id`, and `X-Tenant-Id`. It verifies a minted active key via `AdminService` and returns `Principal`. Missing/invalid identity is 401; malformed path/query/header data is 422.
3. Implement `valid_session()` and `valid_plan()` so an unknown record is 404 and another entity's record is 403. Expose `Caller`, `CallersRun`, `CallersPlan`, `Offset`, and `Limit` aliases. Use those in feature routes; never trust an `entity_id` in a request body as the caller's identity.
4. Implement `require_admin_api_key()` and `AdminUser` for admin-key routes. `app/api/routers/admin.py` and `library.py` protect their routers with this dependency. The **current** external-intelligence router has no API/admin-key dependency; preserve that contract unless a separately approved change says otherwise.
5. Add public probes in `app/api/routers/health.py`: `/health` returns 200 while the process answers; `/ready` checks MongoDB, Redis, and live workers on every routed queue; `/metrics` exposes Prometheus data and is hidden from OpenAPI. `/ready` **reports SQL Server state but SQL failure alone does not make it 503**.

**Gate:** With backing services reachable, `GET /health` returns `{"status":"ok"}`. `GET /ready` has `status`, `dependencies`, `workers`, and `mongodb`; it is 503 when MongoDB, Redis, or a required worker is unavailable. `tests/test_health.py` and `tests/test_api_clients.py` cover the response, problem format, and authentication boundary.

## Stage 5 — Bootstrap API clients, audits, and admin jobs

Build this before normal scenario calls, because callers need a minted key:

1. Define `Principal`, `MintRequest`, `MintedApiClient`, list/output models in `app/models/admin/api_clients.py`; admin-job views in `app/models/admin/admin_jobs.py`.
2. In `app/data_access/admin/api_client_repository.py`, store **only the hash** of a minted key; add unique hash and active-name indexes. In `app/domain/admin/api_keys.py`, validate key form and hash it. Revoke an active key and clear its process cache.
3. In `app/services/admin/admin_service.py`, implement `create_api_client`, `list_api_clients`, `revoke_api_client`, and `get_api_client_id`. Minted secret is returned once, excluded from list/revoke responses, and the mint response sets `Cache-Control: no-store`. Record mint/revoke in `AuditRepository`.
4. In `app/api/routers/admin.py`, expose `POST /v1/tsg/api-clients` (201), `GET /v1/tsg/api-clients`, `POST /v1/tsg/api-clients/{client_id}/revoke`, `POST /v1/embeddings` (202), and `GET /v1/embeddings/{job_id}`. The embedding build uses `AdminJobRepository` and `send_admin_job()`; unlike leased jobs, a failed publish marks the admin job failed and answers 503.
5. Add the `get_admin_service()` provider and the repositories to `app/container.py`. Register the admin router in `app/main.py`.

**Gate:** `tests/test_api_clients.py` proves secret shown once, hash-only storage, duplicate-name rejection, required admin key, required caller identity, and revoke behavior. `tests/test_embeddings_builds.py` proves the admin job path. Manually mint a development key with request 3 in `debug/tsg.http`; keep it in ignored `debug/.env`.

## Stage 6 — Build the library and AI/search foundation

1. Use `tsg_GetThreatLibrary`, `tsg_GetControlLibrary`, and `tsg_GetLibraryStamp` through `ThreatRepository` and `ControlRepository`; map SQL rows in `app/data_access/library/rows.py` and `app/models/library/`. `LibraryCache` in `app/search/library_cache.py` holds the active library.
2. Build `EmbeddingModel`, `ChatModel`, and `RerankModel` through `app/ai/` and the model profiles. Build `LibrarySearch` in `app/search/service.py`. The container providers call `get_settings()`, share the AI-slot limiter and give each gateway its own model's request-rate limiter (`ai_request_rate_for`); do not create a new model client per request.
3. The scheduled/on-demand index build is `app/worker/admin/library_indexes.py`. Wire `TaskName.BUILD_LIBRARY_INDEXES` to `tsg_maintenance` and the admin job endpoints from Stage 5.
4. For curator changes, `app/models/library/curation.py` validates decision bodies; `app/domain/library/curation.py` decides outcomes; `ThreatLibraryService` calls `tsg_ListPendingThreats` and `tsg_DecidePendingThreats` through `ThreatRepository` and audits the result. Expose `GET /v1/tsg/library/pending` and `POST /v1/tsg/library/decisions` in `app/api/routers/library.py`, protected by the admin key.

**Gate:** `tests/test_library.py`, `tests/test_embeddings_builds.py`, `tests/test_library_curation.py`, and `tests/test_model_profiles.py` pass in a working local test environment. An approved library row is visible after the cache/index refresh; a rejected row is not silently re-proposed.

## Stage 7 — Build the worker runtime before accepting long jobs

1. In `app/core/constants/jobs.py`, define `TaskName`, `Queue`, `TASK_ROUTES`, `ROUTED_QUEUES`, lease limits, and status/event values. The **routed and staffed** queues today are `tsg_threats` (plan), `tsg_scenarios` (write), `tsg_controls` (control mapping), `tsg_remediation` (treatment plans), `tsg_servicemapper` (service mapper) and `tsg_maintenance`; each has its own worker Deployment in both OpenShift projects, and `/ready` needs a live worker on every one of them.
2. In `app/worker/celery_app.py`, register every task module in `TASK_MODULES`, define routes and the beat schedule, set the thread pool, JSON messages, late acknowledgements, and `task_ignore_result=True`. Job state lives in MongoDB, not a Celery result backend.
3. In `app/data_access/jobs/job_repository.py`, implement claims, lease renewal, epochs, task IDs, attempts, and fenced writes. In `app/worker/jobs.py:run_leased_job()`, claim the record, keep the lease alive, retry temporary failures, and stop if the lease is lost. In `app/worker/reaper.py`, resend queued/lost work. In `app/worker/heartbeat.py` and `app/worker/lifecycle.py`, make worker liveness visible to `/ready`.
4. Add object providers in `app/container.py` and call `set_up_worker()` at worker startup. A task imports `app.container` **inside** its function, obtains the job object, and passes work to `run_leased_job()`. `app/worker/scenario/tasks.py` is the example.
5. A service must write the queued MongoDB record first, then call `send_job(task_name, record_id, epoch)`. A broker send failure is logged; the reaper resends the persisted queued job. Admin jobs use `send_admin_job()` with a different failure rule.
6. Start local workers with `run.ps1` (later Stage 13); do not route a task to a new queue until local startup, deployment manifests, and readiness all include a worker for it.

**Gate:** `tests/test_worker.py` and `tests/test_job_control.py` cover worker and job behavior. Prove duplicate delivery and a stale epoch cannot overwrite the current record. `tests/test_outside_contract.py` pins task routes and schedules.

## Stage 8 — Build session creation and read endpoints as one vertical slice

Implement these exact public calls before adding review actions:

| Order | Endpoint | Router function | Service method | Response |
| ---: | --- | --- | --- | --- |
| 1 | `POST /v1/sessions` | `start_run` | `create_threat_scenario_session` | `202 RunBoard`; 200 on same-key replay |
| 2 | `GET /v1/sessions/{session_id}` | `get_run_status` | `get_threat_scenario_session` | `RunBoard` |
| 3 | `GET /v1/sessions/{session_id}/results` | `list_run_scenarios` | `list_threat_scenarios_of_session` | paged `RunResults` |
| 4 | `GET /v1/sessions/{session_id}/scenarios/{scenario_id}` | `get_scenario` | `get_threat_scenario` | `ScenarioView` |
| 5 | `GET /v1/entities/{listed_entity_id}/scenarios` | `list_entity_scenarios` | `list_threat_scenarios_of_entity` | paged `ScenarioList` |

Complete the write path in this exact order:

1. In `app/models/scenario/views.py`, define `StartRunRequest` with positive bounded SQL IDs, a required supporting-system list, one-ID alias handling, duplicate checks, and forbidden unknown fields. Define `SessionStatus`, `RunBoard`, `RunResults`, `ScenarioView`, and list shapes. Keep Pydantic models in `models`, not in the router.
2. In `AssetRepository.get_asset_context()`, call `tsg_GetAssetContext` with the **principal's entity ID** and the request IDs. Read its five result sets into `AssetContextRows` (`app/models/scenario/asset_context.py`). A missing or unlinked asset/system must be a defined 404/403/422, not a database traceback.
3. In `app/domain/scenario/plan.py:freeze_context()`, validate the SQL facts and freeze exactly the planning context that a worker will use. Do this before creating a MongoDB session so a bad asset creates no job.
4. In `ThreatScenarioSessionRepository.create_scenario_session()`, persist one session with `entity_id`, asset/request/context, idempotency key, status, and queued job epoch. Its unique indexes arbitrate parallel starts: one active run per asset and one use of an idempotency key for that entity.
5. In `ThreatScenarioService.create_threat_scenario_session()`, check same-key replay first; check the intelligence snapshot only when intelligence is on; fetch/freeze facts; create the session; resolve a competing insert as replay or named 409; call `send_job(TaskName.FIND_THREATS, id, epoch)`; audit the start. Return `(RunBoard, created)` so the router can answer 202 or 200.
6. In `app/api/routers/scenario.py`, inject `Caller` and `ThreatScenarioService`. The POST route does one service call and changes `Response.status_code` to 200 only for a replay. All session GET routes use `CallersRun` for 404/403 ownership before their service read. List calls use `Offset` and `Limit`.
7. In `app/domain/scenario/results.py`, build response views from persisted records. Results include only current versions unless `include_replaced=true`; never leak another entity's record or an internal MongoDB field.
8. Add providers in `app/container.py` for the asset/session/scenario repositories and scenario service. Register `scenario.router` in `app/main.py`.

The current POST route is deliberately thin. This is its executable shape, with imports omitted:

```python
@router.post("/v1/sessions", status_code=202, response_model=RunBoard, summary="1. Start a run")
def start_run(
    body: StartRunRequest,
    response: Response,
    principal: Caller,
    scenarios: Scenarios,
    idempotency_key: Annotated[
        str | None,
        HeaderParam(alias=Header.IDEMPOTENCY_KEY, max_length=Limits.MAX_IDEMPOTENCY_KEY_CHARS),
    ] = None,
) -> RunBoard:
    board, created = scenarios.create_threat_scenario_session(principal, body, idempotency_key)
    if not created:
        response.status_code = 200
    return board
```

**Gate:** Run `tests/test_runs.py`. It checks 202 creation, frozen context, ownership, missing/extra fields, parallel starts, idempotency replay/conflict, and read views. A successful POST must return quickly with `session_id`; it must not wait for the AI job.

## Stage 9 — Generate scenarios, review them, and control their jobs

Start with the worker chain, then expose the reviewer actions:

1. `app/worker/scenario/tasks.py:find_threats` calls `run_leased_job()` and `PlanJob.plan_threat_scenario_session()`. `PlanJob` uses `ThreatFinder` from `app/domain/scenario/plan.py` with library search, chat, rerank, and embeddings. It saves a plan for writing and queues `TaskName.WRITE_SCENARIOS`.
2. `write_scenarios` calls `ScenarioWriteJob.write_scenario_batch()` in `app/worker/scenario/write_job.py`; it uses `app/domain/scenario/write.py`, prompts in `app/domain/scenario/prompts/`, and `ThreatScenarioRepository` to store scenario versions. Status/counts are saved through the lease. A write failure must mark or retry the job according to its error type.
3. `map_controls` calls `ControlsJob.map_threat_scenario_controls()` in `app/worker/scenario/controls_job.py`. It searches/reranks library controls and persists the result. The maintenance `retry_controls` task recovers stalled mappings. The first scenario cards can be read before all controls finish.
4. In `app/domain/scenario/review.py` and `ThreatScenarioService`, implement `accept_threat_scenarios`, `reject_threat_scenarios`, `write_next_threat_scenario_set`, `regenerate_threat_scenarios`, and `promote_threat_scenario_to_library`. Review writes must be conditional on current version/state. Keep old versions readable; do not replace an accepted one without the explicit request option. Promotion creates a **pending** library proposal for curators.
5. Expose these routes in `scenario.review_router`: `POST /v1/sessions/{session_id}/accept`, `/scenarios/reject`, `/scenarios/next-set` (202), `/regenerate/scenarios` (202), and `/scenarios/{scenario_id}/promote-to-library`. Use `CallersRun` and `Caller`; audit every state change and publish the updated session status.
6. In `JobService` and `app/api/routers/jobs.py`, add `GET /v1/jobs`, `POST /v1/sessions/{session_id}/cancel`, and `DELETE /v1/sessions/{session_id}`. Cancellation fences a worker and leaves completed data readable. Deletion requires cancellation first, removes the session/scenarios/plans, and must tolerate an interrupted delete being retried. Audit both.

**Gate:** Run `tests/test_worker.py`, `tests/test_scenario_writing.py`, `tests/test_review.py`, `tests/test_next_set_rules.py`, `tests/test_promotion.py`, and `tests/test_job_control.py`. Confirm a stale or cancelled worker cannot publish an old result and the current status endpoint tells a reviewer what to do next.

## Stage 10 — Build remediation on an accepted scenario

The public request is `POST /v1/remediation`. For the plan routes below, `PLAN_BASE` means `/v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan`; substitute actual IDs in a request:

| Order | Endpoint | Model/service work |
| ---: | --- | --- |
| 1 | `POST /v1/remediation` | `PlanRequest` → `create_remediation_plan` → 202 `PlanStarted`; same-key manual replay is 200 |
| 2 | `GET PLAN_BASE/status` | `CallersPlan` → `RemediationStatus` |
| 3 | `GET PLAN_BASE` | `get_remediation_plan` → `RemediationResult`; optional history |
| 4 | `POST PLAN_BASE/review` | accept/reject a version → `RemediationStatus` |
| 5 | `POST PLAN_BASE/regenerate` | queue next version → 202 `PlanRequested` |
| 6 | `POST PLAN_BASE/cancel` | `JobService.cancel_remediation_plan` |
| 7 | `GET /v1/sessions/{session_id}/treatment-plans` | paged run list |
| 8 | `GET /v1/entities/{listed_entity_id}/treatment-plans` | paged owned-entity list |

1. In `app/models/remediation/{requests,plan,reviews,views}.py`, define separate request, stored/status, review, and view models. `PlanRequest` has two mutually exclusive paths: an accepted generated scenario (`is_manual=false`, session/scenario IDs) or a hand-written scenario (`is_manual=true`, `manual_scenario`, and `Idempotency-Key`). Register fields are optional but validated.
2. In `app/domain/remediation/`, implement manual record creation, version/decision rules, snapshot of input facts, register values, references, and schedule calculations. A generated scenario must already be accepted. A manual scenario is stored and accepted as part of the request; repeat of the same key/body returns the same plan.
3. In `RemediationRepository` and `ThreatScenarioRepository`, persist the plan and versions with atomic uniqueness/ownership checks. In `RemediationPlanService.create_remediation_plan()`, validate the scenario and entity, create the queued plan, send `TaskName.WRITE_PLAN`, audit, and return IDs. Do not map missing controls or call AI in the HTTP request.
4. In `app/worker/remediation/tasks.py`, register `WRITE_PLAN` (routed to `tsg_remediation`) and run `RemediationPlanJob` under the lease. `app/worker/remediation/plan_inputs.py` reads the frozen inputs, maps missing controls/actors, then the job writes a version. A failed or cancelled version stays inspectable; regeneration writes the next version without erasing the old one.
5. In `app/api/routers/remediation.py`, implement the eight routes above; use `Caller`, `CallersPlan`, or `CallersRun` as appropriate. `plan_status` can return the validated `CallersPlan` directly; other routes call one service method. Use `JobService` for cancellation. Put the plan SSE route in Stage 12.
6. Add remediation repository, service, and job providers to `app/container.py`, and register `remediation_router` in `app/main.py`.

**Gate:** Run `tests/test_remediation_models.py`, `tests/test_remediation_requests.py`, `tests/test_remediation_manual.py`, `tests/test_remediation_review.py`, `tests/test_remediation_reads.py`, and `tests/test_remediation_schedule.py`. Verify 202 start, 200 replay, 403 other entity, 404 unknown, 409 invalid state, persisted versions, and terminal status.

## Stage 11 — Add external intelligence behind its master switch

Build this after the original scenario path works with `EXTERNAL_INTELLIGENCE_ENABLED=false`.

1. In `app/core/config.py` and `.env.example`, keep the master switch, source/threshold settings, proxy and model settings explicit. When off, no intelligence data is fetched or needed for a run. The on path requires a calibrated evidence threshold and an active indexed snapshot.
2. In `app/models/external_intelligence/` and `app/data_access/external_intelligence/`, define feed health, records, snapshots, source state, and admin request/response shapes. `IntelligenceSwitch` combines the environment switch and runtime switch. Repository claims and snapshot pointers must fence concurrent refreshes.
3. In `app/worker/external_intelligence/sources/`, download and parse the configured sources through the existing guarded HTTP reader. In `refresh_sources.py`, claim due sources, store and retire versions, audit outcomes, and publish a complete snapshot. `refresh_task.py` executes an on-demand or scheduled refresh on the maintenance queue.
4. In `app/search/external_intelligence/index_keeper.py`, build and atomically swap the active search index. In `app/domain/external_intelligence/`, sanitize untrusted source text and decide applicability; never insert fetched text into prompts without the existing cleaning/gating rules. Scenario writing obtains evidence at write time in `app/worker/external_intelligence/evidence_at_write.py`.
5. In `ExternalIntelligenceService`, implement switch read/write, refresh start/status, health, source revoke, and source approval. Expose seven calls in `app/api/routers/external_intelligence.py`: `GET/PUT /v1/tsg/intel/switch`, `POST /refresh`, `GET /refresh/{job_id}`, `GET /health`, `POST /sources/{source}/revoke`, and `POST /sources/{source}/approve`. Audit changes. The current router intentionally has no API/admin-key dependency; do not add one by assumption.
6. Add conditional intelligence providers/index initialization in `app/container.py`, register the router in `app/main.py`, and route refresh to `tsg_maintenance`. With the switch on but no indexed data, a new session is refused with the existing `intel_no_data` conflict instead of queuing a doomed job.

**Gate:** First run `tests/external_intelligence/switch_off/test_off_equals_original.py`, then `tests/external_intelligence/api/test_intel_admin_api.py`, `tests/external_intelligence/operations/test_refresh_sources.py`, `tests/external_intelligence/search/test_index_keeper.py`, `tests/external_intelligence/safety/test_untrusted_text.py`, and `tests/external_intelligence/test_end_to_end.py`. The off path must retain the original response behavior; the on path must cite only approved, relevant evidence.

## Stage 12 — Add live updates and implement Service Mapper

1. In `app/realtime/publisher.py`, name per-session/per-plan channels and publish after the persisted status changes. In `app/realtime/event_hub.py`, share one Redis subscription among streams in the API process. A published message tells a stream to **reread MongoDB**; it is not the result itself.
2. In `scenario.events_router`, add `GET /v1/sessions/{session_id}/events` and `GET /v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan/events`. Validate ownership **before** opening the stream; send the current status immediately, then changes; recheck key access while connected; emit a deletion event and close after deletion. See `_status_stream()` in `app/api/routers/scenario.py`.
3. Service Mapper: built following **Recipe D1–D16**, with the later owner decisions recorded in [service_mapper/SERVICE_MAPPER.md](service_mapper/SERVICE_MAPPER.md) (one direction per service, names only to the AI, every database service grouped by sector). Its worker consumes only `tsg_servicemapper`.
4. Register `scenario.events_router` and `service_mapper_router` in `app/main.py`; add their tags/descriptions in `app/api/openapi_docs.py`.

**Gate:** `tests/test_realtime.py` covers session/plan streaming and disconnect behavior. Add the mapper model, domain, repository, worker, and API tests in D15; verify every route plus the dedicated task and queue. The OpenAPI pin alone proves only route shapes. The mapper's tests are in `tests/test_service_mapper.py`.

## Stage 13 — Compose, run, test, and hand over

### 13.1 Wire the app once

`app/container.py` owns long-lived providers. Each new repository, service, and job object gets a provider; existing constructor changes update their providers. `create_all_indexes()` includes every MongoDB repository. `set_up_api()` creates indexes and initializes model gateways; `set_up_worker()` initializes worker-side indexes/models. `app/main.py` includes all routers in the documented Swagger order:

```text
health → admin → external intelligence → sessions → review →
remediation → jobs → session/plan events → library → service mapper
```

Run `.\.venv\Scripts\python.exe -m ruff check app tests scripts` and `.\.venv\Scripts\python.exe -m mypy app` after wiring. Fix every new diagnostic; report any still-existing baseline errors separately. `tests/test_code_conventions.py` checks layer directions, one service class per module, database call placement, model placement, singleton placement, and code size.

### 13.2 Start the real local stack

Ensure SQL Server, MongoDB, Redis, and required AI endpoints work, then use **Windows PowerShell 5.1**:

```powershell
.\run.ps1 -NoBrowser
.\run.ps1 status
Invoke-RestMethod http://127.0.0.1:8000/health
Invoke-RestMethod http://127.0.0.1:8000/ready
```

`/ready` needs one live worker on each **routed** queue. Before Recipe D, the local script starts `tsg_threats,tsg_scenarios,tsg_controls,tsg_remediation` on one worker and `tsg_maintenance` on another, plus beat. After D9 and D13, it also starts a separate `tsg_servicemapper` worker; the API then requires that worker's heartbeat. SQL Server health appears in the response but does not alone fail readiness. Stop with `.\run.ps1 stop`.

### 13.3 Run tests without touching application data

`tests/conftest.py` uses a checkout-specific MongoDB test database, a checkout-specific SQL test database, and spare Redis databases (default 14,15). It may drop and recreate the test databases and flush the chosen Redis databases. Check the target addresses and spare numbers first. Then run narrow tests for the changed stage and the full suite:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_code_conventions.py -q
.\.venv\Scripts\python.exe -m pytest tests/test_runs.py -q
.\.venv\Scripts\python.exe -m pytest -q
```

Use this exact narrow-test command for the stage you built; run stages in order. Every pytest command still needs the integration stores from Stage 1 because `tests/conftest.py` has a session-wide autouse database fixture.

| Stage | Command |
| ---: | --- |
| 2–3 | `.\.venv\Scripts\python.exe -m pytest tests/test_config.py tests/test_base_repository.py tests/test_library.py -q` |
| 4 | `.\.venv\Scripts\python.exe -m pytest tests/test_health.py -q` |
| 5 | `.\.venv\Scripts\python.exe -m pytest tests/test_api_clients.py tests/test_embeddings_builds.py -q` |
| 6 | `.\.venv\Scripts\python.exe -m pytest tests/test_library_curation.py tests/test_model_profiles.py -q` |
| 7 | `.\.venv\Scripts\python.exe -m pytest tests/test_worker.py -q` |
| 8 | `.\.venv\Scripts\python.exe -m pytest tests/test_runs.py -q` |
| 9 | `.\.venv\Scripts\python.exe -m pytest tests/test_scenario_writing.py tests/test_review.py tests/test_job_control.py -q` |
| 10 | `.\.venv\Scripts\python.exe -m pytest tests/test_remediation_requests.py tests/test_remediation_review.py tests/test_remediation_reads.py -q` |
| 11 | `.\.venv\Scripts\python.exe -m pytest tests/external_intelligence/test_end_to_end.py -q` |
| 12 | `.\.venv\Scripts\python.exe -m pytest tests/test_realtime.py -q` |

A connection or login failure is an environment failure; record it and repair the store, then rerun. If a restricted execution environment blocks local Redis, run the integration suite on the approved development machine with the same disposable database settings and record its output.

### 13.4 Check the outside contract deliberately

`tests/test_outside_contract.py` pins OpenAPI, stored enums/names, Celery routes/schedule, and MongoDB indexes. For a **deliberate approved** contract change, check that `tests/contract/` has no unrelated pending edits, regenerate the pins, inspect **every** diff, then rerun without the writer variable:

```powershell
$env:TSG_WRITE_CONTRACT = '1'
.\.venv\Scripts\python.exe -m pytest tests/test_outside_contract.py -q
Remove-Item Env:TSG_WRITE_CONTRACT
git diff -- tests/contract
.\.venv\Scripts\python.exe -m pytest tests/test_outside_contract.py -q
```

The writer rewrites **all** pins. Remove the environment variable even if its first pytest run fails. Keep only the intended contract diff; do not accept an unrelated route, enum, queue, or index change merely to pass a test.

### 13.5 Perform a manual end-to-end call

Use `debug/tsg.http` in the VS Code REST Client; `debug/.env.example` lists its variables and ignored `debug/.env` holds development identity values. Keep real keys out of screenshots and PR text. Use a real development identity and linked asset/system IDs supplied for the test entity. Follow this sequence:

| Step | Request to send | Expected result and next value |
| ---: | --- | --- |
| 1 | `GET /health`, then `GET /ready` | 200; proceed when ready is `ready`. |
| 2 | `POST /v1/tsg/api-clients` with `X-Admin-Key` and `{"name":"junior-dev-smoke"}` | 201; copy the one-time `api_key` into ignored `debug/.env`. Use another unique name on a later run. |
| 3 | `POST /v1/sessions` with `X-API-Key`, `X-User-Id`, `X-Entity-Id`, `X-Tenant-Id`, `Idempotency-Key`, and `{"asset_id":<owned_asset_id>,"supporting_system_id":[<linked_system_id>]}` | 202; save `session_id`. Repeating the same key and body returns 200 and the same ID. Replace the angle-bracket ID placeholders with actual numbers before sending. |
| 4 | `GET /v1/sessions/{session_id}` until `progress.overall` reaches `awaiting_review`, `awaiting_next_set`, `complete`, `error`, or `cancelled`; then `GET /v1/sessions/{session_id}/results` | 200; save a returned `scenario_id`. If the run has no scenario, inspect its persisted status/error and worker logs before proceeding. |
| 5 | `POST /v1/sessions/{session_id}/accept` with `{"scenario_ids":["<scenario_id>"]}` | 200; the selected scenario is accepted. Replace the placeholder with the returned ID. |
| 6 | `POST /v1/remediation` with `{"is_manual":false,"session_id":"<session_id>","scenario_id":"<scenario_id>"}` | 202; save `remediation_id` and the returned session/scenario IDs. |
| 7 | `GET /v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan/status` until `latest_status` is `done`, `failed`, or `cancelled`; if done, `GET /v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan` | 200; a done result contains a readable plan. For failed/cancelled, record the status error and investigate the job. |
| 8 | Retry the supported idempotent call; send a missing key, malformed body, unknown ID, and other entity's ID to the applicable route | Replay does not duplicate work; refusals have expected status and `application/problem+json`. |

At each step, check the actual response model, `X-Request-Id`, audit entry for a mutation, worker state for a queued action, and the stored result. The `debug/tsg.http` examples contain the exact headers and more negative calls. If a step fails, use its request ID to find the sanitized API/worker log and inspect the saved job state before changing code.

### 13.6 Final handover gate

- [ ] All 45 OpenAPI operations are registered and have the correct auth dependency; `/metrics` is intentionally hidden from OpenAPI.
- [ ] Every mutation has explicit ownership, atomic persistence, audit, retry/idempotency behavior, and a response the client can follow.
- [ ] Every long job has a stored queued record, a registered/routed task, a staffed queue, lease fencing, recovery, terminal status, and a status endpoint.
- [ ] Every new SQL procedure has its file, enum member, grant, repository call, and test schema coverage; every new MongoDB collection has indexes at startup.
- [ ] Ruff and convention tests pass; mypy has no new errors relative to the recorded baseline; relevant tests and the full suite pass against disposable stores.
- [ ] Any OpenAPI/stored-name/Celery/index pin change is intentional and reviewed; local startup and the manual smoke pass.
- [ ] Update `debug/tsg.http`, `.env.example`, `run.ps1`, and `deploy/` manifests if the contract, configuration, task routes, or workers changed.

If a gate is blocked, hand over the exact command, sanitized error, and missing environment dependency. A route-level test is not proof that the job, storage, and worker path works end to end.

## Appendix — The rules to apply within every stage

1. **A route is thin.** It declares FastAPI path/method, typed input, dependency, `response_model`, and success status; it calls one service method. The service coordinates rules, repository operations, audit, queueing, and events.
2. **Models are wire shapes; domain functions are decisions.** Put Pydantic models and public dataclasses in `app/models/`. Put business comparisons, view construction, and state transitions in `app/domain/`. Do not move HTTP or driver objects into domain functions.
3. **All storage calls belong to `data_access`.** SQL goes through named stored procedures only. MongoDB writes use specific predicates; indexes enforce unique rules. A lost SQL write answer is resolved through the SQL operation record rather than retried blindly.
4. **Ownership is independent of existence.** `Caller` proves the API client/identity. `CallersRun` and `CallersPlan` prove an owned resource. For entity-list paths, compare `{listed_entity_id}` with the principal's entity before listing.
5. **Errors have one format.** Use exceptions in `app/core/exceptions.py` and message/reason constants in `app/core/constants/`; the global handler in `app/api/errors.py` produces the problem body and request ID. 503 includes `Retry-After` where supported.
6. **A Celery message is only a pointer.** Save state first, publish ID/epoch second, fence worker updates by lease, and let the reaper recover missed deliveries. A new `Queue` enum member has no worker until routes, local startup, deployment, and readiness are wired.
7. **A public change changes a pin.** Review `tests/contract/openapi.json`, `celery.json`, `enums.json`, `tsg_names.json`, and `indexes.json` only for the fields the feature intentionally changes.
