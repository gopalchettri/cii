# Service Mapper — Requirements and Solution Plan

> **Superseded:** see [SERVICE_MAPPER_SOLUTION.md](SERVICE_MAPPER_SOLUTION.md) for the current solution; this file is background only.

Status: **Planned** (nothing is built). This is the detailed reference. Candidate selection and matching (related services may come from any sector or sub-sector) is governed by [SERVICE_MAPPER_HOW_IT_WORKS.md](SERVICE_MAPPER_HOW_IT_WORKS.md). The five-API stakeholder summary is [SERVICE_MAPPER_DESIGN.md](SERVICE_MAPPER_DESIGN.md); where the two differ (endpoint set, one-entity mapping, accept/reject), that file governs.

---

## Part 1. Requirements

### 1.1 The problem in plain English
Services depend on each other. If the *Online Payment Service* stops, everything that uses it is hurt; if the *Identity Service* it needs
stops, it is hurt too. Users need a list of **which services a selected service needs** and **which services need it**.

- **Upstream** = a service the selected service **needs**.
- **Downstream** = a service that **needs or relies on** the selected service.
- Direction is always explained from the selected service.

```
  Identity Service  --->  Online Payment Service  --->  Customer Application
   (UPSTREAM:              (SELECTED SERVICE)            (DOWNSTREAM:
    payment needs it)                                     relies on payment)
```

### 1.2 Input
`POST /v1/service-map` (same headers as creating a threat scenario in TSG: `X-API-Key`, `X-User-Id`, `X-Entity-Id`, `X-Tenant-Id`, `Idempotency-Key`).

| Field | Required | Meaning |
|---|---|---|
| `service_name` | yes | Free text. The service may be **new** and exist in no table. |
| `sector_id` | no | Sector id. The name is looked up in the database. |
| `sub_sector_id` | no | Sub-sector id; must belong to `sector_id` when both are given. |
| `entity_id` | no | List of one or more entity ids being assessed. *(Assumption: list of integers.)* |

The prompt to the AI uses **names only, never ids**. `X-Entity-Id` (header) is the caller that owns the record; payload `entity_id` is the entities being assessed.

### 1.3 Business rules
1. **Database first.** Services are chosen from the master table `onboarding_services` whenever one fits.
2. **AI fallback is configurable** (`CII_SERVICE_MAP_AI_GENERATE`). ON: when no database service fits a direction, the AI suggests services, flagged `ai_generated: true`.
   OFF (default): only database services are returned; a list may be empty.
3. A database item carries its `service_id` (`onboarding_services.id`) and `ai_generated: false`. An AI item has `service_id: null` and `ai_generated: true`.
4. Results are **possible** dependencies, not verified architecture.
5. The selected service is never its own dependency. A service appears **once per record** (not in both lists, no duplicates).
6. The number of services per direction is **configurable** (see 1.5).
7. The user can **accept** any, several, or none of the services, and can **regenerate** services; both are tracked.
8. Up to **1,000 simultaneous submissions** must be absorbed without dropping work or overwhelming the LLM.
9. Work is **asynchronous**: submit, then live updates (SSE) or polling. The result is **stored in MongoDB** and expires after a set time.
10. All database reads go through **stored procedures**.
11. Every call checks that the `X-Entity-Id` owner owns the record (404 otherwise).

### 1.4 Output: one JSON per `id`
There is **one record per submit**. Regenerating never creates a new id. Replaced services stay inside their own slot under `previous[]`, in order.

```json
{
  "id": "6650a1f2c3d4e5f607182930",
  "job_status": "done",
  "version": 6,
  "service_name": "Online Payment Service",
  "entity_id": [5, 9],
  "sector_id": 12,
  "sector": "Finance",
  "sub_sector_id": 45,
  "subsector": "Payments",
  "ai_generation_enabled": true,

  "upstream": [
    {
      "item_id": "u1", "direction": "upstream", "revision": 1,
      "service_id": 31, "name": "Identity Service", "sector": "Finance",
      "reason": "Payment needs identity to verify the payer.",
      "confidence": "high", "ai_generated": false,
      "state": "accepted", "restored_from": null, "previous": []
    },
    {
      "item_id": "u2", "direction": "upstream", "revision": 3,
      "service_id": 58, "name": "Core Banking Service", "sector": "Finance",
      "reason": "Payment needs core banking to post debits and credits.",
      "confidence": "medium", "ai_generated": false,
      "state": "suggested", "restored_from": null,
      "previous": [
        {"revision": 1, "service_id": 44, "name": "Fraud Screening Service", "sector": "Finance",
         "reason": "Payment may need fraud screening.", "confidence": "low", "ai_generated": false,
         "replaced_at": "2026-10-15T10:38:55Z"},
        {"revision": 2, "service_id": 52, "name": "Card Network Gateway", "sector": "Finance",
         "reason": "Payment needs a card network to authorize cards.", "confidence": "medium", "ai_generated": false,
         "replaced_at": "2026-10-15T10:51:20Z"}
      ]
    }
  ],

  "downstream": [
    {
      "item_id": "d1", "direction": "downstream", "revision": 1,
      "service_id": null, "name": "Customer Application", "sector": null,
      "reason": "The app relies on payment to charge users.",
      "confidence": "medium", "ai_generated": true,
      "state": "accepted", "restored_from": null, "previous": []
    },
    {
      "item_id": "d2", "direction": "downstream", "revision": 1,
      "service_id": null, "name": "Merchant Portal", "sector": null,
      "reason": "Merchants may rely on payment.",
      "confidence": "low", "ai_generated": true,
      "state": "suggested", "restored_from": null, "previous": []
    }
  ],

  "last_job": {
    "type": "regenerate", "status": "done",
    "requested_item_ids": ["u2", "d2"],
    "not_replaced": ["d2"],
    "message": "No new downstream service found for d2; it was kept as is.",
    "error": null, "finished_at": "2026-10-15T11:05:02Z"
  },

  "created_at": "2026-10-15T10:30:02Z",
  "updated_at": "2026-10-15T11:05:02Z",
  "expires_at": "2026-10-22T10:30:02Z"
}
```

Field guide for UI developers:

| Field | Meaning |
|---|---|
| `job_status` | `queued`, `running`, `done`, `failed`. Treat the lists as final only when `done`. |
| `version` | Whole-record version; goes up on every write. Send it back on every `PUT`/`POST`. |
| `item_id` | Stable id of a slot; never changes across regenerates. |
| `revision` | 1, 2, 3 ... each time that slot is regenerated or restored. |
| `state` | `suggested` (no decision), `regenerating` (job running for this slot), `accepted`. |
| `previous[]` | Older revisions of this slot, oldest first, each with `replaced_at`. |
| `restored_from` | Revision number this item was restored from, else `null`. |
| `last_job` | Outcome of the latest create or regenerate job: `not_replaced` ids, a message, or an error. |
| `ai_generation_enabled` | Config at job time; explains empty lists when the AI is off. |

Invariants: `ai_generated = false` exactly when `service_id` is not null. Regenerating an accepted slot gives the new revision `state: "suggested"`.

### 1.5 Configuration (`.env`, read in `app/core/config.py`, defaults in `app/core/constants/service_map.py`)
| Variable | Default | Meaning |
|---|---|---|
| `CII_SERVICE_MAP_AI_GENERATE` | false | AI may suggest services when the database has none for a direction |
| `CII_SERVICE_MAPPER_DEFAULT_COUNT` | 5 | Services **per direction** generated on create (hard ceiling 20) |
| `CII_SERVICE_MAPPER_UPSTREAM_COUNT` / `..._DOWNSTREAM_COUNT` | blank | Optional per-direction override of the default |
| `CII_SERVICE_MAPPER_REGENERATE_DEFAULT_COUNT` | 3 | Services per direction used on regenerate |
| `CII_SERVICE_MAPPER_UPSTREAM_REGENERATE_COUNT` / `..._DOWNSTREAM_REGENERATE_COUNT` | blank | Optional per-direction override |
| `CII_SERVICE_MAPPER_TEMPERATURE` | blank | Model temperature on create; blank = not sent (provider default) |
| `CII_SERVICE_MAPPER_REGENERATE_TEMPERATURE` | blank | Temperature on regenerate (set slightly higher so repeats are less likely) |
| `CII_SERVICE_MAP_MAX_PENDING` | set at build | Queued + running jobs above this get 503 |
| `CII_SERVICE_MAP_RESULT_DAYS` | 7 | Record expiry (TTL) |

Temperature is sent only when set **and** the model profile accepts it (new profile flag `supports_temperature`, default true, in `app/ai/profiles.py`;
wired through `_build_request_options` in `app/ai/chat.py`). The AI is told "up to N per direction"; fewer is accepted.

### 1.6 Out of scope (v1)
Human approval workflow, saving results as an "approved" dependency map, notifications, priorities, vector search or reranker,
per-entity applicability, a combined TSG + mapper load-test suite (one burst script after v1).

---

## Part 2. Solution

### 2.1 API
Headers on every call: `X-API-Key`, `X-User-Id`, `X-Entity-Id`, `X-Tenant-Id` (`Idempotency-Key` on POSTs).

| Method / path | Body | Success | Errors |
|---|---|---|---|
| `POST /v1/service-map` | `{service_name, sector_id?, sub_sector_id?, entity_id?: [..]}` | 202 `{id, version, job_status:"queued"}`; 200 on an idempotent replay | 422 bad input or sector/sub-sector mismatch; 503 + `Retry-After` over the pending limit |
| `GET /v1/service-map/{id}` | - | 200 the JSON in 1.4 | 404 not found or not the owner |
| `GET /v1/service-map/{id}/events` | - | SSE: queued -> running -> done/failed, also after each regenerate | 404 |
| `PUT /v1/service-map/{id}/accepted` | `{version, items:[{item_id, revision?}]}` | 200 the full record | 409 stale version, job running, or service already live; 422 unknown item or revision |
| `POST /v1/service-map/{id}/regenerate` | `{version, item_ids?:[..]}` | 202 `{id, version, job_status:"queued"}` | 409 stale version or job running; 422 unknown item, too many items, or 10-revision cap; 503 over the pending limit |
| `GET /v1/service-map/{id}/history` | - | 200 events: `created`, `accepted`, `regenerated` with who, when, version, item ids | 404 |

Accept rules: the list is the **full accepted set**. An empty list means "accepted none"; anything not listed returns to `suggested`.
`revision` is optional (default: the current one). Accepting an **older** revision restores it as a new revision with `restored_from` set; older ones stay in `previous[]`.
Restoring is refused (409) if that service is already live in either list.

Regenerate rules:
- **With `item_ids`:** exactly those slots get a new revision (the old one moves to `previous[]`). The number selected per direction must not exceed the regenerate count (422).
- **Without `item_ids`:** adds `regenerate count` NEW slots per direction; nothing is replaced.
- Names already shown on the record (live and in `previous[]`) are never repeated. Database candidates already shown are removed from the pick list.
- If no new service is available (database exhausted and AI off), the slot is kept unchanged and listed in `last_job.not_replaced`. A failed job leaves the lists unchanged.
- At most 10 revisions per slot.

Concurrency: `version` goes up on submit, regenerate, job completion and accept. A request quoting an old version gets 409. Writes are refused while a job is queued/running.
Existing `job.epoch` fencing stops a stale worker from overwriting a newer result.

### 2.2 Architecture and request flow
```
 Client                 FastAPI (API pod)              Redis                Celery worker               Mongo / SQL / LLM
   |  POST /v1/service-map  |                           |                   (queue tsg_service_map)           |
   |----------------------->| validate + pending guard  |                          |                          |
   |                        | create record (queued) ---------------------------------------------------->  tsg_service_maps
   |                        | send_job(id) ------------>| queue                    |                          |
   |<-- 202 {id, queued} ---|                           |------------------------->| claim lease (running)    |
   |                        |                           |                          | SP: names + candidates ->| SQL Server
   |  GET /{id}/events (SSE)|<-- event id (pub/sub) ----|<-------------------------| ask LLM (1 call, 1 fix)->| LLM (AI slot limit)
   |<-- status/result ------| read record  <-------------------------------------------------------------  save result (done)
   |  GET /v1/service-map/{id} (poll alternative)       |                          |                          |
```

### 2.3 What the worker does
```
 [1 Load context]   SP tsg_GetServiceMapContext(sector_id, sub_sector_id, entity_ids)
        |            -> sector, sub-sector and entity NAMES; candidate service rows from onboarding_services
        v
 [2 Build prompt]   names only (no ids); user text treated as data; ALL the rules are written in the prompt:
        |            - upstream = selected service needs it; downstream = relies on selected service
        |            - not the selected service itself; no duplicates; not in both lists; every item has a reason
        |            - return up to N per direction (N from config)
        |            - AI_GENERATE ON : "use candidate names first; only if none fits a direction, suggest new ones"
        |              AI_GENERATE OFF: "use candidate names only"
        |            - regenerate: live + previous names listed as "do not repeat", and the slots to fill
        v
 [3 Ask LLM once]   existing ask_for_json -> upstream[] + downstream[] (name, reason, confidence); one call, no re-ask
        v
 [4 Assemble]       NO checking logic. For each returned name: matches a candidate (normalized name)?
        |              yes -> service_id from that row, ai_generated = false
        |              no  -> service_id = null,       ai_generated = true
        v
 [5 Finish]         sort by confidence, bump version, save to Mongo, publish event
```
**Decision (v1): the checking logic lives in the prompt only; no code-level checks and no corrective re-ask.**
Accepted risks, to revisit if quality is poor: a wrong-direction, duplicate or self-referencing item can reach the user; AI items can appear while the AI setting is off;
a near-miss name ("Identity Svc") is flagged `ai_generated: true`.

### 2.4 Decision flow per direction
```
                  database candidates that fit?
                   /                         \
                 yes                          no
                  |                            |
       return them (ai_generated=false)   AI_GENERATE config ON?
                                              /          \
                                            yes           no
                                             |             |
                            AI suggests services      return empty list
                            (ai_generated=true)
```

### 2.5 Accept and regenerate flow
```
 Client                     API                                  Mongo record (one id)                Worker
   | GET /{id}  (v2, done)   |                                    u1 u2 | d1 d2 ; all suggested          |
   |<------------------------|                                                                           |
   | PUT /{id}/accepted      |                                                                           |
   |  {v2, [u1, d1]} ------->| version ok? no job running? ids exist? no duplicate service?              |
   |<-- 200 record ----------|-- u1,d1 = accepted ; others = suggested ; v3 ; history += accepted        |
   | POST /{id}/regenerate   |                                                                           |
   |  {v3, [u2]} ----------->| version ok? no job running? count <= regenerate count? pending guard?     |
   |<-- 202 {v4, queued} ----|-- u2 = regenerating ; v4 ; send_job(epoch 2) ------------------------------>
   |                         |                                      kept as fixed: u1 d1 d2                |
   |                         |                                      ask for 1 new upstream, no repeats --- |
   |<== SSE running / done ==|<-- u2: revision 2 (old one -> previous[]), state suggested ; v5 ------------|
   |                         |    nothing new found: u2 unchanged, last_job.not_replaced = [u2]            |
```

### 2.6 Design choices and why
| Choice | Why |
|---|---|
| Async job + 202 | A model call takes 5-99 s; the route times out at 30 s; a 1,000-request burst cannot be held open. |
| One record, slots with `previous[]` | The UI makes one call, shows one list, and never merges documents or filters replaced rows. |
| Dedicated queue and worker `tsg_service_map` | Mapper bursts cannot starve TSG scenario jobs. |
| Reuse `run_leased_job`, `send_job`, reaper | Lease, retries, duplicate-delivery protection and epoch fencing already exist. |
| Reuse the AI slot limiter (`app/ai/slots.py`, default 16) | Caps real LLM calls across all workers; a burst waits in the queue (about 1,000 jobs clear in minutes). |
| Mongo `tsg_service_maps` with TTL | Stores the result as required; existing job collections have no TTL, so this adds one. |
| Rules in the prompt, name lookup in code | Keeps the solution simple: the AI returns names; code only marks a name as database (has `service_id`) or AI-generated. |
| SSE plus polling | Live status for the UI; polling is the fallback. |
| 503 + `Retry-After` over a pending limit | Prevents an unbounded backlog. |

### 2.7 Implementation steps (build order, for later)
| Seq | What | Where (existing pattern reused) |
|---|---|---|
| 1 | Constants and settings (section 1.5); extend `Queue`, `TaskName`, `Collection`, `AiTask`, `StoredProcedure`, audit/log/error enums | `app/core/constants/service_map.py`, `app/core/config.py` |
| 2 | Models: request, AI contract (`extra="forbid"`), item/slot, record, responses | `app/models/service_map.py` |
| 3 | Stored procedure and repository | `scripts/sql/tsg_GetServiceMapContext.sql`, `grants.sql`, `tests/sql/*`; `app/data_access/service_map_context.py` (like `asset_context.py`) |
| 4 | Temperature wiring: profile flag `supports_temperature`, per-call temperature | `app/ai/profiles.py`, `app/ai/chat.py` |
| 5 | Engine: prompt (all rules), mapper (create and regenerate modes, name lookup). No checks module, no re-ask. | `app/engine/service_map/` (like `engine/remediation/planner.py`; one `ask_for_json` call) |
| 6 | Mongo record, TTL, unique `(entity_id, idempotency_key)`, indexes | `app/data_access/service_maps.py`, `app/data_access/indexes.py` |
| 7 | Worker task | `app/worker/tasks/service_map.py`; add to `TASK_MODULES` and `task_routes` in `app/worker/celery_app.py` |
| 8 | Dedicated worker `-Q tsg_service_map -c 10` | `run.ps1`, `docs/RUNNING.md` (`/ready` needs a live worker on each routed queue) |
| 9 | Service: idempotent create, accept, regenerate, get, history, pending guard, audit | `app/services/service_map/` (like `services/scenarios/runs.py`, `services/remediation/`) |
| 10 | Router and registration | `app/api/routers/service_map.py`, `app/main.py` |
| 11 | SSE channel | `app/realtime/publisher.py`, `app/api/routers/events.py` |
| 12 | Tests | `tests/test_service_map.py` (FakeChatModel), a case in `tests/test_sql_procedures.py` |
| 13 | Docs | this file; BLUEPRINT entry |

Reused instead of rebuilt: AI slot limiter, lease/reaper/idempotency, SSE hub, Celery wiring, `ChatModel`, prompt redaction.
Not built because it exists or is not needed: new LLM limiter, Celery result backend, custom retry logic.

### 2.8 Tests to write
- Create: a returned name that matches a candidate gets its `service_id` and `ai_generated: false`; an unmatched name gets `service_id: null` and `ai_generated: true`;
  the prompt contains each rule and differs by the AI setting (on/off) and by the configured counts; invalid or mismatched sector/sub-sector;
  no entity given; hostile `service_name` treated as data; idempotent replay returns the same record. (Answer-rule checks are prompt-level, so no unit tests for them in v1.)
- Accept: some, none, older revision restore, stale version (409), job running (409), unknown item or revision (422), duplicate on restore (409).
- Regenerate: replaces only chosen slots; kept items unchanged; the prompt lists live and `previous[]` names as "do not repeat"; no replacement -> `not_replaced`; failed job leaves lists unchanged;
  accepted slot becomes `suggested`; 10-revision cap; too many items (422); without `item_ids` adds new slots; version bumps.
- Platform: SSE event on completion and after regenerate; TTL index present; over the pending limit -> 503; ownership (404 for another entity);
  temperature sent only when set and supported; `tests/test_code_conventions.py` still passes.

### 2.9 Verification
```
.venv\Scripts\python -m pytest tests/test_service_map.py tests/test_sql_procedures.py tests/test_code_conventions.py
ruff check .
mypy app
```
Manual: start the API and a `celery -Q tsg_service_map` worker; POST with AI on and off, with and without ids; watch SSE; GET the record; accept some/none;
regenerate with and without `item_ids`; replay an `Idempotency-Key`; submit about 50 jobs; exceed the pending limit and expect 503 with `Retry-After`.

### 2.10 Risks and open assumptions
- Throughput is bounded by AI slots (default 16), so users see "queued" during bursts.
- Model output is advisory; `confidence` is the model's own estimate, not a probability.
- Assumed, to confirm before build: payload `entity_id` is a **list of integers**; candidates are **all non-deleted `onboarding_services`** (same sector first, about 200 cap);
  regenerate **with** `item_ids` replaces those slots and **without** adds new ones; accepting is separate from choosing what to regenerate.
- Deployment manifests are still "Planned" in the repo, so the dedicated worker is documented in `RUNNING.md` and `run.ps1` only.
- `docs/Service_Mapper_Implementation_Recommendations.md` (your document) is left unchanged; this plan adopts its asynchronous job design and content rules.
