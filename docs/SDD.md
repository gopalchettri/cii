# TSG v2 — Solution Design Document (KISS)

| Version | Date | Status | Owner | Author |
|---|---|---|---|---|
| 0.6 | 2026-10-08 | Draft for owner approval | Gopal Chettri | Claude |

## Context
v1 (`...\DESC_TSG _Search_Remediation\tsg`) gives correct results but is over-built: ~61k lines (34k code) in ~105
files, 67 endpoints, ~170 env variables. v2 is a **new project**: same results, simple design, few moving parts,
fully observable from Grafana, deployed on OpenShift. Rule for every choice: **the simplest thing that works in production.**

## 1. Decisions
| # | Decision |
|---|---|
| D01 | New GitHub repo (owner creates it; I push) |
| D02 | Same results as v1 (threats → attack paths → scenarios → controls → review; remediation plans) |
| D03 | 22 endpoints, one job each: 10 scenarios, 7 remediation, 2 embeddings, 3 API-client keys |
| D04 | FastAPI + Socket.IO + Redis + Celery; 3 queues with task routing |
| D05 | MongoDB for everything TSG writes; SQL Server only for the 9 library tables, via stored procedures |
| D06 | AI: **dev = Azure AI Foundry**, **UAT = LiteLLM proxy** — for chat, embeddings and rerank; same code, env values differ |
| D07 | Data stores: **dev = local** SQL Server, MongoDB, Redis; **UAT = cloud-hosted** services (URL + key) |
| D08 | Observability with ready-made tools: Prometheus, Loki, Flower, Alertmanager — **everything viewed in Grafana** |
| D09 | OpenShift, no new DNS: observability served on **paths of the existing FastAPI URL** (like `/docs`) |
| D10 | Business values are code constants, not env variables |
| D11 | OOP + SOLID + KISS + YAGNI; no DI framework, no unused abstractions |
| D12 | Old sessions ignored; no v1 data migration |

## 2. Architecture
**Style:** modular monolith (one app, separate domain modules) + background workers + ready-made observability stack.

```
 Front end ──HTTP──▶ FastAPI app ──enqueue──▶ Redis (3 queues) ──▶ Celery workers ──▶ AI models
           ◀─Socket.IO─┘   ▲                                          │      (Foundry dev / LiteLLM UAT)
                           └──────── Socket.IO events via Redis ◀─────┘
          FastAPI + workers ──▶ MongoDB (TSG data, cache)   SQL Server (library, stored procedures)

 Observability:  API /metrics + worker /metrics + Flower ──▶ Prometheus ──▶ Alertmanager ──▶ alerts
                 pod logs (stdout JSON) ──▶ Alloy ──▶ Loki
                 Grafana  ◀── reads Prometheus, Loki, Alertmanager; links to Flower      (one entry point)
```

**Layers inside each module:** `router` (HTTP only) → `service` (use cases) → `repository` (database only).
Business steps (threat finding, scenario writing, control mapping, planning) are plain classes in `engine/`.
Calls go downward only; modules talk only through services.

**Project structure — FastAPI standard "package by domain" layout** (FastAPI docs *Bigger Applications* +
the community *FastAPI Best Practices* guide): shared app-wide files at the top of `app/`, then **one folder per
business domain, and every domain folder uses the same file names with the same meaning**. ~50 files, ~9k lines.
```
tsg-v2/
├─ app/
│  ├─ main.py               FastAPI app: include each domain router, mount Socket.IO, error handlers, lifespan
│  ├─ config.py             Settings — the env variables (pydantic-settings)
│  ├─ constants.py          app-wide enums (ErrorCode, Queue, TaskName, Event, Header, Collection, StoredProcedure,
│  │                        AiTask) + constant classes (Generation, Controls, Timeouts, Lease)
│  ├─ exceptions.py         base errors + global error handlers (RFC 9457 body)
│  ├─ dependencies.py       shared Depends: current caller (API key + headers), admin key check
│  ├─ logging.py            JSON logging to stdout, request-id middleware
│  ├─ metrics.py            Prometheus metrics (requests, AI calls, jobs, dependency up/down)
│  ├─ database.py           MongoDB client + SQL stored-procedure client
│  ├─ ai.py                 ChatModel, EmbeddingModel, RerankModel (litellm) + concurrency cap
│  ├─ realtime.py           Socket.IO server + emitter used by workers
│  ├─ worker.py             Celery app, 3 queues, task routes, LeasedTask base, reaper, beat schedule
│  │
│  ├─ scenarios/            ── domain: threat scenarios ──
│  │  ├─ router.py          endpoints 1–10 (HTTP only)
│  │  ├─ schemas.py         request / response models
│  │  ├─ dependencies.py    valid_session (load + entity check), service provider
│  │  ├─ service.py         ScenarioService — one method per use case
│  │  ├─ repository.py      SessionRepository, ScenarioRepository (MongoDB)
│  │  ├─ constants.py       enums: SessionStatus, StageState, Decision, StrideCategory, ConflictReason, Finding …
│  │  ├─ exceptions.py      scenario exception classes (each carries its code and message)
│  │  ├─ tasks.py           Celery tasks: find_threats, write_scenarios, map_controls
│  │  └─ engine/            business steps (plain classes, no HTTP, no DB)
│  │     ├─ threats.py      ThreatFinder
│  │     ├─ paths.py        AttackPathSelector
│  │     ├─ writer.py       ScenarioWriter
│  │     ├─ rules.py        scenario rules
│  │     ├─ controls.py     ControlMapper
│  │     └─ prompts.py
│  ├─ remediation/          ── domain: remediation plans ──
│  │  ├─ router.py · schemas.py · dependencies.py · service.py · repository.py · constants.py · exceptions.py · tasks.py
│  │  └─ engine/            planner.py (RemediationPlanner) · scheduler.py (ActionScheduler) · prompts.py
│  ├─ library/              ── domain: threat & control library + embeddings ──
│  │  ├─ router.py · schemas.py · service.py · repository.py (stored procedures) · tasks.py
│  │  └─ search.py          vector index + hybrid search
│  ├─ api_clients/          ── domain: API keys ──
│  │  └─ router.py · schemas.py · service.py · repository.py
│  ├─ intel/                ── domain: threat intel & ATT&CK ──
│  │  └─ service.py · repository.py · tasks.py
│  └─ health/
│     └─ router.py          /health /ready /metrics
├─ tests/                   same folders as app/ (tests/scenarios/, tests/remediation/ …)
├─ sql/procedures/          the 9 stored procedures
├─ scripts/admin.py         admin command line
├─ observability/           Prometheus config + alert rules, Alertmanager config, Loki + Alloy config,
│                           Grafana data sources + dashboards (JSON, provisioned as code)
├─ deploy/                  OpenShift manifests: app, workers, beat, routes, observability stack
├─ docs/  Dockerfile  pyproject.toml  .env.example  README.md
```
**Same file = same job in every domain:** `router.py` HTTP only · `schemas.py` data in/out · `dependencies.py`
request checks · `service.py` business use cases · `repository.py` database only · `constants.py` enums and fixed
values · `exceptions.py` exception classes · `tasks.py` background jobs · `engine/` business steps. A domain uses only
the files it needs (YAGNI).

## 3. API (22, one job each)
Business endpoints: `X-API-Key` + `X-User-Id` + `X-Entity-Id` + `X-Tenant-Id`; another entity's data → 403,
unknown id → 404. Admin endpoints (#18–22): `X-Admin-Key` alone.
| # | Method | Path | Job |
|---|---|---|---|
| 1 | POST | `/v1/sessions` | Start a run (202) |
| 2 | GET | `/v1/sessions/{id}` | Session status |
| 3 | GET | `/v1/sessions/{id}/results` | All scenarios of the session |
| 4 | POST | `/v1/sessions/{id}/accept` | Accept scenarios |
| 5 | POST | `/v1/sessions/{id}/scenarios/reject` | Reject scenarios |
| 6 | POST | `/v1/sessions/{id}/regenerate/scenarios` | Rewrite chosen scenarios (202) |
| 7 | POST | `/v1/sessions/{id}/scenarios/next-set` | Write the next batch (202) |
| 8 | WS | `/ws/socket.io` | Real-time updates |
| 9 | GET | `/v1/entities/{entity_id}/scenarios` | Entity's scenarios |
| 10 | GET | `/v1/sessions/{id}/scenarios/{sid}` | One scenario |
| 11 | POST | `/v1/remediation` | Create a remediation (AI-generated or hand-written scenario) (202) |
| 12 | POST | `/v1/remediation/{id}/accept` | Accept it |
| 13 | POST | `/v1/remediation/{id}/reject` | Reject it |
| 14 | POST | `/v1/remediation/{id}/regenerate` | New version (202) |
| 15 | GET | `/v1/remediation/{id}/status` | Progress |
| 16 | GET | `/v1/remediation/{id}/result` | The remediation |
| 17 | GET | `/v1/remediation` | Find/list (filters: entity, session, scenario, status, decision, risk level; paged) |
| 18 | POST | `/v1/embeddings` | Build/refresh the AI search index (202) |
| 19 | GET | `/v1/embeddings/{job_id}` | Index job progress |
| 20 | POST | `/v1/tsg/api-clients` | Mint a key — secret returned once, only its SHA-256 hash stored (201) |
| 21 | GET | `/v1/tsg/api-clients` | List keys (never secrets) |
| 22 | POST | `/v1/tsg/api-clients/{client_id}/revoke` | Revoke a key (lost key = revoke + mint new) |
Plus `/health`, `/ready`, `/metrics` for OpenShift probes and Prometheus. Full schemas: OpenAPI (generated, `/docs`).

**Socket.IO (#8):** connect with `auth {api_key, user_id, entity_id, tenant_id}` → `subscribe {session_id}` (entity
checked, joins room `session:<id>`, gets the current status) → server sends `session.updated` and
`remediation.updated` with the same body as the status endpoints. Workers emit through Redis; every API pod relays to
its clients. WebSocket transport only (no sticky sessions). On reconnect the client re-subscribes.

**Errors:** one format for all failures (RFC 9457): `{type, title, status, detail, code, request_id}`; 409 includes a
stable `code` (e.g. `generation_in_progress`, `nothing_left`); 503 includes `Retry-After`.

## 4. Data
**SQL Server** — 9 library tables unchanged; app login can only `EXECUTE` these procedures:
`tsg_GetAssetContext`, `tsg_GetThreatLibrary`, `tsg_GetControlLibrary`, `tsg_GetLibraryStamp`,
`tsg_ResolveManualThreat`, `tsg_ListPendingThreats`, `tsg_ApproveThreats`, `tsg_RejectThreats`, `tsg_ImportThreatLibrary`.
Library and controls are cached in memory and reloaded when `tsg_GetLibraryStamp` changes (checked every minute).
- **Change detection is exact:** the stamp is a SHA-256 of each whole table (as JSON, in primary-key order), so any
  edit to any column is seen. It replaced `CHECKSUM_AGG(BINARY_CHECKSUM(*))`, which on DevTest5 missed an edit after
  the 255th character of a long `ControlDescription` and let two identical edits cancel out. Cost ~100 ms SQL CPU.
- **Requests never wait on SQL Server once loaded:** a background thread per process does the minute check; both
  libraries are swapped in together as one snapshot. If SQL Server is unreachable during a check, the last good copy
  keeps being served (logged as `dependency.unavailable`) and the check repeats next minute. Only a process's first
  load can fail a request (503 + Retry-After), because there is nothing to serve yet.
- **`/ready` only proves SQL Server answers** (a pooled connection is pinged); it never runs a procedure.

**MongoDB:**
| Collection | Holds |
|---|---|
| `tsg_sessions` | one run: frozen asset context, stage + lease, threat plan and attack paths, decisions |
| `tsg_scenarios` | scenario content, controls, decision copy |
| `tsg_remediations` | one per scenario: versions, current status, decision |
| `tsg_api_clients` | name, key hash, prefix, active, revoked |
| `tsg_embeddings` · `tsg_embedding_jobs` | vector cache · index job progress |
| `tsg_intel` · `tsg_techniques` | feed items · ATT&CK list |
| `tsg_ai_calls` | prompt + answer of every AI call, tokens, latency (TTL) — kept for audit/parity; too large for Loki |
Every rule (one run per asset, next set served once, accept XOR reject, one remediation per scenario) is one
conditional single-document update — no transactions, no locks. Every screen = 1 read.

**Environments:**
| Store | Dev | UAT |
|---|---|---|
| SQL Server | local instance | cloud-hosted (connection string + credentials) |
| MongoDB | local instance | cloud-hosted (URI + credentials, TLS; provider gives replica set + backups) |
| Redis | local instance | cloud-hosted (URL + key, TLS) |

## 5. Processing
**Queues and routing** (`task_routes` in `worker.py`; the API only sends a task name):
| Queue | Tasks | Worker deployment |
|---|---|---|
| `tsg_threats` | find threats (first run, long) | `worker-threats` |
| `tsg_scenarios` | write scenarios (first batch, next set, regenerate), map controls, remediation | `worker-scenarios` |
| `tsg_maintenance` | build embeddings, reaper, control retries, intel refresh (beat) | `worker-maintenance` |
Long first runs therefore never delay a reviewer's click.

**Enqueue (FastAPI):** save the record as `QUEUED` in Mongo → `celery.send_task(name, [id, epoch])` (ids only) → return
202. If sending fails, the reaper re-sends any record stuck in `QUEUED`.
**Dequeue (Celery):** one message at a time, acknowledged after the task ends (`acks_late`, `prefetch=1`) → the task
claims its record with a conditional update (duplicates claim nothing) → keeps a 30-s lease → writes only while it owns
the lease → emits Socket.IO updates → on temporary errors retries with backoff; when retries run out marks ERROR with a
clear message. No Celery result backend (status lives in Mongo); Flower shows every task.

**Steps (same behaviour as v1, rules in `docs/RULES.md`):**
1. Start run → load asset context (procedure) → session `QUEUED` → `threats` queue.
2. Threats: search library per STRIDE category → AI relevance check → gap-fill only if the library has nothing →
   remove duplicates → pick actors (1 acting + ≤2 alternates) → AI attack paths → select (coverage first; max 15).
3. Scenarios: 6 at a time → AI write → clean + check rules → ≤1 repair → AI consistency check → save.
4. Controls: search + rerank → 5–25 controls, never empty.
5. Review: accept / reject / regenerate / next set.
6. Remediation: control top-up → AI plan (JSON schema) → schedule actions (critical path, dates) → accept / reject / regenerate.
7. Recovery: the reaper (every 60 s) requeues work whose lease expired.

**Library search** (`app/library/search.py`, v1's method and values): a keyword leg (BM25, k1 1.5, b 0.75) and a
vector leg (cosine over the cached, normalised library vectors), each cut to `top_k`, merged by reciprocal-rank
fusion (k 60); an exact name match comes first. Threats are searched within one STRIDE category (the scope applies
before the cut), controls and actors over the whole library. Texts embedded: the threat name; `"ControlName:
ControlDescription"`; the actor name. The indexes of a library snapshot are built once per process (1.3 s from the
vector cache; the first ever build embeds ~1.8k rows, ~2 min) and rebuilt when the library changes; the maintenance
worker pre-builds them every 30 min so no run waits. Many queries share one embedding call.

**Live updates** (`app/realtime.py`): Socket.IO `AsyncServer` mounted at `/ws/socket.io` beside FastAPI, WebSocket
only, `AsyncRedisManager` on channel `tsg_socketio`. Connect `auth` = the HTTP identity (same checks, 401 body on
refusal); `subscribe {session_id}` checks the entity (403/404 as `error` events) and answers with the current status.
Workers publish with a write-only `RedisManager`; publishing is best effort (the change is already saved).

## 6. AI usage
| Model | Dev (Azure AI Foundry) | UAT (LiteLLM proxy) |
|---|---|---|
| Chat (inference) | Foundry chat deployment | proxy chat model (+ fallback model) |
| Embeddings | Foundry embedding deployment | proxy embedding model |
| Rerank | Foundry rerank model | proxy rerank model |
All three go through litellm with model names from env (`openai/…` on the Foundry endpoint in dev, `litellm_proxy/…`
in UAT) — no code differences. **Model profiles:** `.env` only *names* a model; what that model is like lives in
`app/model_profiles.py`, one frozen dataclass per model, keyed by that name (a local model path by its folder name):
| Profile | Properties | Dev | UAT |
|---|---|---|---|
| `ChatModelProfile` | max output tokens · timeout · JSON mode · reasoning effort (`"none"` = thinking off) | `openai/Kimi-K2.6`: 12,288 · 90 s | `litellm_proxy/kimi-k2.5`, `litellm_proxy/glm-5`: 12,288 · 120 s |
| `EmbeddingModelProfile` | vector size (checked on every answer) · batch cap · timeout | `openai/text-embedding-3-large`: 3,072 · 64 | `litellm_proxy/qwen3-embedding-8b-mig`: 4,096 · 32 |
| `RerankModelProfile` | timeout · control cut-off (0–100, a calibration value) | `bge-reranker-v2-m3` (local): 60 | `litellm_proxy/qwen3-reranker-8b-mig`: 60 |
The API builds every AI gateway at start-up, so a model with no profile stops start-up with its name, instead of
failing every later call. The fallback chat model is called with **its own** profile (not the first model's options).
**Adding a model** = one entry in `model_profiles.py` + its name in `.env`. **Rationale:** model limits are facts
about the model, not about the deployment — one place, typed, reviewed in code; `.env` stays connections and names.
- **Chat:** related questions batched into one call; strict JSON answers; fixed instructions first so the provider's
  prompt cache is used; output tokens capped; thinking off; fallback model only on outage.
- **Embeddings:** the library is embedded once (`POST /v1/embeddings`, only changed rows) and held in memory — search
  is a matrix multiply; query texts embedded in one batched call and cached.
- **Rerank:** only for control mapping, one call per scenario.
- **Limits:** one shared concurrency cap (Redis); timeouts and bounded retries; every call measured (tokens, latency,
  errors) in Prometheus and stored in `tsg_ai_calls`.

## 7. Errors and logging
- `AppError` → `NotFound`, `Forbidden`, `Conflict(code)`, `Invalid`, `Unavailable(retry_after)`; three handlers
  (`AppError`, validation, unexpected → 500 with `request_id`, stack trace logged, nothing internal returned).
- Repositories and the AI gateway convert driver errors into these; nothing is swallowed.
- Timeouts on every outbound call; retries only for temporary errors.
- **Logs:** JSON to stdout with `request_id`, `session_id`, `task_id`, `entity_id`; secrets masked; collected by Alloy
  into **Loki** and searched in Grafana (by request id, session id, error).

## 7A. Fixed values: enums and constant classes (no magic strings or numbers)
**Rule:** every fixed set of values is an `Enum` (`StrEnum` for text, `IntEnum` for numbers) and every fixed number is
a `Final` attribute of a constants class. Code never compares or returns a bare string/number literal for these.
Shared ones live in `app/constants.py`; domain ones in `<domain>/constants.py`; exceptions in `exceptions.py`.
| Kind | Where | Examples |
|---|---|---|
| Statuses (kept simple — one vocabulary everywhere) | `app/constants.py` | `Status` = `queued` · `running` · `done` · `failed` — the same four values for a run, a scenario, a scenario's controls and a remediation · `Decision` = `pending` · `accepted` · `rejected` · `Step` = `threats` · `scenarios` · `controls` (only says where a run is) |
| Business values | `scenarios/constants.py` | `StrideCategory` (6, with display order) · `ActorRole` (acting, alternate) · `RouteStatus` (confirmed, assumed, standalone) · `ControlMatch` (exact, nearest) · `ScenarioSource` (generated, manual) |
| Conflict / refusal reasons | `scenarios/constants.py` | `ConflictReason` (active_session_exists, generation_in_progress, nothing_left, target_reached, scenarios_abandoned, already_decided, duplicate_version, manual_session) |
| Validation findings + messages | `scenarios/constants.py` | `Finding` enum whose members carry `(code, severity, message template)`, e.g. `TITLE_NAMES_ASSET = ("title_names_asset", Severity.REPAIR, "The title names the asset {name}.")`; `Severity` (blocking, repair, advisory) |
| Error codes | `app/constants.py` | `ErrorCode` (validation_error, unauthorized, forbidden, not_found, conflict, unavailable, ai_unavailable, internal_error) |
| Exceptions | `app/exceptions.py`, `<domain>/exceptions.py` | classes, not strings: `AppError` → `NotFound`, `Conflict`, `Unavailable`…; `SessionNotFound(NotFound)`, `GenerationInProgress(Conflict)` — each class fixes its `code`, HTTP status and title; every title and message is a constant (`ErrorTitle`, `ErrorMessage` in `app/constants.py`; domain messages such as `ApiClientMessage` in `<domain>/constants.py`) — never inline text in a `raise` |
| Infrastructure names | `app/constants.py` | `Queue` (tsg_threats, tsg_scenarios, tsg_maintenance) · `TaskName` · `Event` (session.updated, remediation.updated, error) · `Header` (X-API-Key, X-User-Id, X-Entity-Id, X-Tenant-Id, X-Admin-Key, Idempotency-Key, X-Request-Id) · `Collection` · `StoredProcedure` · `AiTask` (relevance_gate, gap_fill, same_attack, attacker_fit, attack_paths, write_scenario, repair_scenario, consistency_check) |
| Fixed numbers | `app/constants.py` | `class Generation: FIRST_BATCH: Final = 6; NEXT_BATCH: Final = 6; MAX_SCENARIOS: Final = 15` · `class Controls: MIN = 5; MAX = 25; SHORTLIST = 60; BACKFILL_RATIO = 0.42` · `class Timeouts` · `class Lease: SECONDS = 120; HEARTBEAT = 30; REAPER_EVERY = 60; MAX_ATTEMPTS = 5` |
| Function and variable names | everywhere | clear verb + object, never vague or one-letter: `find_client_id_for_api_key`, `get_stored_procedure_client`, `build_problem_response`, `report_readiness` — not `verify`, `get_sql`, `problem`, `ready`, `s`, `k` |
| Name prefixes | everywhere | `tsg_` on stored procedures (`tsg_GetAssetContext`), MongoDB collections (`tsg_sessions`, `tsg_scenarios`, `tsg_remediations`), queues (`tsg_threats`, `tsg_scenarios`, `tsg_maintenance`) and task names (`tsg_find_threats`); remediation-only items use `plan_`; env variables keep `CII_` |
| User-facing texts | `<domain>/constants.py` | `PlanNote`, `RouteNote` message templates (`StrEnum` with `{placeholders}`), so every message is written once |
Pydantic schemas use these enums as field types, so OpenAPI lists the allowed values and invalid input is rejected
automatically; MongoDB stores the enum's value (a plain string). **Rationale:** typos become type errors (mypy), each
value and message is defined once, the API contract documents itself, and renaming is safe.

## 8. Observability (ready-made tools, one entry point: Grafana)
| Tool | Role | What it tracks |
|---|---|---|
| **Prometheus** | metrics store | API requests/latency/errors per endpoint; jobs started/failed/duration per queue; AI calls/tokens/latency/errors per model; Socket.IO connections; dependency up/down (SQL, Mongo, Redis, AI) |
| **Loki** (+ Alloy collector) | log store | every log line of API, workers and beat |
| **Flower** | Celery monitor | live queues, workers, each task (args, state, retries, runtime); its `/metrics` feed Prometheus |
| **Alertmanager** | alert delivery | sends alerts (mail / Teams) and shows them in Grafana |
| **Grafana** | single entry point | data sources Prometheus, Loki, Alertmanager; dashboards: API, Pipeline (runs/stages/failures), Celery & queues, AI usage & cost, Dependencies, Logs; link to Flower |
Dashboards, data sources and alert rules are files in `observability/`, provisioned automatically (no manual setup).
**Alerts (start set):** API 5xx rate high · API latency high · job failures / retries exhausted · queue backlog
growing · no worker running · SQL / Mongo / Redis / AI unreachable · pod restarts.

## 9. Security
Hashed API keys (shown once), admin key compared in constant time, entity check on every resource, response models
never expose stored documents, request size and rate caps, only the platform backend can reach the API (network
policy), SQL login can only run the procedures, secrets in OpenShift Secrets, TLS to cloud services, AI answers
validated before use, names passed to the AI as data (prompt-injection defence). Grafana and Flower behind login;
Prometheus, Loki and Alertmanager not exposed (Grafana reads them inside the cluster). Checked against OWASP API Top 10
and OWASP LLM Top 10.

## 10. Configuration
Env variables only: `TSG_ENV`, `TSG_SQL_DSN`, `TSG_MONGO_URI`, `TSG_MONGO_DB`, `TSG_REDIS_URL`, `TSG_AI_BASE_URL`,
`TSG_AI_API_KEY`, `TSG_CHAT_MODEL`, `TSG_CHAT_FALLBACK_MODEL`, `TSG_EMBEDDING_MODEL`, `TSG_RERANK_MODEL`,
`TSG_ADMIN_API_KEY`, `TSG_OTX_API_KEY`, `TSG_CORS_ORIGINS`, `TSG_LOG_LEVEL`, `TSG_PUBLIC_URL` (the fixed route URL).
Dev: local addresses + Foundry endpoint/key. UAT: cloud URLs/keys + LiteLLM proxy URL/key (OpenShift Secret).
Per-model properties (tokens, timeouts, vector size, batch cap, cut-off) are in `app/model_profiles.py` (§6);
everything else is in `constants.py`.

## 11. Deployment (OpenShift, one fixed URL)
**Workloads:** `api` ×2 (FastAPI + Socket.IO), `worker-threats` ×2, `worker-scenarios` ×2, `worker-maintenance` ×1,
`beat` ×1, plus `grafana`, `prometheus`, `alertmanager`, `loki`, `alloy`, `flower` (×1 each, same namespace).
Data stores are cloud-hosted in UAT (not deployed by us). One Docker image for API, workers and beat (non-root).

**No new DNS — everything on paths of the existing FastAPI URL** (OpenShift path-based Routes on the same host):
| URL | Serves | Exposed? |
|---|---|---|
| `http://<tsg-host>/` | API (`/v1/...`, `/ws/socket.io`) | yes |
| `http://<tsg-host>/docs` | Swagger UI | yes (as today) |
| `http://<tsg-host>/grafana/` | Grafana — dashboards, logs, alerts | yes (login) |
| `http://<tsg-host>/flower/` | Flower — Celery tasks (also linked from Grafana) | yes (login) |
| Prometheus, Loki, Alertmanager | internal services only, viewed through Grafana | no |
How: extra Route objects with the same `host` and `path: /grafana` / `path: /flower`; Grafana runs with
`GF_SERVER_ROOT_URL=http://<tsg-host>/grafana/` + `GF_SERVER_SERVE_FROM_SUB_PATH=true`; Flower with
`--url_prefix=flower`. Requirement: these Routes live in the same namespace as the API Route (OpenShift's rule for
sharing a host). Fallback if the cluster forbids it: `oc port-forward` to Grafana.
The route is plain http (as today); Socket.IO therefore connects with `ws://`. Probes on `/health` and `/ready`;
resource limits on every pod; network policy; rolling updates; rollback = previous image tag.

**Dev:** local SQL Server, MongoDB, Redis; Azure AI Foundry; `dev.ps1` starts API, workers, beat, Flower; optional
`docker compose -f observability/compose.yml up` for Grafana/Prometheus/Loki/Alertmanager on the laptop.
**CI (GitHub Actions):** ruff, mypy, pytest (with Mongo, Redis, SQL Server containers), pip-audit; build and push the
image on a version tag.

## 12. Testing
Unit tests for the pure parts (rules, path selection, scheduler); repository tests on real Mongo and SQL Server; API
tests with a fake AI model; parity test replaying ~20 UAT sessions against v1's results; one kill-a-worker test and
one double-click test. Every business rule in `docs/RULES.md` has a test.

## 13. Architecture and patterns — the answer for management (with rationale)
**One-sentence answer:** *TSG v2 is a **modular monolith** with a **layered architecture**, using **asynchronous,
queue-based processing** for the AI work and **real-time push** to the user interface — built on FastAPI, Celery,
Redis, Socket.IO and MongoDB, following SOLID, KISS and YAGNI, and observed end-to-end in Grafana.*

| # | Choice | What it means | Rationale (why) |
|---|---|---|---|
| 1 | **Modular monolith** (not microservices) | one application, split into independent domain modules (scenarios, remediation, library, keys, intel) | One product, one team, shared data: one deployment is cheaper to build, test, run and debug. Modules talk only through each other's service, so any module can become its own service later without a rewrite. Microservices would add network calls, separate releases and distributed failures with no business benefit at this scale. |
| 2 | **Layered architecture** (router → service → repository) | HTTP, business rules and database code live in separate layers | Each layer changes for one reason: a database change never touches business rules; business rules are tested without HTTP or a database; new developers know where everything is. |
| 3 | **FastAPI "package by domain" structure** | every domain folder has the same files (router, schemas, service, repository …) | Industry-standard FastAPI layout: predictable, easy to onboard, easy to review. |
| 4 | **Asynchronous request–reply** | the API answers immediately (202) and the AI work runs in the background | AI generation takes minutes; holding an HTTP request that long fails under load and through proxies. Users get an instant response and follow progress. |
| 5 | **Task queue with routing** (Celery + Redis, 3 queues) | long first runs, user clicks and maintenance go to separate queues and worker pools | A burst of new runs never slows down a reviewer's click; each workload is scaled on its own; jobs survive restarts and are retried automatically. |
| 6 | **Publish–subscribe, real-time push** (Socket.IO over Redis) | workers publish progress; every API server pushes it to connected users | Users see progress instantly without refreshing; no constant polling, so less load on servers and the database; works across several API servers. |
| 7 | **Repository pattern + stored procedures** | all database access sits in repository classes; SQL Server only through 9 named procedures | Data access is in one known place; SQL is reviewable by the DBA; the app's SQL login can only run those procedures (least privilege); the shared library tables stay unchanged for the platform. |
| 8 | **Document model / aggregate** (MongoDB) | a session, a scenario and a remediation are each one document | Matches the data's natural shape (AI output is JSON); every screen is one read and every action one atomic update — fast, no joins, no locks. |
| 9 | **Optimistic concurrency + leases** | updates apply only if the record is still in the expected state; a worker owns a job only while its lease is valid | Double clicks, retries and crashed workers can never create duplicates or overwrite newer work — without slow database locks. |
| 10 | **Adapter / gateway for AI models** (litellm) | one interface for chat, embeddings and rerank | Azure AI Foundry in dev, LiteLLM proxy in UAT, any future provider — by configuration only; retries, limits and cost tracking in one place; no vendor lock-in. |
| 11 | **Dependency injection** (FastAPI `Depends`, constructor arguments) | each class receives what it uses instead of creating it | Easy testing (a fake AI model replaces the real one); no extra framework (KISS). |
| 12 | **Cache-aside** (embeddings, library in memory) | results are reused instead of recomputed | Lower AI cost and faster responses; the same text is never embedded twice. |
| 13 | **Retry with back-off + timeouts** | temporary failures are retried a few times with growing waits | Survives brief outages of AI or databases without overloading them; nothing waits forever. |
| 14 | **Observability with standard tools** (Prometheus, Loki, Flower, Alertmanager → Grafana) | metrics, logs, tasks and alerts in one place | Problems are seen and alerted before users report them; one URL for operations; no custom tooling to maintain. |
| 15 | **Standard errors + structured logs** (RFC 9457, JSON logs, request id) | one error format; every log line traceable to one request | Faster support and incident analysis; the front end handles every error the same way. |
| 16 | **Principles: SOLID, KISS, YAGNI, 12-factor** | small single-purpose classes; nothing built "for later"; config from environment | About a third of v1's code: cheaper to maintain, fewer defects, the same image runs in every environment. |

**How the principles are applied (concrete examples)**
| Principle | Example in TSG v2 | Rationale |
|---|---|---|
| **S** – Single responsibility | `router.py` only HTTP; `service.py` only use cases; `repository.py` only database; `ScenarioWriter` only writes scenarios; `ActionScheduler` only computes dates | a change has one place to go; small classes are easy to test |
| **O** – Open/closed | a new scenario rule is a new function added to the rules list — the writer is not edited; a new AI provider is a new model name in env — no code change | extend without risking working code |
| **L** – Liskov substitution | the fake AI model used in tests has the same methods as the real one, so services work unchanged with either | reliable tests without paying for AI calls |
| **I** – Interface segregation | three small AI classes (chat, embedding, rerank); `ControlMapper` gets only search + rerank, not chat | classes depend only on what they use |
| **D** – Dependency inversion | services receive their repository and AI model in the constructor (`ScenarioWriter(chat, intel)`); FastAPI `Depends` supplies them | swap real/fake implementations; no hidden globals |
| **KISS** | one app (not microservices); 3 queues; ready-made observability; sync database code; one AI library; plain classes | fewer moving parts → fewer failures, faster onboarding |
| **YAGNI** | no DI framework, no generic base repository, no plugin system, no feature flags, no legacy code, no settings nobody changes, files only where needed | nothing to maintain that nobody uses |
| **No magic values** | every status, reason, finding, message, queue, header and limit is an `Enum` member or a `Final` constant (§7A) | typos caught by the type checker; one place to change; OpenAPI shows allowed values |
| **Repository pattern** | `SessionRepository`, `ScenarioRepository`, `RemediationRepository`, `ApiClientRepository` (MongoDB) and `LibraryRepository` (stored procedures) — the only classes that touch a database | all queries in one place per domain; storage can change without touching business rules; easy to test |

**Object-oriented design (OOP) — the four pillars + composition**
| Concept | Example in TSG v2 | Rationale |
|---|---|---|
| **Encapsulation** | `SessionRepository` hides every MongoDB query; `ScenarioService.accept()` is the only way to accept (state cannot be changed from outside); `ChatModel` hides retries, limits and logging inside | rules are enforced in one place and cannot be bypassed |
| **Abstraction** | services expose business actions (`start_run`, `next_set`, `accept`, `regenerate`); `ChatModel.complete(task, prompt, schema)` hides which provider answers | callers think in business terms, not database or provider details |
| **Inheritance** (used sparingly) | `AppError` → `NotFound`, `Conflict`, `Unavailable`…; every background job extends `LeasedTask`; schemas extend Pydantic `BaseModel`; `Settings` extends `BaseSettings` | shared behaviour written once (error format, lease/retry/logging for every job) |
| **Polymorphism** | one error handler serves every `AppError` subclass (each carries its own status and code); every job runs through `LeasedTask.run()` and differs only in `execute()`; a fake AI model can stand in for the real one | new error types and new jobs need no changes to shared code |
| **Composition over inheritance** | `ScenarioService` *has* repositories and engine classes; `ScenarioWriter` *has* a `ChatModel` — no deep class trees | flexible, easy to test, easy to read |

**Likely follow-up questions**
| Question | Answer and rationale |
|---|---|
| Why not microservices? | See #1 — no independent scaling or team boundary needs it today; the module boundaries keep the option open. |
| Why both MongoDB and SQL Server? | The shared threat/control library already lives in SQL Server and other platform parts use it; TSG's own data is document-shaped, so MongoDB serves it faster and simpler. |
| Why Celery and not Kafka? | We need reliable background jobs, not an event-streaming platform; Celery + Redis does exactly that with far less to run. |
| Will it scale to 10,000 users? | Yes — API and workers scale out by adding pods; the real limit is AI-provider capacity, which is sized from measured calls per run (visible in Grafana). |
| How do we know it is healthy? | Grafana shows API, jobs, queues, AI usage, dependencies and logs in one place; Alertmanager alerts on failures. |
| How is it kept secure? | Hashed API keys, entity checks on every record, least-privilege database access, secrets outside code, monitoring tools behind login, checked against OWASP API and LLM Top 10. |
| How do we know results match v1? | Every v1 business rule (397) has a test, and a replay of real UAT sessions is compared with v1 before switching. |
| Standards followed? | REST + OpenAPI 3.1, RFC 9457 errors, Idempotency-Key, 12-factor, JSON logging, Prometheus metrics, OWASP, Semantic Versioning, C4 diagrams + ADRs for documentation. |

## 14. Documentation (in the repo)
`README.md` (run in 5 steps) · `docs/SDD.md` (this, with C4 context/container diagrams) · `docs/API.md` + OpenAPI ·
`docs/RULES.md` (397 business rules → tests) · `docs/adr/` (one page per decision in §1) · `docs/RUNBOOK.md`
(deploy, rollback, rotate keys, rebuild embeddings, read dashboards, handle alerts).

## 15. Open items (default chosen)
1. Foundry: confirm one endpoint/key serves chat, embedding and rerank (else one extra base-URL setting per model type).
2. Max scenarios per run = 15 (constant).
3. AI-proposed attacker → nearest library actor, flagged (your "never invented" rule).
4. Alert channel (mail or Teams webhook) and recipients.
5. Persistent volumes for Prometheus and Loki in OpenShift (without them history is lost on restart); retention 15 days.
6. Confirm the cloud MongoDB is a replica set with backups, and the cloud Redis has TLS + persistence for queues.
7. The fixed URL is plain **http**: API keys, the admin key and the Grafana/Flower logins cross the network unencrypted
   (Socket.IO uses `ws://`). Zero-DNS fix if allowed: set the existing Route to `tls: termination: edge` — OpenShift then
   serves the same host over https with the router's default certificate, no DNS or certificate request needed.

## 16. Build plan
| M | Deliverable | Done when |
|---|---|---|
| M0 | `docs/RULES.md`, UAT captures for parity, this SDD in the repo | you sign off |
| M1 | Skeleton: shared files, health, API-client keys, OpenAPI for all endpoints, CI; observability stack on dev + `/grafana`, `/flower` routes in UAT | front end has the contract; Grafana shows the API |
| M2 | Library + embeddings API + search | search parity with v1 |
| M3 | Sessions, Socket.IO, queues, leases, reaper; Celery dashboards + alerts | kill-worker test passes; jobs visible in Grafana/Flower |
| M4 | Threat finding | parity on captured sessions |
| M5 | Scenarios + controls + review actions | scenario parity, rule tests green |
| M6 | Remediation | scheduler and flow tests green |
| M7 | Admin CLI, runbook, UAT side by side, load test, switch front end | parity + load sign-off; all alerts tested |

## 17. Effort estimate (person-days, experienced Python developer, incl. unit tests)
| Milestone | Work | Days |
|---|---|---|
| M0 | Rules catalogue (397 rules tagged + owner review) 3 · parity capture script + runs 2 · SDD/ADRs/C4 2 | 7 |
| M1 | Repo, CI, Dockerfile 2 · shared core (config, errors, logging, metrics, auth) 3 · Mongo client + 9 stored procedures 4 · API-client keys 1.5 · health 0.5 · OpenAPI contract + API doc + v1→v2 field map 3 · observability stack (Prometheus, Loki/Alloy, Flower, Alertmanager, Grafana dashboards + alerts, routes) 5 | 19 |
| M2 | Library repository + cache 2 · AI gateway (chat/embed/rerank, retries, cap, metrics) 3 · vector index + hybrid search 2.5 · embeddings API + job 1.5 · search parity 1 | 10 |
| M3 | Sessions repository/service + asset context 3 · Celery (3 queues, routing, LeasedTask, reaper, beat) 3 · Socket.IO (auth, rooms, Redis, worker emitter) 2.5 · kill-worker / double-click tests 1.5 | 10 |
| M4 | Prompts port 2 · ThreatFinder (search, AI gate, gap-fill, dedupe, actors) 6 · AttackPathSelector + golden tests 2 · parity replay + fixes 3 | 13 |
| M5 | ScenarioWriter 5 · scenario rules + tests 4 · ControlMapper 3 · accept/reject/regenerate/next-set/results/list 4 · parity + rule tests 3 | 19 |
| — | Intel module (CISA KEV/ICS, OTX, ATT&CK lookup) | 4 |
| M6 | Remediation endpoints/service/repository 3 · planner (snapshot, register controls, AI plan, checks, top-up) 4 · scheduler + golden tests 2.5 · hand-written scenario flow 2.5 | 12 |
| M7 | Admin CLI 3 · runbook/README/ADRs 3 · OpenShift UAT deployment 3 · UAT side-by-side parity + fixes 5 · load test + tuning 3 · front-end switch support 3 | 20 |
| | **Development total** | **114** |
| | Contingency 20 % (Foundry/proxy differences, cloud-store access, parity mismatches) | 23 |
| | **Backend total** | **≈137** |
Outside the backend estimate: front-end changes to the new API ~10–15 days (front-end team); QA test design and UAT
execution ~15 days; DevOps/platform (namespace, routes, volumes, secrets, cloud-store access) ~8 days; owner reviews ~8 days.
Calendar: 1 developer ≈ 27 weeks; 2 developers + part-time DevOps and QA ≈ 15–16 weeks; AI-assisted build (Claude
writes code and tests, 1 developer reviews, runs UAT and coordinates) ≈ 8–10 weeks, gated by reviews, UAT access and
parity iterations.

## On approval
M0 starts in the current repo (read-only); M1 starts when you send the GitHub repo URL.

## Verification
CI green at each milestone; parity replay from M2; kill-worker and double-click tests at M3/M5; every dashboard and
alert checked in UAT through `http://<tsg-host>/grafana/`; UAT side-by-side and a load test before the front end switches.
