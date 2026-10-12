# TSG v2 — System Design (Phase 1: Scenarios)

| Version | Date | Scope | Based on |
|---|---|---|---|
| 1.0 | 2026-10-08 | Phase 1 — threat scenarios end to end (2 days) | `docs/SDD.md` v0.6 (approved) |

Phase 1 delivers the scenario flow solidly: start a run → threats → attack paths → scenarios → controls →
review (accept, reject, next set, regenerate), live updates over Socket.IO, three Celery queues, API-key auth.
Remediation, the embeddings API, the full Grafana stack and the admin CLI are Phase 2 (§7).

---

## 1. Requirements

### 1.1 Functional (Phase 1)
| # | The system must… |
|---|---|
| F1 | Start a scenario run for one asset and 1–50 of its supporting systems (idempotent; one active run per asset) |
| F2 | Find the threats that apply (library first, STRIDE only, AI relevance check, AI gap-fill only when the library has nothing) |
| F3 | Group threats into attack paths and select them (coverage first; at most 15 scenarios; never padded) |
| F4 | Write one scenario per path, 6 per batch, applying every scenario rule (titles, no codes, risk statement, actors, route) |
| F5 | Map 5–25 controls to every scenario (never empty), after the scenario is shown |
| F6 | Let reviewers accept / reject scenarios, write the next batch, and regenerate chosen scenarios |
| F7 | Show status, results, one scenario, and an entity's scenarios; push every change live (Socket.IO) |
| F8 | Authenticate callers with API keys (minted with the admin key, shown once) and keep each entity's data separate |
| F9 | Produce the same results as v1 for the same input (rules in `docs/RULES.md`) |

### 1.2 Non-functional
| Quality | Target (Phase 1 dev; UAT targets confirmed in Phase 2) |
|---|---|
| Read latency | p95 < 300 ms (status, results, lists) |
| Write latency | p95 < 500 ms (start run, accept, reject, next set, regenerate — work runs in the background) |
| First 6 scenarios | p95 < 10 min after start (bounded by AI speed) |
| Live update delay | < 2 s from a worker's write to the browser |
| Availability | 99.5 % in business hours (UAT/prod: ≥ 2 API and worker pods) |
| Durability | no accepted decision or written scenario is lost on a pod/worker crash |
| Recovery | an interrupted job resumes within 2 minutes (lease expiry + reaper) |
| Scale | 10,000 registered users; ~1,000 active at peak (§5.1) |
| Cost | AI calls bounded per run (batched, cached, capped); no paid component besides AI |
| Security | API key + identity headers on every call; entity isolation; least-privilege database access |

### 1.3 Constraints
- **Time:** 2 days for Phase 1; one AI-assisted developer + owner review.
- **Stack (decided):** Python 3.12, FastAPI, python-socketio, Celery 5 + Redis, MongoDB, SQL Server (stored
  procedures only), litellm.
- **Data:** 9 SQL library tables must stay unchanged (shared with the platform); platform tables are read-only.
- **Environments:** dev = local SQL Server (SQLEXPRESS), MongoDB, Redis (Memurai) + Azure AI Foundry; UAT = cloud-hosted
  stores + LiteLLM proxy; OpenShift, one fixed **http** URL, no new DNS.
- **Principles:** OOP, SOLID, KISS, YAGNI; FastAPI "package by domain" layout.

### 1.4 Assumptions (explicit)
| # | Assumption | If wrong |
|---|---|---|
| A1 | Peak 200 runs/hour (UAT/prod) | AI capacity and worker counts scale linearly (§5.1) |
| A2 | ~40 AI calls per first run, ~15 s and ~7.5k tokens each | measured from v1 Prompt_Log; §5.1 recalculated |
| A3 | Library ≈ 75 threats, ≈ 200 actors, ≈ 1,300 controls (v1 seed) | > 100k rows → move vectors out of memory (§8) |
| A4 | Embedding model `text-embedding-3-large` (3,072 dimensions) in dev | vector memory changes proportionally |
| A5 | A reranker is reachable in dev (Foundry) | without it controls rank by search score only → parity not guaranteed |
| A6 | Nothing but this API reads TSG data | otherwise reporting needs an export |
| A7 | Old v1 sessions are not migrated | entity lists start empty in v2 |

---

## 2. High-level design

### 2.1 Components
```
                   ┌───────────────────────────── TSG v2 (one image) ─────────────────────────────┐
 Front end ─HTTP──▶│ API pods: FastAPI routers + Socket.IO server                                  │
          ◀─WS─────│   scenarios · api_clients · health                                            │
                   │        │ send_task (ids only)                     ▲ Socket.IO events          │
                   │        ▼                                          │ (Redis pub/sub)          │
                   │   Redis ── queues: threats │ scenarios │ maintenance ─┘                           │
                   │        │                                                                      │
                   │        ▼                                                                      │
                   │ Worker pods: worker-threats · worker-scenarios · worker-maintenance · beat        │
                   │   ThreatFinder → AttackPathSelector → ScenarioWriter → ControlMapper          │
                   └──────┬──────────────────────┬──────────────────────────┬──────────────────────┘
                          ▼                      ▼                          ▼
                   MongoDB (sessions,     SQL Server (library +       AI models via litellm
                   scenarios, api_clients, platform tables, stored     (chat · embeddings · rerank)
                   embeddings, ai_calls)  procedures only)
```

### 2.2 Data flow — start a run to first scenarios
```
Client            API                       Mongo        Redis/Celery           Worker                     AI / SQL
  │ POST /v1/sessions                          │              │                    │                          │
  │──────────────▶│ auth, entity check          │              │                    │                          │
  │               │ tsg_GetAssetContext ─────────────────────────────────────────────────────────────────────▶ SQL
  │               │ insert session (QUEUED) ───▶│              │                    │                          │
  │               │ send_task(find_threats) ───────────────────▶│                    │                          │
  │◀── 202 {session_id}                         │              │──── deliver ──────▶│ claim (conditional upd.) │
  │ socket: subscribe(session)                  │              │                    │ search library (memory)  │
  │◀──────────── session.updated (threats running) ◀──────────────── emit ──────────│ AI gate ×6, gap-fill,    │
  │                                             │              │                    │ dedupe, actors, paths ──▶ AI
  │                                             │◀──── save plan (one update) ──────│                          │
  │                                             │              │◀── send_task(write_scenarios) ──│                 │
  │                                             │              │──── deliver ──────▶│ write 6 scenarios in parallel ▶ AI
  │◀──────────── session.updated (scenarios ready) ◀─────────────────── emit ───────────│ save scenarios; REVIEW       │
  │                                             │              │◀── send_task(map_controls) ─│                 │
  │◀──────────── session.updated (controls ready)◀────────────────── emit ──────────│ search + rerank ────────▶ AI
```

### 2.3 API contracts (Phase 1)
Common headers: `X-API-Key`, `X-User-Id`, `X-Entity-Id`, `X-Tenant-Id`. Errors: RFC 9457 (§3.5).
| # | Method · Path | Request | Success |
|---|---|---|---|
| 1 | `POST /v1/sessions` (+ optional `Idempotency-Key`) | `{entity_id, asset_id, supporting_system_ids[1..50], service_id?, sector_id?, subsector_id?}` | 202 `{session_id, status}` · 200 on replay |
| 2 | `GET /v1/sessions/{id}` | — | 200 status (below) |
| 3 | `GET /v1/sessions/{id}/results` | `?limit&offset` | 200 `{items:[scenario], total}` |
| 4 | `POST /v1/sessions/{id}/accept` | `{scenario_ids:[…] \| "all", replace_accepted?}` | 200 `{accepted[], replaced[], controls_pending[]}` |
| 5 | `POST /v1/sessions/{id}/scenarios/reject` | `{scenario_ids:[…]}` | 200 `{rejected[]}` |
| 6 | `POST /v1/sessions/{id}/regenerate/scenarios` | `{scenario_ids:[1..50]}` | 202 `{epoch}` |
| 7 | `POST /v1/sessions/{id}/scenarios/next-set` | `{}` | 202 `{epoch}` |
| 8 | `WS /ws/socket.io` | `auth {api_key, user_id, entity_id, tenant_id}`; `subscribe {session_id}` | events §3.4 |
| 9 | `GET /v1/entities/{entity_id}/scenarios` | `?decision&limit&offset` | 200 `{items:[scenario], total}` |
| 10 | `GET /v1/sessions/{id}/scenarios/{sid}` | — | 200 scenario |
| 20–22 | `POST /v1/tsg/api-clients` · `GET /v1/tsg/api-clients` · `POST …/{client_id}/revoke` | `X-Admin-Key` only | 201 `{client_id, api_key (once), key_prefix}` · 200 list · 200 revoked |
| — | `GET /health` · `GET /ready` · `GET /metrics` | — | probes, Prometheus |

Status body (#1, #2, also pushed as `session.updated`; BLUEPRINT R-6):
```json
{ "session_id": "8139828e…", "entity_id": 127, "asset_id": 1207, "asset_name": "Smart Grid Infrastructure (SGI)",
  "user_id": "1", "session_status": "completed",
  "progress": {"threats": "COMPLETE", "scenarios": "COMPLETE", "controls": "RUNNING", "overall": "awaiting_review",
               "timings": {"threats": 126.1, "scenarios": 8.4, "controls": null}, "error_message": {},
               "last_next_set": null, "last_regen": null,
               "scenario_count": {"total": 170, "served": 6, "remaining": 164, "complete": false,
                                  "pending_review": 6, "accepted": 0, "rejected": 0}},
  "updated_at": "2026-10-11T20:28:51.676Z" }
```
Results body (#3): the run, its `progress` as above, then `scenarios[]` and `total`. One scenario (#3, #9, #10):
```json
{ "scenario_id": "1b9e…", "session_id": "7f3c…", "version": 1, "status": "done",
  "scenario": {"threat_category": "Tampering", "contributing_categories": [], "threat_type": "Malware/Ransomware",
               "threat_name": "…", "supporting_systems_involved": [{"supporting_system_id": 321,
               "supporting_system": "SCADA historian", "is_entry_point": true}],
               "scenario_title": "Loss of process history",
               "scenario_statement": "…\n\nWhy this threat applies: …", "risk_statement": "…", "assumptions": [],
               "route_status": "STANDALONE"},
  "threat": {"threat_id": "lib:297", "threat_category": "Tampering", "threat_category_id": 5,
             "threat_type": "Malware/Ransomware", "threat_name": "…", "threat_type_id": 1,
             "library_threat_type": "Malware/Ransomware", "library_threat_name": "…", "grounding_status": "verified",
             "threat_catalogue_id": 297, "is_threat_type_ai_generated": false, "is_threat_ai_generated": false,
             "grounding_score": 85.0, "score": 85.0, "scope_rank": 5},
  "actors": [{"actor_id": 7, "actor_name": "Organised crime group", "role": "acting", "closest_match": false,
              "below_threshold": false}],
  "controls_status": "done",
  "controls": [{"control_id": 213, "control_code": "CII-CID-213", "itot": "OT", "domain": "…", "control_name": "…",
                "control_description": "…", "map_rank": 1, "score": 70.9, "match_type": "EXACT",
                "match_reason": "…"}],
  "accepted": false, "accepted_by": null, "accepted_at": null, "rejected_by": null, "rejected_at": null,
  "validation_status": "ok", "validation_errors": [], "validation_notes": [], "scenario_source": "generated",
  "replaced_scenarios": [], "replaced_by": null, "failure": null, "regenerate_error": null,
  "created_at": "2026-10-08T09:13:02Z" }
```

### 2.4 Storage choices
| Data | Store | Why |
|---|---|---|
| Threat/actor/control library, assets, supporting systems | SQL Server (existing tables) via stored procedures | shared with the platform; must stay unchanged; DBA-reviewable SQL; least privilege |
| Sessions, scenarios, decisions | MongoDB | document-shaped (AI JSON), one read per screen, one atomic update per action |
| API clients | MongoDB | small, owned by TSG |
| Embedding vectors (cache) | MongoDB + process memory | computed once, reused by every pod |
| AI call records (prompt, answer, tokens) | MongoDB `tsg_ai_calls` (TTL 14 days) | audit and parity checks; too large for logs |
| Queues, live-event fan-out, AI concurrency slots | Redis | in-memory speed; Celery and Socket.IO both use it natively |

---

## 3. Deep dive

### 3.1 Data model (MongoDB)
**`tsg_sessions`** — the aggregate root (all session rules are single-document updates)
```json
{ "_id": "7f3c…", "tenant_id": "DESC", "entity_id": "86", "user_id": "u1", "asset_id": 103,
  "status": "queued | running | done | failed", "step": "threats | scenarios | controls", "idem_key": "c0ffee…",
  "job": { "epoch": 3, "task_id": "b1…", "lease_until": "…", "attempts": 1, "batch": ["p7","p8"],
           "error": {"code": "ai_unavailable", "message": "…"} },
  "request": { "supporting_system_ids": [321], "service_id": 5, "sector_id": null, "subsector_id": 12 },
  "context": { "asset": {}, "systems": [], "sector": "…", "sub_sector": "…", "critical_service": "…" },
  "plan": { "budget": 12, "notes": ["…"],
            "threats": [{"threat_id": "t3", "category": "Tampering", "type": "…", "name": "…", "library_id": 297,
                         "ai_generated": false, "systems": [321], "reason": "…",
                         "actors": [{"id": 1, "name": "…", "role": "acting"}]}],
            "paths": [{"path_id": "p1", "rank": 1, "category": "Tampering", "steps": ["t3","t7"], "systems": [321],
                       "scenarios": [{"scenario_id": "1b9e…", "status": "done"}], "attempts": 0}] },
  "decisions": { "1b9e…": {"decision": "accepted", "by": "u1", "at": "…"} },
  "accepted":  { "p1": "1b9e…" },
  "last_action": {"kind": "next_set", "outcome": "complete", "reason": null},
  "timings": {"threats_s": 212, "scenarios_s": 64, "controls_s": 41},
  "created_at": "…", "updated_at": "…" }
```
Indexes: unique partial `{entity_id:1, asset_id:1}` where `status` is `queued` or `running` (one active run per asset) ·
unique partial `{entity_id:1, idem_key:1}` · `{status:1, "job.lease_until":1}` (reaper) · `{entity_id:1, created_at:-1}`.

**`tsg_scenarios`** — `_id = uuid5(session_id, path_id, version)` (retries converge); scenario fields as in §2.3; `controls`,
`controls_mapped_at`, `controls_attempts`, `controls_due`; `decision` (copy of the session's, for one-query lists);
`replaces`, `superseded`. Indexes: `{session_id:1}` · `{entity_id:1, created_at:-1}` · sparse `{controls_due:1}`.

**`tsg_api_clients`** `{_id, name, key_hash, key_prefix, active, created_at, created_by, revoked_at, last_used_at}` —
unique `{key_hash}`, unique partial `{name}` where active. **`tsg_embeddings`** `{_id: "model|group|sha256(text)", vector
(binary float32), dim}`. **`tsg_ai_calls`** `{ts (TTL), session_id, task, model, prompt, response, tokens_in, tokens_out,
latency_ms, ok}`.

Invariants and the update that enforces each:
| Invariant | Enforced by |
|---|---|
| one active run per asset | partial unique index (insert fails → 409 with the active session id) |
| next set served once | `update_one({_id, "status": "done", "job.epoch": e}, {"$set": {"status": "queued", "step": "scenarios", "job.epoch": e+1, "job.batch": […]}})` — a second click matches nothing → 409 |
| accept XOR reject; one accepted version per path | one update on `decisions` + `accepted`, filtered on their current values |
| a crashed worker cannot overwrite newer work | every worker write filtered on `job.task_id` + `job.epoch` |

### 3.2 SQL access (stored procedures used in Phase 1)
`tsg_GetAssetContext(@EntityID, @AssetID, @ServiceID, @SectorID, @SubsectorID, @SystemIDs)` → asset (only if owned by
the entity), services, sector/sub-sector, entity technology text, linked supporting systems, option names ·
`tsg_GetThreatLibrary()` · `tsg_GetControlLibrary()` · `tsg_GetLibraryStamp()`. The app login has `EXECUTE` on these only.

### 3.3 Caching strategy
| Cache | Where | Refreshed | Why |
|---|---|---|---|
| Threat/actor/control library | process memory | when `tsg_GetLibraryStamp` (SHA-256 per table, exact) changes; checked every 60 s by a background thread, never on a request | every run searches it; SQL read once per change |
| Library vectors | process memory (normalised float32 matrix) | with the library; missing vectors computed once and stored in Mongo | search = one matrix multiply, no AI call |
| Query embeddings | memory LRU → Mongo `tsg_embeddings` | never expires (key includes model + text hash) | retries and regenerations cost nothing |
| API keys | process memory, 60 s TTL | expiry | one Mongo read per key per minute, not per request |
| HTTP responses | none | — | each read is already one indexed query; data changes often |
Memory per pod for vectors ≈ (75 + 200 + 1,300) × 3,072 × 4 B ≈ 19 MB.

### 3.4 Queue and event design
**Queues and routing** (`worker.py` `task_routes`):
| Task (name) | Queue | Worker | Concurrency |
|---|---|---|---|
| `tsg_find_threats(session_id, epoch)` | `tsg_threats` | `worker-threats` (threads) | 10 per pod |
| `tsg_write_scenarios(session_id, epoch)` (first batch, next set, regenerate) | `tsg_scenarios` | `worker-scenarios` (threads) | 10 per pod |
| `tsg_map_controls(session_id, epoch)` | `tsg_scenarios` | `worker-scenarios` | — |
| `tsg_reap()` (beat, 60 s) · `tsg_retry_controls()` (beat, 30 min) · `tsg_build_library_indexes()` (beat, 30 min) | `tsg_maintenance` | `worker-maintenance` | 2 |
Message = task name + ids only (JSON); all data lives in Mongo. Settings: `task_acks_late=True`,
`worker_prefetch_multiplier=1`, `task_ignore_result=True`, per-task time limit < broker visibility timeout, Redis key
prefix `tsg2:`.

**Worker pool: threads, one process per pod** (`app/worker.py`). Tasks mostly wait on AI answers, so threads fit.
One process gives one library copy, one set of connection pools shared by all threads (MongoDB, SQL Server and
Redis clients are thread-safe; SQL pool 5 + 10 overflow, Mongo up to 100) and one Prometheus registry, served on
`CII_WORKER_METRICS_PORT` (default 9100) — so the AI calls, tokens and job outcomes recorded in workers reach
Grafana. Start-up refuses any other pool (exits with the reason): prefork would copy open connections into forked
children and hide each child's metrics; gevent would stall on pyodbc and the local reranker, which block its loop.
Clients are created lazily inside the worker and closed on shutdown.

**Job record** (`job` on `tsg_sessions`): `{task, epoch, task_id, lease_until, due_at, attempts, error {code,
message}}`. Indexes `{status, job.lease_until}` and `{status, job.due_at}` serve the reaper's two scans.

**Job life-cycle (LeasedTask):** claim (conditional update `queued` or expired `running` → `running`, `task_id`,
`lease_until = now+120 s`) → heartbeat every 30 s → fenced writes → finish (`done`) or fail (`failed` + `job.error
{code, message}`) → emit event. A duplicate delivery claims nothing and exits. The reaper re-queues expired leases
(< 5 attempts) and re-sends records stuck in `queued` for > 2 min (covers a lost enqueue).

**Socket.IO events** (room `session:<id>`): `session.updated` (status body §2.3) after every stage change and every
scenario/controls batch; `error` (RFC 9457 body) on subscribe failures. Server: `AsyncServer` + `AsyncRedisManager`; workers
emit with a write-only `RedisManager`; transport WebSocket only.

### 3.5 Error handling and retries
| Situation | API answer | Worker behaviour |
|---|---|---|
| Bad input | 422 `validation_error` (field list) | — |
| Missing / wrong key or headers | 401 | — |
| Other entity's session | 403 | — |
| Unknown id | 404 | — |
| State conflict (run active, batch running, nothing left, already decided) | 409 `code` (`active_session_exists`, `generation_in_progress`, `nothing_left`, `already_decided`, …) | — |
| AI rate-limited / provider down | 503 + `Retry-After` (only where the API calls AI) | retry with back-off 15 s → 30 s → 60 s → 120 s → 240 s; fallback model in UAT; then stage `error` (`ai_unavailable`) |
| Mongo / SQL / Redis timeout | 503 + `Retry-After` | retry as above; lease keeps ownership |
| Unreadable AI answer | — | one re-ask; then a failure scenario for that path (others continue); path abandoned after 5 attempts |
| Unexpected exception | 500 `internal_error` + `request_id` (details only in logs) | stage `error` + stack trace in logs |
Body (RFC 9457): `{"type", "title", "status", "detail", "code", "request_id"}`. Timeouts on every outbound call (AI 90 s,
Mongo 5 s, SQL 30 s, Redis 5 s).

### 3.6 Enums and constant classes
No magic strings or numbers (SDD §7A). Phase 1 defines:
| File | Enums / classes |
|---|---|
| `app/constants.py` | **`Status`** (queued, running, done, failed) · **`Decision`** (pending, accepted, rejected) · `ErrorCode`, `Queue`, `TaskName`, `Event`, `Header`, `Collection`, `StoredProcedure`, `AiTask`; `Generation`, `Controls`, `Timeouts`, `Lease` (`Final` values) |
| `app/exceptions.py` | `AppError` → `Invalid`, `Unauthorized`, `Forbidden`, `NotFound`, `Conflict`, `Unavailable` (each with its `ErrorCode` and HTTP status) |
| `scenarios/constants.py` | `Step` (threats, scenarios, controls), `StrideCategory`, `ActorRole`, `RouteStatus`, `ControlMatch`, `ScenarioSource`, `ConflictReason`, `Severity`, `Finding` (code + severity + message template), `PlanNote`, `RouteNote` |
| `scenarios/exceptions.py` | `SessionNotFound`, `ScenarioNotFound`, `ActiveSessionExists`, `GenerationInProgress`, `NothingLeft`, `AlreadyDecided`, … (subclasses of the app errors, each fixing its reason and message) |
| `api_clients/constants.py` | `KeyPrefix` (`tsg_`) and key length as `Final` constants |
Schemas use the enums as field types (OpenAPI lists allowed values); MongoDB stores enum values as strings.

---

## 4. Structure (Phase 1 files)
```
cii/
├─ app/
│  ├─ main.py · config.py · constants.py · exceptions.py · dependencies.py · logging.py · metrics.py
│  ├─ database.py · ai.py · realtime.py · worker.py
│  ├─ scenarios/  router.py · schemas.py · dependencies.py · service.py · repository.py · constants.py · exceptions.py · tasks.py
│  │   └─ engine/ threats.py · paths.py · writer.py · rules.py · controls.py · prompts.py
│  ├─ library/    service.py · repository.py · search.py · tasks.py
│  ├─ api_clients/ router.py · schemas.py · service.py · repository.py · constants.py
│  └─ health/router.py
├─ sql/procedures/  tsg_GetAssetContext.sql · tsg_GetThreatLibrary.sql · tsg_GetControlLibrary.sql · tsg_GetLibraryStamp.sql
├─ tests/  scenarios/ · library/ · api_clients/ · conftest.py (real Mongo + Redis, fake AI)
├─ docs/   SDD.md · SYSTEM_DESIGN.md · RULES.md (Phase 1 subset)
├─ pyproject.toml · .env.example · dev.ps1 · README.md
```

---

## 5. Scale and reliability

### 5.1 Load estimation (UAT/prod, assumptions A1–A2)
| Quantity | Calculation | Result |
|---|---|---|
| Runs | peak | 200 / hour |
| AI calls per run | 40 first run + ~9 next sets/regenerations | ≈ 49 |
| AI calls | 200 × 49 / 60 | ≈ 163 / min |
| Concurrent AI calls | 163 × 15 s / 60 | ≈ 41 → slot cap 48 |
| AI tokens | 163 × 7.5k | ≈ 1.2 M / min (provider quota to request) |
| Threat jobs in flight | 200/60 runs/min × ~5 min | ≈ 17 → `worker-threats` 2 pods × 10 |
| Scenario jobs in flight | 200/60 × ~2 min (+ next sets) | ≈ 8 → `worker-scenarios` 2 pods × 10 |
| HTTP requests | 1,000 active users × 1 per 10 s | ≈ 100 / s (each 1 indexed read) → 2 API pods |
| Socket connections | 1,000 active users | ≈ 1,000 (≈ 50 MB across pods) |
| Mongo growth | 200/h × 8 h × 22 d × ~0.4 MB (session + scenarios) | ≤ 14 GB / month upper bound; `tsg_ai_calls` ≈ 20 GB steady with 14-day TTL |
| Redis | ids in queues, events, slots | < 1 GB |
The binding constraint is AI throughput (tokens and concurrent calls), not servers or databases.

### 5.2 Scaling
- **Horizontal:** API pods (stateless; Socket.IO fan-out via Redis), each worker pool independently (by replica count).
- **Vertical:** none needed for app pods (≈ 0.5–1 CPU, 1 GB each); MongoDB/Redis sized by the cloud provider.
- **AI:** raise provider quota and the slot cap together; batching and caching (§3.3) keep calls per run low.

### 5.3 Failover and redundancy
| Failure | Effect | Recovery |
|---|---|---|
| API pod dies | its sockets drop | other pod serves; clients reconnect and re-subscribe |
| Worker dies mid-job | job stops | message redelivered (`acks_late`) or reaper re-queues after lease expiry (≤ 2 min); fenced writes prevent duplicates |
| Beat dies | reaper/retries pause | OpenShift restarts it; nothing is lost (records stay QUEUED/expired) |
| Redis down | no new jobs, no live events | API returns 503 on actions; reads work; on return the reaper re-sends QUEUED work |
| MongoDB down | API 503; workers retry | provider failover (replica set); work resumes |
| SQL Server down | runs needing a new asset context refused (503 + Retry-After); every process keeps serving its last good library (logged, rechecked each minute); only a process's first library load fails | resumes on return |
| AI provider down / throttled | stages retry, then `error` with a clear message | fallback model (UAT); user can regenerate / restart |
Redundancy: ≥ 2 API pods, ≥ 2 pods per busy worker pool, managed HA for data stores, PodDisruptionBudgets.

### 5.4 Monitoring and alerting
Phase 1: `/metrics` (Prometheus format), JSON logs with `request_id`/`session_id`/`task_id`, Flower for tasks.
Phase 2 adds Prometheus + Loki + Alertmanager + Grafana on `http://<tsg-host>/grafana/`.
| Signal (SLI) | Alert when |
|---|---|
| API 5xx share | > 2 % for 10 min |
| API p95 latency | > 1 s for 10 min |
| Job failures | > 10 % of jobs for 15 min, or any `retries_exhausted` |
| Queue backlog (`tsg_threats`, `tsg_scenarios`) | > 50 waiting for 15 min |
| Workers alive | none for 5 min |
| Dependency up (SQL, Mongo, Redis, AI) | down for 3 min |
| AI error rate | > 10 % for 10 min |

---

## 6. Trade-off analysis
| Decision | Chosen | Alternatives | Why chosen | Cost accepted |
|---|---|---|---|---|
| Deployment shape | modular monolith | microservices | one team, shared data, fastest to build and run | one release for all modules (mitigated by module boundaries) |
| TSG data store | MongoDB | SQL Server tables | document-shaped data; one read/one update per action; no joins | two databases to operate; no ad-hoc SQL reporting |
| SQL access | stored procedures | ORM / inline SQL | DBA-reviewable, least privilege, library tables untouched | procedures deployed separately from code |
| Background work | Celery + Redis | FastAPI BackgroundTasks, Kafka, RabbitMQ | survives restarts, retries, routing, Flower; Redis already needed | Redis must be persistent/HA in UAT |
| Live updates | Socket.IO over Redis | SSE, polling | push across pods, auto-reconnect, rooms | a Socket.IO client in the front end; extra dependency |
| Queues | 3 (tsg_threats, tsg_scenarios, tsg_maintenance) | 1 queue; one per task | isolates long runs from clicks with few moving parts | coarse isolation inside `tsg_scenarios` |
| Vector search | in-memory matrix | vector database (Atlas Vector Search, Qdrant) | library is small (~1.6k rows); zero extra infrastructure | revisit beyond ~100k rows (§8) |
| AI access | litellm | each provider's SDK | one code path for Foundry and LiteLLM proxy | dependency on a fast-moving library (pin the version) |
| Route handlers | sync `def` + PyMongo | async + Motor | one client type for API and workers; no event-loop blocking bugs | thread-pool sizing for very high concurrency |
| Config | code constants + 16 env vars | everything configurable | fewer misconfigurations; values reviewed in pull requests | changing a business value needs a release |
| Errors | RFC 9457 | custom envelope | industry standard; front end parses one format | front end adapts once |
| Data migration | fresh start | migrate v1 history | 2-day timeline; owner decision | entity lists start empty |

---

## 7. Phase 1 plan (2 days)
| When | Deliverable | Done when |
|---|---|---|
| Day 1 AM | Skeleton: config, constants, exceptions, logging, metrics, database (Mongo + procedure client), 4 procedures, API-client keys, health | `pytest` green; `/ready` green on local stores |
| Day 1 PM | Library cache + vectors + hybrid search; AI gateway; sessions repository/service; worker (3 queues, LeasedTask, reaper); Socket.IO | start run → job claimed → `session.updated` received |
| Day 2 AM | ThreatFinder + AttackPathSelector + ScenarioWriter + scenario rules (ported from v1, prompts reused) | one real run on the local asset writes 6 scenarios |
| Day 2 PM | ControlMapper; accept / reject / next set / regenerate / results / lists; tests (rules, paths, conflicts, kill-worker, double click); README | all 10 endpoints + Socket.IO work end to end; tests green |
**Out of Phase 1:** remediation, `/v1/embeddings` API, intel/ATT&CK enrichment, Grafana stack, admin CLI, UAT
deployment, parity sign-off on all 397 rules (Phase 1 covers the scenario rules; full parity replay is Phase 2).

**Needed from the owner now:** permission to create the 4 procedures in the local database · Azure AI Foundry
endpoint, key and model names for chat, embeddings and rerank (dev today uses an OpenAI-compatible chat endpoint
`Kimi-K2.6` and `text-embedding-3-large`; v1's reranker was a local model, which v2 drops).

---

## 8. What to revisit as the system grows
| Trigger | Revisit |
|---|---|
| Library > ~100k rows or vectors > 1 GB per pod | move vectors to MongoDB Atlas Vector Search or Qdrant |
| One entity dominates AI capacity | per-entity queues or weighted fair scheduling |
| > ~10k concurrent sockets | dedicated Socket.IO pods behind their own route |
| Beat must never pause | leader election (e.g. RedBeat) for the scheduler |
| Remediation needs its own release cadence or team | extract `remediation/` into its own service (boundary already clean) |
| AI cost too high | smaller model for yes/no checks (after a parity test); reuse plans for unchanged assets |
| Reporting needs on TSG data | nightly export to SQL Server or a reporting store |
| Plain http route | edge TLS on the same route (no DNS needed) |
| Session documents near 16 MB | move plan trace / history to their own collection |
