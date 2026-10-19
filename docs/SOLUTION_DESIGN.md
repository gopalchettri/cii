# TSG Solution Design (v2.1, 2026-10-18)

Saved as `docs/SOLUTION_DESIGN.md` and as a shared page. §7 tracks progress.

## 1. Problem

**What a threat scenario is.** A short, specific story of how one attacker could harm one critical
asset through one weakness, and what the harm would be. It is written for a risk register.

Each scenario is built from:
- a **threat type**, a **threat** and a **threat actor** from the SQL Server library;
- the asset and the supporting systems the attack goes through (the **attack path**).

It has a title, a scenario statement and a risk statement. When external intelligence is on, it also
cites real evidence (advisories, known-exploited vulnerabilities).

*Example:* "Grid Control Centre", RTU network, Tampering, "Unsigned firmware pushed to an RTU",
Nation-state/APT. *An APT actor gains vendor remote access, pushes modified firmware, and changes
breaker commands… Risk: loss of grid switching integrity, leading to outages.* Evidence: CISA ICS
advisory [1].

**Who and why.** Critical-infrastructure entities must keep a risk register for each critical asset.
Hand-written scenarios are slow, generic, duplicated and not tied to real threat data.
- **Reviewers** start sessions and accept or reject scenarios.
- **Curators** approve AI-proposed threats.
- **Admins** run keys, indexes and intelligence.

**Goals**
- **G1 Unique.** No two scenarios of an asset tell the same threat, as the same kind of attack, on the
  same systems, or in the same words.
- **G2 Grounded.** Content comes from the curated library. The AI proposes a new threat only when none
  fits, and a curator approves it.
- **G3 Evidence on.** With intelligence on, every AI-written scenario cites at least one relevant
  evidence entry.
- **G4 Nothing invented off.** With intelligence off, no evidence or real-world incident appears.
- **G5 Human decides.** Nothing is final until a reviewer accepts it. Scenarios come in sets.
- **G6 Traceable.** Every change is audited.
- **G7 Isolated.** An entity sees only its own data.
- **G8 Reliable.** Outages never lose or duplicate work. A broken AI reply is retried; it ends a
  session only when not one threat could be checked in 5 tries (D6).

## 2. Features (for tracking)
| # | Feature | In one line |
|---|---|---|
| F1 | Start a session | asset + systems → the asset's facts are frozen; one active session per asset; a safe retry with Idempotency-Key |
| F2 | Find threats | the AI checks each library threat that has a linked attacker, per kind of attack; may propose one missing threat; picks the attacker. A broken reply is retried later; on the last try planning carries on with what it could check |
| F3 | Attack paths | threats grouped by kind of attack + systems, ranked; the first set is written now, more on "Next set"; spares replace failures |
| F4 | Write scenarios | code prepares the facts → the AI writes → code checks → the AI reviews; the AI is given each word range from .env, its upper number a hard limit (no code cut); a blocked draft is given up at once and a spare takes its place (the writer's own retry is commented out, ready to switch back on); no duplicates; unique titles |
| F5 | Evidence | on: one search per write (a regenerate searches again); the AI writes no marker, code adds one cited sentence from the entry's own facts; the nearest evidence when none meets the threshold; never blocked for missing evidence. Off: cite nothing |
| F6 | Map controls | library controls matched to each scenario by search + score; never written by the AI |
| F7 | Review | accept, reject, regenerate, next set, cancel, delete, propose a threat to the library, read results, live status |
| F8 | Hand-written scenarios | entered with a remediation request; checked against the library; no AI in the request; the person's own record (needs no evidence, never refused as a duplicate) |
| F9 | Remediation plans | for an accepted scenario: the AI writes the plan, code fixes controls and dates; versions; accept or reject |
| F10 | Library and curation | threats and controls cached from SQL Server; curators approve or reject proposed threats |
| F11 | External intelligence | six public sources imported safely; on/off switch; evidence index |
| F12 | Service mapper | a stub with canned answers, until the real service exists |
| F13 | Admin and security | API keys, admin key, entity isolation, audit log, redaction |
| F14 | Background jobs | leased jobs, retries, reaper, a global AI-call cap |
| F15 | Operations | health, readiness, metrics, logs, alerts, OpenShift deploy |

## 3. Solution: the architecture

**Six business modules**, each with the same layout in every layer (a folder only where it has files):
- **scenario** (includes control mapping)
- **remediation**
- **library** (threats, controls, curation)
- **external_intelligence**
- **service_mapper**
- **admin**

**Shared platform:** core, ai, search, realtime, worker jobs.

```
   HTTP clients                                   Celery queue
        │                                              │
        ▼                                              ▼
  api/routers/<module>.py ─ HTTP only         worker/<module>/ ─ background jobs
        │                                              │
        ▼                                              │
  services/<module>/ ─ ONE class per module            │
        │  (load → decide → save → audit → publish)    │
        ├────────────────────┬─────────────────────────┘
        ▼                    ▼
  domain/<module>/      data_access/<module>/ ─ ONE repository per collection
  business rules        │              │
                      MongoDB      SQL Server (procedures)

  models/<module>/ ─ data shapes only
  app/container.py ─ builds each long-lived object once and passes it in (dependency injection)
```

**End-to-end architecture (what runs where)**
```
 ┌─────────────────────────────── Clients ───────────────────────────────┐
 │ CII portal: X-API-Key + X-Entity-Id          Admin tools: X-Admin-Key │
 └──────────────┬───────────────────────────────────────┬────────────────┘
                │ HTTPS /v1/...                         │ SSE /v1/sessions/{id}/events
                ▼                                       ▼
 ┌──────────────────────────── API pod (FastAPI) ────────────────────────────┐
 │ api/routers: scenario · remediation · library · external_intelligence ·   │
 │              service_mapper · admin · jobs · health (/health, /ready)     │
 │   auth → entity isolation → ONE service method per route                  │
 │ services: ThreatScenarioService · RemediationPlanService · JobService ·   │
 │   ThreatLibraryService · ExternalIntelligenceService · AdminService ·     │
 │   ServiceMapperService (stub)                                             │
 │ domain (rules) · data_access (repositories) · realtime (EventHub)         │
 │ container.py builds every long-lived object once at start-up              │
 └─────┬────────────────────────┬──────────────────────┬─────────────────────┘
       │ save the record,       │ stored procedures    │ live events
       │ then send the job      │ only                 │ (subscribe)
       ▼                        ▼                      ▼
 ┌──────────────────┐   ┌──────────────────┐   ┌──────────────────────────┐
 │ MongoDB          │   │ SQL Server       │   │ Redis                    │
 │ tsg_sessions     │   │ threat library   │   │ Celery broker (3 queues) │
 │ tsg_scenarios    │   │ control library  │   │ live-event pub/sub       │
 │ tsg_remediations │   │ asset context    │   │ global AI-call slots     │
 │ tsg_audit, ...   │   │ curation queue   │   │ worker heartbeats        │
 │ (13 collections) │   └────────▲─────────┘   └────────────┬─────────────┘
 └────────▲─────────┘            │                          │ jobs
          │                      │                          ▼
          │      ┌───────────── Worker pods (Celery, thread pool) ─────────────┐   ┌──── Beat ─────────────┐
          └──────┤ tsg_threats:     tsg_find_threats      (plan job)           │◄──┤ tsg_reap         60 s │
                 │ tsg_scenarios:   tsg_write_scenarios   (write job)          │   │ tsg_retry_controls 5m │
                 │                  tsg_map_controls      (controls job)       │   │ tsg_build_library_    │
                 │                  tsg_write_plan        (remediation plan)   │   │   indexes       30 m  │
                 │ tsg_maintenance: tsg_reap, tsg_retry_controls,              │   │ tsg_refresh_external_ │
                 │                  tsg_build_library_indexes,                 │   │   intelligence 1 h    │
                 │                  tsg_refresh_external_intelligence          │   │   (only when on)      │
                 │ worker/<module> task → container → service / domain / repo  │   └───────────────────────┘
                 └──────────┬───────────────────────────────────┬──────────────┘
                            │ LiteLLM (through the proxy)       │ HTTPS downloads (intelligence on)
                            ▼                                   ▼
                 ┌──────────────────────┐      ┌──────────────────────────────────────────┐
                 │ AI                   │      │ Six public sources                       │
                 │ chat model (Kimi)    │      │ CISA KEV · FIRST EPSS · CISA ICS         │
                 │ embeddings           │      │ advisories · NIST NVD · MITRE ATT&CK     │
                 │ reranker (bge)       │      │ Enterprise · MITRE ATT&CK ICS            │
                 └──────────────────────┘      └──────────────────────────────────────────┘

 Observability: /metrics → Prometheus · JSON logs → Alloy → Loki · Grafana dashboards · Flower (tasks)
 Deploy: OpenShift (API, worker and beat pods; network policies)
```

**End-to-end flow of one session** (normal path, then what happens on failure)
```
 Reviewer           API                       Worker                         AI / SQL / evidence
 ── POST /v1/sessions ─►
                    check key, entity, intel data
                    asset facts ───────────────────────────────────────────► SQL tsg_GetAssetContext
                    save session (queued) → send tsg_find_threats
 ◄─ 202 session_id
                                              PLAN JOB (lease, attempt n of 5)
                                              library threats with a linked attacker
                                              gate: which fit, per kind of attack ─────► chat
                                              gap fill: one missing threat ────────────► chat
                                              attacker, attack paths, rank, first set
                                              save plan → send tsg_write_scenarios
                                              WRITE JOB (up to 4 paths per batch)
                                              switch read (unsure → wait and retry)
                                              evidence search, if on ──────────────────► evidence index
                                              facts → writer → code checks → reviewer ─► chat
                                              duplicate check (database) → save scenario
                                              send tsg_map_controls; next batch or set done
                                              CONTROLS JOB: search + score ────────────► embeddings, reranker
 ◄─ GET status / live events (SSE) ◄──────── published after every save
 ── accept / reject / regenerate / next set / cancel / delete ─►
                    rule check → save → audit → counts → publish
 ── POST remediation request (accepted scenario) ─►
                    save request → send tsg_write_plan
                                              PLAN WRITER: AI writes the plan ─────────► chat
                                              code fixes controls and dates; version saved

 On failure:
 · Every job: record saved first, then sent; a lease and epoch fence each write.
 · Outage → retry after 15/30/60/120 s, up to 5 tries; the reaper re-sends lost jobs, ends dead ones.
 · Broken AI reply → retry; on the last try carry on with what was checked; nothing checked → "AI unavailable".
 · Blocked draft → given up at once; a spare path takes its place (from the next set if none is left).
 · A path the asset already holds → never planned; one held since planning → given up before any AI call.
 · SQL write → operation record first; a lost answer is replayed, never guessed.
 · Cancel/delete → fenced writes stop running jobs; the controls sweep settles what is left.
```

| Module | Service class | Repositories |
|---|---|---|
| scenario | ThreatScenarioService | ThreatScenarioSessionRepository, ThreatScenarioRepository, AssetRepository |
| remediation | RemediationPlanService | RemediationRepository |
| library | ThreatLibraryService | ThreatRepository, ControlRepository, SqlOperationRepository |
| external_intelligence | ExternalIntelligenceService | IntelFeedRepository, IntelRecordRepository, IntelSnapshotRepository |
| service_mapper | ServiceMapperService (stub) | none yet |
| admin | AdminService | ApiClientRepository, AuditRepository, AdminJobRepository, EmbeddingRepository |
| platform (jobs) | JobService | JobRepository, WorkControlRepository (cancel, resume, delete and the controls sweep across collections) |

**Project structure: before → after** (exact file names are fixed in the step-0 contract file)
```
app/
  main.py
  container.py  NEW: builds every long-lived object once and passes it in
  api/routers/
    scenario.py               ← scenarios.py + review.py + events.py
    remediation.py, external_intelligence.py, service_mapper.py, jobs.py, health.py (unchanged)
    library.py                ← library_curation.py
    admin.py                  ← api_clients.py + embeddings.py
  services/
    scenario/threat_scenario_service.py          ← runs.py + review.py + results.py (5 classes → 1)
    remediation/remediation_plan_service.py      ← 8 files → 1
    library/threat_library_service.py            ← library_curation.py
    external_intelligence/external_intelligence_service.py   ← 9 files → 1 (the 12 source readers move to the worker)
    service_mapper/service_mapper_service.py     ← 3 files → 1
    admin/admin_service.py                       ← api_clients.py + embeddings_builds.py + audit.py
    jobs/job_service.py                          ← jobs.py
  domain/<module>/            rules, same files grouped by module; audit helpers → domain/shared
  data_access/
    scenario/   threat_scenario_session_repository.py, threat_scenario_repository.py, asset_repository.py   ← repository.py (928 lines)
    library/    threat_repository.py, control_repository.py, sql_operation_repository.py                  ← repository.py
    remediation/remediation_repository.py
    external_intelligence/ intel_feed_, intel_record_, intel_snapshot_repository.py, intelligence_switch.py
    admin/      api_client_, audit_, admin_job_, ai_call_, embedding_, query_vector_repository.py
    jobs/       job_repository.py, work_control_repository.py
  models/<module>/            the same shapes, moved out of the 15 flat files into module folders
  worker/
    scenario/                 ← tasks/scenarios.py, writing.py, controls.py + path_writing.py, plan_progress.py
    remediation/              ← tasks/remediation.py + plan_inputs.py
    external_intelligence/    (today's files + the 12 source readers)
    admin/                    ← tasks/library_indexes.py
    celery_app.py, jobs.py, reaper.py, lifecycle.py, heartbeat.py   (platform, stay)
  core/, ai/, search/, realtime/   (platform, stay; their hidden get_x() builders move to container.py)
```

**Rules**
1. **Layers point one way:** api → services → domain / data_access; the worker → domain / data_access.
2. **One service class per module.** Its methods are named by use case, e.g. create_threat_scenario_session,
   get_threat_scenario, accept_threat_scenarios, regenerate_threat_scenarios.
3. **One owning repository per collection or SQL area.** File name = class name. Two named classes
   work across collections: JobRepository and WorkControlRepository. Repositories depend one way: the
   session repository uses the scenario repository, never the reverse.
4. **Models hold data shapes:** fields, validators and record mappers. No database, no settings, no
   business decisions; those live in domain.
5. **Dependency injection.** Every class gets what it needs through its constructor. Only
   `app/container.py` builds long-lived objects; a per-job helper is built by its caller from what
   the container gave it. Routers use FastAPI `Depends`; worker tasks ask the container when they run.
6. **Nothing changes outside:** API, stored data, SQL procedures, Celery task names, environment keys,
   audit rows. The only exceptions are the removed `coverage` field and the four removed environment keys.

**What the restructure removes**
| Today | After |
|---|---|
| 36 hidden `get_*()` singletons in 30 files | 1 file, `app/container.py` |
| services/scenario: 3 files, 5 classes | 1 file, 1 class |
| services/remediation: 7 files | 1 file, 1 class |
| services/external_intelligence: 19 files | 1 service class; the six source readers move unchanged to the worker |
| data_access/scenario/repository.py: 5 repositories in 928 lines | 1 repository per collection, 1 file each |
| models: 29 files in one folder | the same shapes, in module folders |
| worker_runtime install hack; the IntelAccess wrapper (its "wait if unsure" rule moves to the switch); "not assessed" | deleted |

**What it does not add:** no interfaces, no DI library, no new layer, no new feature, no behaviour or
API change.

**Must-haves, enforced by code, not by the AI**
1. **Evidence.** Intelligence counts as on when EXTERNAL_INTELLIGENCE_ENABLED=true **and** the runtime
   switch is on, read once when a write batch starts. If the switch cannot be read, the batch waits and
   retries; it never guesses.
   - **On (owner, 2026-10-19):** every AI-written scenario cites the best evidence from an approved
     source.
     - The AI writes no marker. It writes a separate evidence passage (EVIDENCE_STATEMENT_WORD_LIMIT,
       30-80 words) from the cited entry's facts only; code appends it to the statement and cites it [1]
       once the reviewer confirms it.
     - A passage that is missing, too long, carries a marker, link or code, or is not confirmed is
       replaced by a sentence code builds from the same entry's facts (a warning, never a blocker), e.g.
       'In real-world attacks, APT41 and FIN8 have used the technique "Valid Accounts" [1].'
     - **Nearest evidence:** when nothing meets the relevance threshold, the nearest evidence is cited.
       It is said as "related" and stored with evidence_mode "nearest".
     - **No record at all:** the scenario is still written, without a citation, and stored with
       evidence_mode "inferred".
     - **Outages:** a search that could not be made waits and retries.
     - Start, next set and regenerate all refuse when intelligence is on but has no data.
   - **Off:** no evidence; any citation or advisory number blocks the draft, including one copied from
     the asset's own facts.
   - Hand-written scenarios, and versions written before a switch change, stay as stored.
2. **No duplicate threat scenario.** An AI-written scenario is refused (near_duplicate) when it repeats
   another scenario of the session, or a pending or accepted scenario of the same asset in another
   session (hand-written ones included). "Repeats" means either:
   - the same threat (same library id **or** same name), the same kind of attack and the same systems;
   - or the same statement.

   The check reads the database right before each save. Saves run one at a time per batch, and there
   is one active session per asset.

   The same rule runs twice earlier, with no AI call: the planner drops every path the asset already
   holds before it picks the set, and the write job gives up a path that repeats a scenario held now
   before its evidence search. A given-up path's spare may come from the next set.

**Features removed in this round (owner, 2026-10-18)**
| Removed | What remains |
|---|---|
| Attacker balancing and the "closest" actor pool | Settled when planning. A threat whose type links no attacker is not checked, and neither is an AI-proposed one. The attacker is the AI's pick among the linked actors, else the top-ranked linked actor. A hand-written scenario takes its threat's linked actors, else its type's, else the top-ranked actor of the whole library |
| Coverage report | Results show the session, its progress and its scenarios. The `coverage` field, the given-up explanations and their second reader go. Two messages are reworded |
| The one rewrite, and the writer's own retry | A draft with a problem is not rewritten, and is given up at once (owner, 2026-10-19). A spare path takes its place. The retry branch in PathSaver.save is commented out, ready to switch back on (up to MAX_PATH_ATTEMPTS). A draft that code already blocked skips the AI reviewer |
| Evidence re-search, and the same evidence for every version | One evidence search per write, kept in memory only; evidence stored on old plans is ignored. EVIDENCE_SEARCH_RETRIES is removed |
| AI answer reuse on retry | A retried job asks the AI again (R3). The AI call log and its index stay |
| Step-tracing tools | `@traced`, record_detail, core/tracing.py, the console's "How it runs" panel, scripts/replay_run_steps.py. DEBUG_STEP_OUTPUT, DEBUG_STEP_DETAIL and DEBUG_STEP_TOP are removed |
| "Not assessed" categories | A broken AI reply is retried later. On the last try, planning carries on with what it could check (D4, D6). The plan keeps writing an empty `not_assessed` list for one release, so old pods don't break during a rolling update |

The four removed environment keys are deleted by name from `.env.example`, `.env` and `.env.uat`, and
their values are never printed.

**Kept on purpose:** AI-proposed threats (gap fill), spare paths, the AI reviewer, the controls job,
hand-written scenarios, live events, the runtime switch, all six sources, source approve and revoke.

## 4. End-to-end review (2026-10-18)
32 agents checked this design against the code:
- 8 agents each checked one area.
- 8 agents each traced one flow from end to end:
  1. the normal path;
  2. next set and regenerate;
  3. the intelligence switch;
  4. races;
  5. AI failures;
  6. crashes and outages;
  7. cancel and delete;
  8. library and admin.
- A skeptic re-checked every finding.

The review raised 154 findings. The skeptics refuted 24 and confirmed 130. Most confirmed findings were
the same problem found by several agents, and they come down to the 16 fixes below. All of them are
made in this round, at the cause:

| # | Fix | Why |
|---|---|---|
| X1 | The "if unsure whether intelligence is on, wait" rule moves onto IntelligenceSwitch. A write batch asks it in strict mode | a MongoDB blip could otherwise serve scenarios without evidence |
| X2 | Only `near_duplicate` is final at once (FINAL_FINDINGS) | without the rewrite, a mismatch or a missing citation would give up a path after one draft |
| X3 | The attacker is settled while planning (see the table above) | otherwise paths are planned that can never be written |
| X4 | Evidence is one search per write, in memory. Revoked sources are filtered before ranking. An empty index means "no evidence found", not an outage. There is no catch-all around the search | the cut is finished; no wrong give-ups; no false failure after 4 minutes |
| X5 | The duplicate check reads the database right before each save and matches threats by id or by name | two duplicates slipped through: a scenario saved meanwhile, and an AI threat later approved into the library |
| X6 | **D11 order:** the plan job tells the planner "last try". A broken gate or gap-fill reply is retried before gap fill runs; provider refusals and empty replies count as broken. On the last try, the batch is skipped with a warning log, using the existing metric. A cut-off reply is skipped, as today. If nothing at all could be checked, D6 applies | the rule had no clear trigger, order or outcome |
| X7 | The same Idempotency-Key sent again while the first start is still running returns the same session | today it can answer 409 |
| X8 | A remediation job retries an "operation in progress" instead of failing. A lost card lease hands the job back for the normal retry. The control-library check runs before the first write. A regenerate on a session being deleted answers 409 and writes nothing | plans could fail or stall for no reason |
| X9 | **Cancel and delete:** the delete mark is read through the session repository. Settle, resume and the controls sweep live in WorkControlRepository, session first and then cards. The sweep never stops a live lease. A card whose mapping keeps crashing is given up after its attempts. Three lease-signal gaps are closed | a resume or a sweep could undo a cancel; a crash could loop forever |
| X10 | Coverage cut: one run reader is left. build_board moves to domain/scenario so JobService and the scenario service share it | leftover code and dangling messages |
| X11 | The library cache reads the stamp, then the threats, then the controls, and swaps both at once. Controls are read only from that cache | the two separate repositories you chose stay safe; no half-loaded library |
| X12 | **Start-up keeps today's order.** Worker: pool check → logging → metrics → container set-up. Any failure stops the worker. Beat sets up logging only. Proxy set-up is one step that every AI and HTTP client runs first. Readiness stays plain functions, and `/health` and `/ready` take no injected dependency, so they never wait for a request thread | a worker that failed to start could still run jobs; less wiring |
| X13 | The container has providers only for real owners. A long-lived job object builds the per-job helpers. Tests override service providers or pass fakes, never leaf objects. There is no reset fixture, and only the patches whose target moved change | fewer edits; no hidden second copies |
| X14 | The code-rules test is updated first. Service and repository classes may be wide; container.py is allowed; `@singleton` is allowed only in the container and core | the new layout would fail today's test |
| X15 | **Library and admin:** an import started by turning intelligence on, or by approving a source, is no longer refused by the worker's 60-second switch cache. Deleting a session also deletes its SQL operation records. Each use case reads one copy of the library, and reloads take a lock. Admin-job status reads check the job kind | a first import could fail; a reused key could replay a deleted session's proposal; an older library could overwrite a newer one |
| X16 | **Build order:** cuts and fixes first, on today's layout. Then pin the API, the stored enum values, Redis keys, task names, indexes and script imports. Then move and inject. Four OpenAPI names are pinned so the moves don't rename them | snapshots taken first would fight the cuts |

**Not taken:** merging ThreatRepository and ControlRepository. You chose to keep them separate, and X11
keeps the load order safe. Findings the skeptics refuted are dropped.

## 5. Decisions
| # | Decision |
|---|---|
| D1 | Keep the current stack: sync MongoDB, Celery threads, SQL Server procedures |
| D2 | Modules with the same layout in every layer; one service class per module; one owning repository per collection |
| D3 | Dependency injection through one container, with no extra library |
| D4 | "Not assessed" categories are removed; a broken AI reply is retried later |
| D5 | Plan versions: REGENERATIONS_MAX_VERSION_COUNT = 10 (1–40) |
| D6 | Not one threat checked after 5 tries: the session fails as "AI unavailable" ("The AI could not answer. Start a new session later."). If at least one was checked, it carries on (owner, 2026-10-18) |
| R1, R2 | Accepted risks: API keys are not tied to an entity; the intelligence admin routes have no login |
| R3 | Accepted cost: a broken-reply retry asks the AI again for every planning batch (rare; it shows in tsg_ai_calls_total) |
| D7 | Code writes the one evidence citation; the AI writes no marker (owner, 2026-10-19, after the end-to-end test showed 9 of 12 drafts citing evidence wrongly) |
| D8 | Nearest evidence when none meets the threshold, said as "related"; a scenario is never blocked for missing evidence (owner, 2026-10-19) |
| D9 | mypy runs inside the test suite (tests/test_types.py, warn_unused_ignores), so a type error fails the tests like any other (owner, 2026-10-19) |
| D10 | Never plan or write a path the asset already holds; a spare may come from the next set (session 72a02461 planned 12, wrote 1 and gave up 5: 4 repeats found only after the AI wrote them, 1 with no spare left) |
| D11 | Word limits (owner, 2026-10-19): THREAT_SCENARIO_WORD_LIMIT 150-200, RISK_STATEMENT_WORD_LIMIT 100-150, EVIDENCE_STATEMENT_WORD_LIMIT 30-80, each a separate limit given to the AI, the upper number a hard limit, the lower a target; code cuts nothing. Revises D7: the AI writes the evidence passage from the cited entry, the reviewer confirms it, code cites it; code's own sentence is the fallback. scripts/scorecard.py reports any text over its maximum |

## 6. Not in this round (backlog, one at a time after the re-architecture)
1. Scenario regenerate has no version cap: AI cost is unbounded.
2. A crashed admin job can block new index builds for up to an hour.
3. Monitoring pages (Grafana, Prometheus, Flower) have no login.
4. An approved threat without a category disappears from the app.
5. An intelligence import shows "done" even when every source failed.

## 7. Build plan and progress
| Step | What | Status |
|---|---|---|
| 0 | Back up; save this document; update the code-rules test (X14) | done: backup tag, this document, shared page; code-rules test at step 3 |
| 1 | Cuts and review fixes on today's layout; parallel agents, one owner per file; tests green | done: 14 developers, 14 commits, 1,793 tests pass |
| 2 | Pin the API, stored enum values, Redis keys, task names, indexes and script imports | done: tests/test_outside_contract.py + tests/contract/ |
| 3 | Parallel agents, one per module + one for the container: move files, one service class, one repository per collection, constructor injection | done: 8 agents; 7 service classes, 1 per module; 0 hidden singletons outside app/container.py |
| 4 | Join the pieces; full test suite; fix failures | done: 1,795 tests pass; pins unchanged; ruff clean |
| 5 | Count files and lines before and after; commit locally | done: app/ 212 → 223 .py files (one file per repository and module folders), 22,906 → 22,403 lines; 36 hidden singletons → 0 outside app/container.py; services/ 43 files → 7 service classes |
| 6 | Last, after everything else: update the two console pages, app/ux/tsg_console.html and app/ux/sse_test.html (owner, 2026-10-19) | done: removed features gone from both pages, Word export fixed, every call checked against the pinned API |

**Final production check (2026-10-19).** Five reviewers covered the must-haves, start-up and DI, recovery,
security and leftovers, and a skeptic re-checked each finding. All 16 confirmed findings are fixed:
- evidence claims and markers are checked, and a real bug in the evidence search is no longer retried as
  an outage;
- the controls sweep no longer undoes a resume, and a last-try failure still maps saved scenarios;
- the switch retries after 5 s;
- a live stream ends within 30 s of its key being revoked;
- dead code and duplicates are removed.

1,806 tests pass, the outside pins are unchanged, and ruff is clean.

The agents also get build notes that are kept out of this document:
- the confirmed findings, with file:line and the exact fix (review runs wf_9fb2d4cf-f5f and
  wf_ea77d59e-a52);
- the constructor lists;
- the file owners.

They go into the step-0 contract file.

**Verification**
- The full test suite passes. The test count is reported before and after (1,787 today).
- The step-2 pins prove that the API, stored values, keys, task names and indexes are unchanged, except
  for `coverage`.
- One new test for each logic fix:
  - an unreadable switch makes the write wait;
  - a mismatched draft is retried and a duplicate is given up;
  - a threat with no attacker is not planned;
  - a duplicate is matched by name;
  - nothing checked in 5 tries fails as "AI unavailable";
  - two parallel starts with the same Idempotency-Key get the same session;
  - an empty index gives evidence_not_found;
  - an "operation in progress" is retried;
  - resume and the sweep run in the right order.
- The code-rules test checks the layers, one service class per module, and `@singleton` only in the
  container and core.

**Estimate:** about 3 hours. Step 1 adds the cuts and the fixes.
