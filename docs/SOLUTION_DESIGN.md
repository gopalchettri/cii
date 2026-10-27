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
| F3 | Attack paths | one asset-level path per threat per kind of attack it was accepted for, entering through that kind's own systems (never one per system); each threat's strongest kind first, then by impact; the first set is written now, more on "Next set"; spares replace failures; every candidate left out is traced (GET /v1/sessions/{id}/plan-trace) |
| F4 | Write scenarios | code prepares the facts → the AI writes → code checks → the AI reviews; the AI is given each word range from .env, its upper number a hard limit (no code cut); a blocked draft is given up at once and a spare takes its place (the writer's own retry is commented out, ready to switch back on); no duplicates; unique titles |
| F5 | Evidence | on: one search per write (a regenerate searches again); the AI writes no marker; it writes an evidence passage from the cited entry, which code cites once the reviewer confirms it, else code cites its own sentence from the entry's facts (D11); the nearest evidence when none meets the threshold; never blocked for missing evidence. Off: cite nothing |
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
 │ tsg_sessions     │   │ threat library   │   │ Celery broker (6 queues) │
 │ tsg_scenarios    │   │ control library  │   │ live-event pub/sub       │
 │ tsg_remediations │   │ asset context    │   │ AI slots, request rate   │
 │ tsg_audit, ...   │   │ curation queue   │   │ worker heartbeats        │
 │ (13 collections) │   └────────▲─────────┘   └────────────┬─────────────┘
 └────────▲─────────┘            │                          │ jobs
          │                      │                          ▼
          │      ┌───────────── Worker pods (Celery, thread pool) ─────────────┐   ┌──── Beat ─────────────┐
          └──────┤ tsg_threats:       tsg_find_threats      (plan job)         │◄──┤ tsg_reap         60 s │
                 │ tsg_scenarios:     tsg_write_scenarios   (write job)        │   │ tsg_retry_controls 5m │
                 │ tsg_controls:      tsg_map_controls      (controls job)     │   │ tsg_build_library_    │
                 │ tsg_remediation:   tsg_write_plan        (remediation plan) │   │   indexes       30 m  │
                 │ tsg_servicemapper: tsg_map_services      (service mapper)   │   │ tsg_refresh_external_ │
                 │ tsg_maintenance:   tsg_reap, tsg_retry_controls,            │   │   intelligence 1 h    │
                 │                    tsg_build_library_indexes,               │   │   (only when on)      │
                 │                    tsg_refresh_external_intelligence        │   │                       │
                 │ worker/<module> task → container → service / domain / repo  │   └───────────────────────┘
                 └──────────┬───────────────────────────────────┬──────────────┘
                            │ LiteLLM (directly: the gateway is on NO_PROXY, D23)       │ HTTPS downloads (intelligence on)
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
                                              WRITE JOB (up to 6 paths per batch)
                                              switch read (unsure → wait and retry)
                                              evidence search, if on ──────────────────► evidence index
                                              facts → writer → code checks → reviewer ─► chat
                                              duplicate check (database) → save scenario
                                              send tsg_map_controls as each is saved; next batch or set done
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
 · A path repeating another path of the same session → given up before any AI call (other sessions never block: D15).
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
    remediation/              tasks.py + remediation_plan_job.py (the plan job builds the input; D18)
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
   - the same threat (same library id **or** same name) as the same kind of attack, whatever systems it
     involves or gets in through: the systems are its group and its ways in, the scenario is the asset's
     (owner, 2026-10-19; D14);
   - or the same statement.

   The check reads the database right before each save. Saves run one at a time per batch, and there
   is one active session per asset.

   The same rule runs earlier, with no AI call: the write job gives up a path that repeats one of the
   session's own scenarios before its evidence search. A given-up path's spare may come from the next set.
   The asset's other sessions never take a path away (D15).

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
| D5 | Plan versions: REGENERATIONS_MAX_VERSION_COUNT = 10 (1–40); a latest plan version that failed for an outage is written again in place (no version used, D32) |
| D6 | Not one threat checked after 5 tries: the session fails as "AI unavailable" ("The AI could not answer. Start a new session later."). If at least one was checked, it carries on (owner, 2026-10-18) |
| R1, R2 | Accepted risks: API keys are not tied to an entity; the intelligence admin routes have no login |
| R3 | Accepted cost: a broken-reply retry asks the AI again for every planning batch (rare; it shows in tsg_ai_calls_total) |
| D7 | Code writes the one evidence citation; the AI writes no marker (owner, 2026-10-19, after the end-to-end test showed 9 of 12 drafts citing evidence wrongly) |
| D8 | Nearest evidence when none meets the threshold, said as "related"; a scenario is never blocked for missing evidence (owner, 2026-10-19) |
| D9 | mypy runs inside the test suite (tests/test_types.py, warn_unused_ignores), so a type error fails the tests like any other (owner, 2026-10-19) |
| D10 | Never plan or write a path the asset already holds; a spare may come from the next set (session 72a02461 planned 12, wrote 1 and gave up 5: 4 repeats found only after the AI wrote them, 1 with no spare left) |
| D11 | Word limits (owner, 2026-10-19): THREAT_SCENARIO_WORD_LIMIT 150-200, RISK_STATEMENT_WORD_LIMIT 100-150, EVIDENCE_STATEMENT_WORD_LIMIT 30-80, each a separate limit given to the AI, the upper number a hard limit, the lower a target; code cuts nothing. Revises D7: the AI writes the evidence passage from the cited entry, the reviewer confirms it, code cites it; code's own sentence is the fallback. scripts/scorecard.py reports any text over its maximum |
| D12 | Asset-level scenarios (owner, 2026-10-19): one per threat per kind of attack, its systems the entry points; duplicates are the same threat + kind, whatever systems. Replaces the 2026-10-13 grouping (one path per kind × exact system set), which capped asset 1166 at 12 paths from 34-42 accepted threats (60-95% only "also applies") and lost whole groups to the held drop on re-runs (12 → 7, 2, 8, 3). Each kind keeps its own systems, impact and confidence; a "none fits" attacker pick never vetoes one another kind named; the landscape is cut fairly (every system keeps its line, the ASSET line lists the systems by name and asset type); the plan's trace is saved with it |
| D13 | run.ps1 takes .env over the shell: every setting .env owns (each key it names, set, blank or commented out, and every GF_ key) that the shell also sets is unset while run.ps1 runs (start, stop, status) and put back after, so every check and program it starts reads .env; a warning names, never shows, the ones whose value differs. A setting in the environment beats .env, and VS Code's python.terminal.useEnvFile copies .env into a terminal once, when it opens: session 13bd93f2 wrote evidence with EXTERNAL_INTELLIGENCE_ENABLED=false in .env (2026-10-19). Other commands typed into such a terminal (scorecard, monitoring.py, the debug tools) still see that copy; the setting off removes it. A deployment is unchanged: its environment is its config |
| D14 | Turns and groups (owner, 2026-10-19): the gate names, per threat and kind, every system it involves (one, several or all, judged with the asset and all its systems together) and the ways in among them; the asset type limits the way in only, so a group may mix IT and OT (asset + SYS1 + SYS2, or all four), and a threat with no way in its type fits is refused. One scenario per threat per kind on its whole group (D12). The ranked paths are dealt in turns over the systems (SYS1, SYS2 ... the asset itself, then SYS1 again), each turn the best path that can get in through that system, passing over one a system still to play that round has no other way to take; a system with nothing left is skipped. A run's results list follows the turns (the path's rank, then the save time), so a set written at once still reads in turn order. Code assigns that system as the card's entry point and the writer is offered only it. Revises the 2026-10-12/13 type fit (every system of the threat's type). Planner prompt planner-5 |
| D15 | Other sessions of the asset never block a scenario (owner, 2026-10-20): every duplicate check (the plan, the write job before the AI, the near-copy check before a save) reads only the session's own finished scenarios. Session 99447a6e planned 84 paths and kept 2: 82 were held by 20 earlier test sessions (74 pending, 8 accepted). Revises D10 and G268's cross-session part; two sessions may now hold, and both accept, the same threat. `counts.already_held` stays in the API, always 0 |
| D16 | The UI is told why a stage waits (owner, 2026-10-20): session 57d4f77a's AI gateway answered HTTP 500 for 6 minutes while the status said only "in progress". Each give-back after an outage stores `job.retry` (reason, message, attempt, max_attempts, retry_at) in the same fenced write; `progress.retrying` shows it on the run (with its stage) and on the plan status while the next try waits; the claim of that try clears it, so a running retry shows none (owner, 2026-10-25). AI outages have four reasons, each with its own message (`AiOutage`, `AI_OUTAGE_MESSAGES`): ai_down (500, 502), ai_unreachable (no connection), ai_busy (429, 503, no AI slot or request turn), ai_timed_out (tested first: litellm's Timeout is a lost connection). With intelligence on, an AI outage in the evidence search (embedding or rerank) is carried on the search's audit (`outage`, with its own words in `outage_message`), so a held-back path raises that outage too, never a reasonless evidence one. The last failure keeps the reason in `job.error` and the board's `progress.error_reason`; the next try's claim, hand-over, end, fail and cancel clear the notice. Same retries and delays as before |
| D17 | Every place an AI outage reaches the UI says which (owner, 2026-10-20, "resolve everything" after a sweep of D16): a last-try failure card and a regenerate's `regenerate_error` carry `reason` and the outage's own message; a card's control mapping keeps the outage on `controls.error` and shows it as `controls_error` while queued or failed; the evidence rerank gate's wait is `ai_busy`; among a batch's outages the one naming the AI is raised first; the service-mapping status, view and stream show `retrying` and `error.reason`; the jobs list shows `retrying`; a first evidence-index build the AI stopped leaves writes waiting on that outage, and the refresh job reports `result.index_error`; while no first index has been built, an AI or store outage retries the build after 30 s every time, and any other failure, and every failure once an index serves, doubles the pause from 30 s up to 900 s; a reaper requeue drops the old notice; litellm's plain `APIError` with a 5xx, 408 or no status is an outage (524, 598, 599, 504 timed out; 529, 503 busy). Not done: starting a run while intelligence holds no data still answers 409 `intel_no_data` when the first index build failed on the AI (needs a build-failure document id in `intelligence.py`, the owner's) |
| D18 | Remediation rebuilt lean, and control gaps decided in code (owner, 2026-10-21). Layout as scenario's: domain `rules.py`, `manual.py`, `plan.py`, `schedule.py`, its prompt in `app/prompts.toml` `[remediation.plan]` (D37); models `requests.py`, `plan.py`; the plan job builds the input (the request stores `snapshot: null`). Each scenario control is `implemented` (in the register and `existing_controls_all_subsystems` Yes), `partially_implemented` (No or empty) or `missing`; a register control matches by id, code or punctuation-blind name, and a "CODE · Name" label by its code. The AI (prompt `remediation-2`) writes only missing (implement) and partial (improve) controls; its first answer is re-asked once for a left-out gap or a listed implemented control, else the plan is kept with `GAP_NOT_ADDRESSED`; a usable first answer is kept when the re-ask breaks or finds the AI busy or down. Code removes implemented controls from the recommendations and from every `implements_controls`, sets `control_coverage` and stores `control_assessment`. A plan job waiting for another job's control mapping is given back without using an attempt. Amended the same day after a live check (owner): a "covered" plan only verifies, and its interim action is re-asked; `action_plan` restates no schedule (order, parallel work, days, dates, critical path, window, deadline) and claims nothing about the library beyond the mapped controls: the AI no longer sees the window, a first answer restating the schedule is re-asked, and a claim the re-ask keeps is dropped with its sentence (code computes the schedule and warns past the window); a first answer describing a partial control as new, or a missing one as extended, is re-asked; code titles the plan "<domains> Remediation" (covered: "<domains> Verification") from the recommended (verified) controls' library domains, keeping the AI's name only when none has a domain; plan texts say "1 day". The console shows `control_assessment`. Dropped: register advisories, library edge cases, plan advisories. **Release step:** roll every worker of both projects before any API pod (an old worker fails a version stored with `snapshot: null`); `deploy/deploy-uat.ps1` rolls `api` before ai-remediation's `worker-scenarios`. 29 → 18 files, 48 → 38 classes, 169 → 120 functions |
| D19 | Remediation against the corrected requirements (owner, 2026-10-21; revises D18). **Request** (revised by D34: the flags and the per-control lists are replaced by two lists sent once per request): two required 0/1 flags. `all_supporting_systems_applicable`: the risk is on every system of the run (0: only the scenario's own systems). `existing_controls_all_supporting_system_applicable`: the existing controls are on every system (0: each existing control lists its `supporting_system_ids`, each a system of the run, else 422 naming the field). `existing_controls_all_subsystems` stays optional and unused (a register stored before D19, without the new flag, still falls back to its Yes/No on regenerate). The planned-controls flag is never sent, so it is not accepted (like any unknown field, a 422). Existing controls still match as in D18: by id, code (any case) or punctuation-blind name, and a "CODE · Name" label by its code; IT/OT twins share coverage. **Status, by code, over the affected systems:** `implemented` (an existing control is on all of them), `partially_implemented` (on some), `not_implemented` (on none, or not in the register; was `missing`, which an older plan reads as `not_implemented`), `unverified` (flagged by the AI). Each assessed control lists `protected_systems` and `required_systems`; each recommended control its `required_systems`. **One search, one AI call (prompt `remediation-3`):** code searches the library once more, with the mapping's search and reranker, for 5 alternatives not already identified (`Remediation.ALTERNATIVES`). The AI checks every identified control for relevance only, never by its status: `retained`, `replaced` (by an offered alternative; code stores `replaced_by` and `replaces`) or `flagged_for_review` (unverified, never recommended). A check left out, or a replacement outside the alternatives, is re-asked once, then the control is flagged. A retained implemented control's reason says how it already reduces the risk. Each action lists its `supporting_systems`: the affected systems the AI names (others are warned), else those its controls still need, else every affected system. `unresolved_gaps` (code): each flagged control (`flagged_control`), one `no_validated_control` when no identified control or replacement passed the check, and the AI's `uncovered_risks` (`uncovered_risk`); the systems a control still needs are on its `required_systems`. **Also:** scenario mapping keeps 3 to 5 controls (MIN_CONTROLS, MAX_CONTROLS), and the 3 closest when none meets the cutoff (NEAREST_CONTROLS); the AI sees the window's `total_days` when the request gives one, else it estimates (code still dates the plan and warns past the window); `LibraryRef` removed; UAT rolls ai-remediation's workers, then the API. **Summary measured:** the D18 prompt left `action_plan` out of 19 of 77 first answers, this one 0 of 24, so the field keeps its name; a summary still left out is re-asked once, then fails `generation_failed`. **Breaking for the UI:** the status rename; the console ships with it. **Open:** "every supporting system" means the run's systems, and a hand-written plan's run holds only the systems its request names, so for it both values of the risk flag give the same scope |
| D20 | "All supporting systems" means every system linked to the asset (owner, 2026-10-21; closes D19's open item; the flags it reads are replaced by D34's lists, and the asset's systems it freezes still check them). `all_supporting_systems_applicable = 1` puts the risk on every supporting system linked to the asset in SQL, for generated and hand-written plans alike; 0 keeps the scenario's own systems (the run's when it names none, never the asset's others). With `existing_controls_all_supporting_system_applicable = 1` an existing control is on every one of them; with 0 each of its `supporting_system_ids` must be one of the asset's systems. **SQL:** `tsg_GetAssetContext` part 4 returns every system linked to the asset (not deleted, the entity owning the asset), sent or not; `@SystemIDs` stays, not read; a multi-select value that is not a JSON list reads as no answer (`ISJSON`), so one bad value on a system nobody sent never stops a run. Still five result sets, the same columns. **Run start:** `context.systems` is unchanged (the sent systems, SYS1..n, their facts); the new `context.asset_systems` holds `{id, name}` of every linked system, sent first in request order, then by id, each once, a blank name read as "Supporting system {id}", and a name an earlier system already has given its id ("Historian (1600)"), so a name the AI gives back finds one system. Nothing else of an unsent system is kept, sent to the AI or able to refuse a start; the AI sees the extra systems by name only, in `affected_systems` (prompt `remediation-3` unchanged). The list is frozen at run start, like every asset fact: a system linked later needs a new run, and a run stored before D20 knows only its own systems (`FrozenContext.linked_systems`, the one rule both plan kinds use). **422:** `SYSTEM_NOT_OF_ASSET` names the asset's systems; a hand-written plan is now checked before its run and scenario are saved (before D20 the 422 came after them, and a retry replayed into it or got a 409). **Release:** install the procedure before the app; an old app ignores the extra rows, but runs a new app starts on the old procedure keep only their sent systems for good. Not done: no cap on linked systems (the largest asset has 4) |
| D21 | A control counts only on systems of its asset type (owner, 2026-10-21, after the end-to-end test found 34 cases of an IT-only control "still needed" on OT systems and the reverse, once risk flag 1 put every system of the asset in scope). Each control's affected systems are those of its type: an IT control the IT systems, an OT one the OT systems, an IT\OT or untyped one all (`_of_its_type`, `compatible_asset_types`, `asset_type_fits`); its status, `protected_systems` and `required_systems` are decided over them, so an action falling back to its controls' systems lands on the right ones. A system of no recorded category takes every control; when none fits (a control named by hand), every affected system. `asset_systems` now keeps each system's `category_code` (`FrozenContext.system_categories`); a run frozen before keeps its sent systems' categories, and its other systems take every control. The same round fixed three latent defects the test's probes confirmed: the other-type fallback kept the AI-control rule (an AI control was possible on a non-AI threat); its controls are never "strong" (they were labelled exact, so the API said EXACT), and its shortfall is counted after the cut; a name two different controls share no longer resolves to the lowest id (a register entry could mark the wrong control in place), only twins do |
| D22 | Sharper control identification and suggestion (owner, 2026-10-21, after the blind review found 55% of identified controls fit their scenario and 80% of the plan writer's checks sound). **A:** `MAX_CONTROLS` 5 (`.env.example` and `.env.uat` already said so; the local `.env` had 10): ranks 1-5 fit 67%, ranks 6-10 37%. **B:** a card is about AI by its threat's type and name or its scenario text (an LLM chatbot typed Web/API Exploitation now gets the library's LLM controls); the names of real-world attackers the cited evidence names never count (5 of 7 statement-only matches were "the Anthropic AI-orchestrated Campaign"). **C:** prompt `remediation-4`: a control is kept only when it directly reduces the risk on this attack path, and a generic or weakly related one is replaced when an alternative is clearly more direct, else flagged. Not changed: the reranker itself, whose scores order fitting controls above weak ones only 64% of the time locally (bge-reranker-v2-m3; rewording the query gave 63-71%); a per-scenario AI choice at mapping time is the open option |
| D23 | The AI gateway is on the pods' NO_PROXY (owner, 2026-10-21, UAT: every LLM call timed out). The pods send outside calls to the corporate proxy (HTTPS_PROXY), which cannot reach llmapi.govai.ae; the support team showed that with NO_PROXY=llmapi.govai.ae the pod reaches it directly. G264 ("called directly") had changed only comments and the egress rule and left the bypass to the app's process environment, which no `oc set env`, `env` or curl shows. Now: every app container lists the gateway on NO_PROXY and no_proxy (`deploy/deploy.yaml`, `deploy/deploy.ai-remediation.yaml`); the deploy gate (`scripts/gen_openshift_config.py`, `gateway_problems`) refuses a LiteLLM gateway that is not https on 443, not pinned (hostAliases) or not on both spellings in every app pod; the app merges NO_PROXY and no_proxy into one list (Python on Linux reads the lowercase one alone, so the gateway written into it alone hid the pod's localhost and .svc) and logs `ai.gateway_route` per AI gateway at start: direct, or the proxy's host and port. The live UAT deployment (`tsg-api`, no NO_PROXY) did not match the repository (`api`): deploy from it |
| D24 | UAT is production; the monitoring moves to ai-common (owner, 2026-10-23). Quotas (limits): ai-threatgen and ai-remediation 6 CPU, 12 Gi, 60 Gi each; ai-common 6 CPU, 16 Gi, 180 Gi, shared with the chatbot (its workers use what TSG leaves; TSG keeps to 3 CPU, 6 Gi, 60 Gi); ai-dca 10 CPU, 24 Gi, 120 Gi for the chatbot. **Quota fix:** a worker update started a second 2 Gi pod, 12.5 Gi against ai-threatgen's 12 Gi: workers now update with maxSurge 0 (the old pod stops first) and ai-remediation gets a second `worker-maintenance`, so every queue has a worker in each project and `/ready` stays green while one rolls (beat sends each maintenance task once, so a second copy doubles nothing). ai-threatgen peaks at 6 CPU, 11.5 Gi; ai-remediation 2.75 CPU, 8 Gi. **ai-common:** Prometheus, Alertmanager, Loki, Alloy, Grafana, redis-exporter, kube-state-metrics and Flower, public as before (since D31 only Grafana and Flower are public, on the API's host); they read both app projects through namespaced Roles there. `tsg-secrets` is copied to ai-common (Flower checks every required setting; redis-exporter reads the broker URL): whoever may read Secrets there can read TSG's passwords. `deploy-uat.ps1` deletes the monitoring programs and Routes left in ai-remediation (a host belongs to the first project that claims it) and keeps their volumes. No pod mounts a service account token. `tests/test_deploy.py` checks every project's CPU, memory and storage against its quota, surges included. **Alerts** still go nowhere (D-05) |
| D25 | The deploy is plain YAML, applied with `oc apply -f` only (owner, 2026-10-24): every value is written in the files, no script makes or fills them. `deploy/configmap.yaml`: `tsg-config` for the three projects and the monitoring's config files (Prometheus, Alertmanager, Loki, Alloy, Grafana), embedded byte for byte and tested equal to `observability/`; `deploy/secrets.example.yaml` (in git, `CHANGE_ME` values) is copied to `deploy/secrets.yaml` (git-ignored, real values): `tsg-secrets` for the three projects and Grafana's admin password; `deploy/networkpolicy_threatgen.yaml`, `deploy/networkpolicy_remediation.yaml`: each app project's ingress and egress rules; `deploy/deploy_remediation.yaml`: the 4 twin workers; `deploy/deploy_threatgen.yaml`: the API, the 4 workers, beat, the API's Service, Route and disruption budget; `deploy/deploy_common.yaml`: the monitoring and Flower in ai-common (and, since D31, the monitoring proxy in ai-threatgen). Apply order: secrets and settings, network rules, ai-remediation, ai-threatgen (the API last), ai-common; `deploy/DEPLOYMENT_GUIDE.md` has every step and check. No `kubernetes.io` anywhere in `deploy/*.yaml` (one exception since D29: `topologyKey: kubernetes.io/hostname`): pods carry `app`, `component` and `part-of` (Prometheus' job comes from `component`, Alloy's log labels from `part-of` and `component`); DNS egress is allowed by port (53/5353) to any address; the monitoring reaches the app pods by pod label from any project; the API's spreading over nodes was dropped (D29 brings it back); the image pull secret `quay-pull` is created with `oc create secret docker-registry`. Every YAML line carries a plain-English comment (block-scalar contents excepted), checked by a test. The image tag is `v2-<last commit that changed the image's inputs>` (`app/`, `pyproject.toml`, `requirements.txt`, `Dockerfile`, `.dockerignore`), so a YAML- or docs-only commit keeps the tag. `deploy/deploy-uat.ps1`, `deploy/observability.ps1` and `scripts/gen_openshift_config.py` are removed; the settings check moved into `tests/test_deploy.py`. The first switch deletes the old Deployments by name (a Deployment's selector cannot change, so a few minutes of downtime) |
| D26 | `deploy/build-image.bat` replaces `deploy/build-image.ps1` (owner, 2026-10-24: the build machine's PowerShell script policy blocks .ps1 files). The image tag is the build date, `dd-Mon-yyyy` with an English month (`tsg-api:24-Oct-2026`), or a tag given as the argument; `--no-push` builds and checks only. A tag that already exists in Quay is refused: the pods pull with `imagePullPolicy: IfNotPresent`, so an overwritten tag would never reach a node that already has it; a second build on the same day takes a suffix (`24-Oct-2026-2`). The date does not name the code, so the last commit that changed the build inputs is a label on the image (`org.opencontainers.image.revision`). The build still refuses uncommitted build inputs (`app/`, `pyproject.toml`, `requirements.txt`, `Dockerfile`, `.dockerignore`) and checks that the image loads the API, the worker and the SQL Server driver before it pushes. `tests/test_build_image.py` runs the .bat against stub git and docker. |
| D27 | Every image is built on Red Hat UBI 9, `FROM registry.access.redhat.com/ubi9:latest` (owner, 2026-10-24: docker.io and registry.k8s.io images cannot be used, and copying them into the Quay mirror does not work; Red Hat's own monitoring images are on registry.redhat.io, which needs a login, and there is no Red Hat Redis exporter or Alloy). `deploy/images/<name>/Dockerfile` per monitoring image downloads the program's official release and checks it against the release's published sha256 (the build fails on a mismatch or a missing line); kube-state-metrics, which publishes no binary, is compiled from its source with `ubi9/go-toolset`. Each runs as a non-root user, its writable folders in group 0 for OpenShift's random UID. `deploy/build-monitoring-images.bat` reads the names and tags from the `image:` lines of `deploy/deploy_common.yaml` (the one place versions live; names and tags unchanged), builds each with `--build-arg TAG=<tag>`, runs its version check as a random UID in group 0 and needs the tag's version in the output, refuses a tag already in Quay (as D26) and pushes; a name builds one image, `--no-push` builds and checks only. The app image moves to ubi9 with Python 3.12 from UBI AppStream and msodbcsql17 from Microsoft's RHEL 9 repo. |
| D28 | `deploy/build-image.bat` needs no git (owner, 2026-10-24: the build runs from a downloaded ZIP of the repo, without git). The committed-files check and the commit label are gone; the date tag (and the refusal of a tag already in Quay) names each build. `deploy/build-monitoring-images.bat` never used git |
| D29 | The speed-up package and the production layout (owner, 2026-10-24). **Why, in numbers:** one gateway key serves chat, embedding and rerank for every pod of both projects, and each model has its own requests-a-minute limit on it: kimi-k2.5's is 192; glm-5.3's, the embedding model's and the reranker's are not known yet. Each model's requests, retries included, are spaced across all pods on that model's own Redis key (`tsg:ai_next_request:{model}`), so one model's queue never delays another's: `CII_CHAT_REQUESTS_PER_MINUTE` = 180 for kimi-k2.5, and `CII_CHAT_FALLBACK_REQUESTS_PER_MINUTE`, `CII_EMBEDDING_REQUESTS_PER_MINUTE` and `CII_RERANK_REQUESTS_PER_MINUTE` stay 0 (no limit) until the gateway admin gives each model's limit; `CII_MAX_CONCURRENT_AI_CALLS` is 0 in UAT. At kimi-k2.5's 5 s a call, 180 a minute is about 15 calls in flight, so kimi's limit, not the pods, sets the ceiling: about 140 runs an hour. Each job fans out its own calls (gate 8, writer 6, controls 6 at once), so 2 threads a worker keep kimi-k2.5 busy; more would only wait at the limiter and add memory. **Faster runs:** gate batches 8 at once (was 4); write batches of 6, a set in one round (was 4); 6 reranks at once per process (was 4); control mapping sent as each scenario is saved, up to 6 scenarios mapped at once on a remote reranker; evidence rerank scores cached per process (2,000 searches); a plan delivery, a retry or a reaper re-send alike, reuses the gate and gap-fill answers its job already accepted (`tsg_ai_calls`, by record, epoch, stage and prompt hash; revises R3 for planning), and starts no new gate call once one found the AI unavailable; a rejected gate verdict holds only its reason and needs (`planner-6`); no attacker ranking for a threat whose gate pick decides; remediation drops, never re-asks, an `action_plan` sentence restating the schedule or the library, and takes its alternatives from the mapping's reranked `shortlist`; the service mapper re-asks only for faults the AI can fix; per-task `max_tokens` (`CHAT_MAX_OUTPUT_TOKENS`), a cut-off answer asked once more at the model's full limit (outcome `truncated`). **The AI under load:** an HTTP 429 waits (its Retry-After, at most 15 s, else 2, 5, 10, 15 s ±20%, 35 s in all) and asks the same model again, since glm-5.3 takes 55-99 s; the API, which answers a caller, retries a 429 as any busy answer (0.5, 1, 2 s); at most `CII_MAX_CONCURRENT_FALLBACK_CALLS` calls (UAT 16) on the fallback model at once (`tsg:ai_fallback_slots`); a model that timed out or stayed rate-limited is asked last for 120 s in that process; the rerank gate waits up to 300 s (was 60: requests now wait their turn); processes embedding the same texts at once (every pod after a library change) share the batches: each sends them in its own order and skips one another process has stored. **Queues:** a run's next stage, a retry and a reaper re-send go to the front of their queue (priority 0, new work 3), so started runs finish first; a retry delivered early is sent again for its due time; a job waiting for another polls every 15 s (was 120); `tsg_map_controls` moves to `tsg_controls`, `tsg_write_plan` to `tsg_remediation`. **Layout** (the same twin workers in both projects; threads, CPU request/limit, memory request/limit): `worker-threats` 2, 500m/1, 1Gi/1536Mi; `worker-scenarios` 2, 500m/1, 1Gi/2Gi (ai-threatgen's interim 250m/1536Mi cut undone); `worker-controls` (new) 1, 100m/250m, 640Mi/1Gi; `worker-remediation` and `worker-service-mapper` 2, 250m/500m, 640Mi/1Gi; `worker-maintenance` 3, 100m/250m, 768Mi/1536Mi; in ai-threatgen `api` ×2, 250m/750m, 512Mi/1Gi (maxUnavailable 0 and maxSurge 1 kept; readiness fails after 12 checks, was 3) and `beat`, 50m/250m, 320Mi/512Mi. Limits: ai-threatgen 5.25 CPU, 10.5 Gi (6.0, 11.5 Gi during an API update), ai-remediation 3.5 CPU, 8 Gi, within the 6 CPU, 12 Gi quotas (D24). **Measured** (UAT-like container, laptop): a worker holds about 220 MB, about 450 MB with the evidence index, about 600 MB after index rebuilds and up to about 815 MB during one, so only the scenarios workers hold the index. The old probe (`celery -A app.worker inspect ping`) loaded the whole app: about 230 MB and 5-6 s of CPU a check, 21 s at 250m, near the probe's 30 s limit. Every worker's startup and liveness probe is now `celery -A app.probe inspect ping -d "celery@$HOSTNAME" --timeout 10` (`app/probe.py` loads no worker code: about 36 MB and 0.3 s). The image sets `OPENBLAS_NUM_THREADS`, `OMP_NUM_THREADS` and `MKL_NUM_THREADS` to 1: numpy started a thread per node core, so vector searches used 13-17 times a 250m pod's CPU. Metrics: `tsg_ai_request_rate_wait_seconds{model}`, `tsg_ai_rate_limited_total{model}`, `tsg_job_queue_wait_seconds{task}`. **Spreading over nodes** (owner, 2026-10-24): nothing placed the pods apart, so a worker and its twin, or both API pods, could share a node and one node failure stopped both, which is what the twins and the API's disruption budget are for. Every worker in both projects now prefers a node without another pod of its own `app` label in either project (pod anti-affinity, `preferredDuringSchedulingIgnoredDuringExecution`, weight 100, `namespaces: [ai-threatgen, ai-remediation]`: the twin is in the other one); the API the same in its own project (no `namespaces`); beat is one pod. Preferred, never required: a pod still starts on a small or busy cluster and as the API's maxSurge pod. Only the node label `kubernetes.io/hostname` names "another node", so D25's "no `kubernetes.io`" rule has exactly one exception: that string as a `topologyKey` value; anywhere else (label, selector, Secret type, comment) `tests/test_deploy.py` still fails. A quota with the `CrossNamespacePodAffinity` scope (usually `pods: 0`), or a cluster that demands one, refuses pods whose rules name another project (the workers; the API names none): `deploy/DEPLOYMENT_GUIDE.md` step 1 checks for one (the cluster admin allows it, or the workers' `namespaces` line goes and each project spreads only its own pods). **Release:** `deploy/DEPLOYMENT_GUIDE.md` waits for each project's rollouts by label (`part-of=tsg`), so the new `worker-controls` is awaited too, and restarts Prometheus after a settings change so new alert rules load (`AiRequestRateWaitHigh`). **Open (owner):** whether TSG alone uses kimi-k2.5 on this key (180 assumes so); glm-5.3's, the embedding model's and the reranker's own requests a minute (their settings stay 0 until the gateway admin gives them); glm-5.3's concurrent capacity (16 until the gateway admin says); glm's timeout stays 120 s until one glm run is measured in UAT; the per-pod memory, to check in Grafana after the first week. **Embedding queries (2026-10-24):** a search query is embedded after its model's query instruction (`EmbeddingModelProfile.query_instruction`; qwen3-embedding-8b: `Instruct: {task}\nQuery:{query}`, per its model card, one English task per corpus in `QUERY_TASKS`); library texts stay plain, so nothing is re-embedded, and text-embedding-3-large takes none. Query vectors are keyed on the text sent, and the controls shortlist on the instruction (`made_with.query_instruction`). The 0.60 vector floor is to re-check on UAT; the similarity thresholds are reranker scores and do not change (429 waits revised by D30; beat 200m since D31) |
| D30 | TSG holds back its AI calls only after the gateway says it is full (owner, 2026-10-25). `CII_MAX_CONCURRENT_AI_CALLS` stays 0 in UAT: no fixed limit, so each model's requests a minute (D29) is the only limit until the gateway answers HTTP 429. **The 429 limit:** a 429 sets one limit on the AI calls in flight on every pod (`tsg:ai_slots:limit`, `AiSlots.note_rate_limited`): half the calls in flight at that moment, never below 4 (`AiLimits.ADAPTIVE_LIMIT_FLOOR`), at most one cut every 5 s. A cut never raises the limit: when half is not lower, the limit stays. Each answered call raises it by 1 / limit, and it is gone 180 s after the last 429 (`ADAPTIVE_LIMIT_TTL_SECONDS`). Above 0, the setting stays a fixed ceiling, and a 429's limit applies only when it is lower. **Leased slots:** each call's slot is a 60 s lease that its process renews every 20 s on one daemon thread (`SLOT_LEASE_SECONDS`, `SLOT_RENEW_SECONDS`), so a pod killed mid-call (out of memory, a crash, no SIGTERM) stops counting within a minute. This replaces the worst-case expiry (about 58 min for a chat call) and the shortening at SIGTERM. **Redis IO:** an answered call costs two Redis round trips (take; free, which also raises the limit). Only a call that ends with an answer raises the limit, so a request no model answered never does. At cap 0, a Redis failure makes the slots skip Redis for 30 s (`REDIS_SKIP_SECONDS`): calls go ahead uncounted. A model's request-rate turn still asks Redis on every request. The gauges `tsg_ai_slots_in_use` and `tsg_ai_slots_cap` (the limit in force: `CII_MAX_CONCURRENT_AI_CALLS` or the one a gateway 429 set, the lower; 0 = none) show NaN on any Redis error, so a scrape never fails. **429 waits** (revises D29's): a worker waits 2, 5, 10 and 15 s (±20%) and asks the same model again. A longer Retry-After is honoured up to 60 s; a shorter one never makes TSG ask sooner than its own step (the floor). At most 60 s of waits in all, then the fallback model. **Who refused:** `tsg_ai_outages_total{source}` is `gateway` (the gateway or its provider) or `limiter` (TSG's own: no slot or request turn free within the wait). The `AiNotAnswering` alert and the "AI no answer" tile count `gateway` only; "Why the AI did not answer" and "AI capacity in use" say what `limiter` and the limit in force mean. The API's own AI calls are counted too (it waits 30 s for a slot). `tsg:ai_slots:limit` is pinned in `tests/contract/tsg_names.json` |
| D31 | Grafana and Flower on the API's host, through a proxy in ai-threatgen (owner, 2026-10-25). OpenShift gives a host to one project only, and a Route reaches only a Service of its own project. So the Routes `grafana` (`/grafana`) and `flower` (`/flower`) are in ai-threatgen on `threatgen-api`, and point at a small nginx there (`monitoring-proxy`: Red Hat's UBI 9 nginx 1.24, `observability/nginx/nginx.conf`, embedded in `deploy/configmap.yaml`). It forwards those two paths only to Grafana and Flower in ai-common; the API's Route keeps every other path. Prometheus, Alertmanager and Loki have no public address (`oc port-forward`, guide Part 3), and ai-common has no TSG Route left. The proxy lives in `deploy/deploy_common.yaml` with the monitoring it serves: one pod, Recreate, 50m CPU and 64Mi as requests and limits. Beat's CPU limit goes from 250m to 200m to leave room in ai-threatgen's quota. nginx never spills to disk (`proxy_max_temp_file_size 0`), gives up a blocked connection after 5 s, and its config is checked with `nginx -t` at every release (`deploy\build-monitoring-images.bat nginx --no-push`). Grafana sends gzip and publishes no metrics page of its own. Only the proxy may reach Grafana (3000) and Flower (5555) from outside ai-common. A rollback first deletes the proxy, its Service and its Routes (`oc -n ai-threatgen delete deployment,service,route -l part-of=tsg-monitoring`), so the previous release fits the quota. **No login (owner):** Grafana stays without login. Anyone who can reach the API's address can read every log line and metric through Grafana's query API: its anonymous Viewer may send any Loki or Prometheus query (`POST /grafana/api/ds/query`). Flower has no login either, and is view only: without a login it switches its own API off, so no one can stop or revoke a job through it |
| D32 | A failure caused by an outage can always be tried again (owner, 2026-10-25). An outage is: a scenario card whose `failure.reason` is an AI outage (`ai_busy`, `ai_down`, `ai_unreachable`, `ai_timed_out`); a plan version or a mapping whose `job.error.code` is `unavailable` (an AI or a store outage). For scenario cards, plan versions and mappings, each try is one bounded job (at most 5 attempts) that only the next set or a user action starts. Other failures keep their behaviour. **Scenarios:** the next set writes an outage card's path again. Regenerate on such a card writes its path's first scenario again in place (same id, version 1), always, also after the path was given up after 5 tries. It never pulls a spare, so a run may end one scenario over its target (owner). Another outage keeps the card failed with its reason; `last_regen` ends `partial` and the run is not failed. An outage card whose path is given up as a repeat of a held scenario is relabelled `near_duplicate` (no reason) and is no longer regenerable. The console shows Regenerate on an outage card only. **Treatment plans:** regenerate on a latest version that failed for an outage writes that same version again in place: no new version and no version used, so `version_limit_reached` never stops it (D5). A hand-written request sent again with the same `Idempotency-Key` and body does the same (`202`, `replayed: true`). Any other failure, or a cancel, gets a new version. **Control mappings:** no automatic retry after 5 tries (the sweep still retries a failure with attempts left); a plan request or a plan regenerate maps them again. **Service mappings:** regenerate starts a new generation after any failure. The same `Idempotency-Key` (create or regenerate) starts a new try while that key's generation is still the latest and failed for an outage, else it replays (`200`); a create replay never answers `409 generation_in_progress`. A retried delivery of one generation reuses the AI answer it already got (`reuse_earlier_answer`). **AI answers:** a usable first answer is kept when its follow-up ask is unusable or finds the AI busy or down (treatment plans, service mapper). **First evidence index:** while no first index has been built, an AI or store outage retries the build after 30 s every time; any other failure, and every failure once an index serves, doubles the pause from 30 s up to 900 s (a build reads about 100 MB of stored vectors). **Busy notice:** cleared when the retry starts (D16) |
| D33 | Before a deploy, the cluster's own pull login is checked against every image (owner, 2026-10-25). Quay makes a new repository private, and a node can start a pod from its own copy, so a running pod proves nothing. `deploy/DEPLOYMENT_GUIDE.md` Part 2 step 6 (and Part 4 at every release) reads the login in ai-common's `quay-pull`, prints its account name (never the password) and runs `oc image info` on every `image:` line of `deploy/deploy_common.yaml`, the app image included. Every line must say `OK` (found, built on UBI 9) before going on. `CANNOT READ`: the account may not read the repository, or the image was never pushed (Quay answers the same for both); `NOT IN QUAY`: the tag is missing; `OLD COPY`: not the UBI 9 build under that tag; `CANNOT CHECK`: anything else, such as an untrusted certificate. The lines change nothing and delete the login file at the end, also on Ctrl+C. The 8 monitoring images include `dda-desc/nginx:1.24.0`, which needs the same Read right as the others (best as a default permission of `dda-desc`) |
| D34 | Supporting systems once per request (owner and Prashant, 2026-10-25; revises D19's flags and per-control lists, and D20's request). **Request** (`POST /v1/remediation`, both `is_manual` true and false): `supporting_systems_applicable_to_risk`, the asset's systems the risk applies to, and `supporting_systems_applicable_to_existing_controls`, the systems the existing controls are on, one list for all of them. Both optional: null, `""` and `[]` mean no supporting system; stored as `[]`, so a new register always has both keys, each id once in the order sent. Every id sent must be a supporting system of the scenario's asset (generated: the run's asset systems frozen at its start, D20; hand-written: SQL, checked before anything is saved), else 422 `body.<list>[n]`, `n` the place as sent. An existing-controls system outside the risk list is accepted; only the overlap counts. `existing_controls` only names the controls: an entry sending `supporting_system_ids` is refused as an unknown field (`RegisterControlRef` removed). The old flags (`all_supporting_systems_applicable`, `existing_controls_all_supporting_system_applicable`, `existing_controls_all_subsystems`) are removed from the request (owner, 2026-10-26): any value (0/1, a list, null, `""`) is a 422 on that field whose message names the list to send instead, and a new register never stores them. **Assessment:** affected = the asset's systems in the risk list, in the asset's order; every existing control is on the existing-controls list's systems; statuses, `protected_systems` and `required_systems` as in D19 and D21 (over the affected systems of the control's type). With a risk list, existing-controls list empty → every control `not_implemented`, needed on every affected system. Risk list empty → the risk is on the asset itself: an existing control `implemented`, any other `not_implemented`, both system lists `[]`, every action's `supporting_systems` `[]`. The snapshot's `risk_scope.all_supporting_systems_applicable` and `existing_controls.all_supporting_systems_applicable` are worked out: 1 only when the list names every supporting system of the asset, so `applicable_to_all_subsystems` is `Yes` only then. **Example** (Prashant's): 1 historian, 2 workstation, 3 SCADA, 4 firewall; risk `[1, 2, 3, 4]`, existing controls on `[2, 3]` → existing controls `partially_implemented`, still needed on 1 and 4. **Old plans:** a register stored before D34 (no lists) is assessed exactly as before, from its flags and per-control lists, on regenerate too. Prompt `remediation-5` (step 2: `affected_systems` are the systems the request lists; when empty, plan at the asset level). The console's plan form sends the two lists and no flag |
| D35 | The threat's own action carries its category (2026-10-27, from a ransomware scenario the owner shared, filed under Tampering). The prompts never say a threat/category pair is wrong; they forbid an invented bridge. **Gate and gap fill:** a threat belongs to a category only when one of its own actions (every action its name states) directly causes the loss the category's definition describes; one that needs an added step (e.g. a data theft put under Tampering by also altering the records it copies) is not relevant. The reason says why the threat fits the asset, never the attack steps. The gap fill prompt (`[scenario.gap_fill]`) lost its sentences addressed to the application (when gap fill may run is decided in code). **Writer:** every action the threat's name states happens, and the impact comes from one of them; an essential missing detail goes in `assumptions` as "assumes <condition>", and no safeguard assumed missing to enlarge the impact; the passage's closing "could"/"may" sentence uses only the cited entry's behaviour. **Reviewer:** rule 1 and `same_threat` catch an added step causing the impact, rule 7 a safeguard assumed missing, and `evidence_supported` a link that adds behaviour. **Shown statement:** `scenario_statement` is the statement alone; "Why this threat applies: ..." is no longer appended, and `scope.evidence` is always `[]` (owner, 2026-10-27). **No `why_applies`** (owner, 2026-10-27): it was in no API answer, so the writer no longer writes it and reviewer rule 9, which judged it, is gone (eight rules again); an old record's `content.why_applies` still reads and is never shown. The BRIEF's `why_it_applies` (the gate's reason) stays: it grounds the writer's systems and assumptions and shows in the plan trace. **Platform note** (owner, 2026-10-27, root cause of "not recorded in the platform" in stories): the gate and gap fill prompts had the reason end each assumption with it, the reason became the BRIEF's `why_it_applies`, and the writer copied it into the story. No prompt mentions it now: the AI writes "assumes ..." only. The API adds " - not recorded in the platform" once to each shown assumption (`results.py` `_scenario_text`; an old record's assumption that already holds it, any case, is shown unchanged; stored text stays the AI's own). `build_brief` removes the note from `why_it_applies` and from each `other_scenarios` statement, so an older plan or version never feeds it back. The writer's re-ask on the wording is gone. Versions: `planner-1`, `scenario writer-1`, `scenario writer-evidence-1` (one number for every prompt, D36) |
| D36 | One prompt version (owner, 2026-10-27). The version is `version = 1` at the top of `app/prompts.toml` (D37); `PromptVersion.NUMBER` in `app/core/constants/common.py` reads it, one number for every AI prompt. Raise it when any prompt in that file changes and every label moves at once. Labels: `planner-1` (each frozen plan's `prompt_version`), `scenario writer-1` and `scenario writer-evidence-1` (a scenario's `content.prompt_version`, by writing style), `remediation-1` (each plan version's `prompt_version`, returned by the API). Replaces `PLANNER_PROMPT_VERSION`, `WRITER_PROMPT_VERSION`, `StoryLimits.PROMPT_VERSION` and `Remediation.PROMPT_VERSION`. A record saved before keeps its label (e.g. `planner-7`, `remediation-5`); the labels restart at 1, so a `remediation-1` record from before D18, or a `scenario writer-1` or `scenario writer-evidence-1` record from before D35, carries the same label as a new one: tell them apart by date (`completed_at`, `frozen_at`, `created_at`) |
| D37 | One prompts file (owner, 2026-10-27). Every AI prompt and the prompt version live in `app/prompts.toml`, one section per prompt: `[scenario.gate]`, `[scenario.gap_fill]`, `[scenario.writer]`, `[scenario.reviewer]`, `[remediation.plan]`, `[service_mapper.generate]`. Each holds the prompt as `text`, and the fixed lines code adds to it (e.g. the gate's `system`, the writer's and reviewer's `no_evidence`, the remediation `context_prefix`). `app/core/prompts.py` reads the file once into `PROMPTS` (standard library `tomllib`). Replaces the six `prompts/*.txt` files and the fixed instruction strings in code; the AI gets the same text, character for character. The four unused "copy" files are deleted; git keeps every old version. Gap fill stays |

## 6. Not in this round (backlog, one at a time after the re-architecture)
1. Scenario regenerate has no version cap: AI cost is unbounded.
2. A crashed admin job can block new index builds for up to an hour.
3. Monitoring pages (Grafana, Flower) have no login. Anyone who can reach the API's address can read every log
   line and metric through Grafana's query API: its anonymous Viewer may send any Loki or Prometheus query
   (POST /grafana/api/ds/query). Prometheus and Alertmanager have no public address (oc port-forward only).
4. An approved threat without a category disappears from the app.
5. An intelligence import shows "done" even when every source failed.
6. The same threat told as two or more kinds may read alike; if reviewers report it, show the writer the
   run's other kinds of that threat (today only a regenerate shows the writer other versions).

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
