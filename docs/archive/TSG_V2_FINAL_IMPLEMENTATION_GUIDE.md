> **Retired 2026-10-10 — do not build from this file.** The only implementation guide is [IMPLEMENTATION_GUIDE.md](../IMPLEMENTATION_GUIDE.md) (§0.2 #1). Kept for reference only.

# TSG v2 — End-to-End Solution Implementation Guide

**Version:** 3.0  
**Date:** 2026-10-09  
**Purpose:** A dependency-ordered guide for building, testing, deploying, and accepting the complete TSG v2 solution from a clean repository.  
**Audience:** Developers, solution architects, QA, DBA, DevOps, and production owner.

---

## 0. How to use this guide

Build in the order in §8. Do not start a later step until the current step's **Exit check** passes. Keep each step in a small pull request where possible. This revision tightens the threat → canonical type → intelligence evidence → deduplication → actor-resolution contract, removes duplicate actor-selection paths, and makes path-level actor consistency a pre-writer validation gate. The guide covers the whole solution, not only Phase 1 scenario generation.

### Source precedence

1. This guide's explicit resolutions in §1 implement the latest owner requirements and override conflicting older text.
2. The `BLUEPRINT.md` business rules and module designs apply where this guide does not explicitly change them.
3. `IMPLEMENTATION_GUIDE.md` supplies the build status and lower-level implementation detail, subject to items 1–2.
4. `SDD.md` and `SYSTEM_DESIGN.md` explain the original design. Their older choices (Socket.IO, 15-scenario maximum, 5–25 controls, and the original package-by-domain layout) are historical where they conflict with the newer design.

### Critical prerequisites

- Python 3.12; SQL Server with ODBC Driver 17; MongoDB 6+; Redis 6+ (Memurai can be used locally on Windows).
- Access to one chat model, one embedding model, and one reranker, through the same LiteLLM-based gateway interface.
- SQL Server permissions to deploy the TSG stored procedures and grant the application `EXECUTE` on those procedures only.
- An approved set of requirements, data contracts, prompts, decision rules, source policies and acceptance fixtures defined as part of this new build. No existing TSG application, source tree, prompt implementation, or legacy behavior is a prerequisite. Create the first labelled evaluation set and golden fixtures during implementation; version them alongside the code.
- Dev/UAT connection values and secrets supplied through environment-specific configuration; never commit secrets.

---

## 1. Decisions and conflict resolutions

| Topic | Required implementation | Resolution / rationale |
|---|---|---|
| Scenario count | `.env`: `TOTAL_SCENARIO_COUNT=0` | Exact name required by the owner. This is an explicit exception to the normal `CII_` setting prefix. A value of `0` means all valid, relevant planned paths; a positive value selects the top N after all candidate paths have been identified and ranked. |
| No artificial scenarios | Never pad to meet a count | The system generates one scenario per selected valid path. If no valid path remains, complete successfully with zero scenarios and an explanatory plan note. A genuine system failure (e.g. no active capable actors in the canonical actor library) remains a failure, not a zero-result success. |
| Scenario universe | Keep the full identified/ranked path plan | A positive count limits which paths are eligible for generation; it does not truncate the underlying plan or mean only the first paths were analysed. “All paths” means all valid candidates produced by the documented threat and path-planning process, not every mathematically imaginable combination of attacks. |
| Control query | Include both scenario statement and risk statement | The combined query also includes threat/type, attack path, actor, title, asset and technology, and involved systems. Control mapping must not rely only on STRIDE or a threat-to-control lookup. |
| Control fallback | AI may help search/assess candidates, but cannot invent canonical controls | The current design treats `Control_Library` as the source of truth. Use hybrid retrieval and reranking; keep all controls over the cut-off, or the single nearest library control with `match=nearest` and a warning if none passes. If the library itself is empty, return/fail with `control_library_empty`; never store an AI-invented control as a real library control. This explicitly resolves the difference between the latest “AI fallback” request and the existing library-authority rule. |
| Remediation event stream | Include `GET /v1/remediation/{remediation_id}/events` as endpoint #28 | This was described but not counted in the earlier 27-endpoint inventory. It uses SSE and the same identity checks as other business endpoints. |
| Live updates | Server-Sent Events (SSE) + Redis pub/sub | Supersedes the older Socket.IO choice. Session stream is #8; remediation stream is #28. |
| Retry behaviour | Keep AI-call retries and background-job retries separate | **AI call:** `AiLimits.RETRIES=3` means up to 4 attempts total for one AI call. **Background job/path:** up to 5 job attempts, with retry delays of 15, 30, 60, and 120 seconds after failures 1–4; the fifth failed attempt is terminal. Test these as the new product's explicit retry contract. |
| Folder architecture | Layered folders | Use the `core`, `models`, `api`, `services`, `data_access`, `ai`, `search`, `engine`, `realtime`, and `worker` structure defined in §2; do not mix it with the older package-by-domain layout. |
| Control source/schema | `dbo.Control_Library` only; column `AssetType` | Use `AssetType` (`IT`, `OT`, `IT-OT`, `OT-IT`). `IT-OT` and `OT-IT` both mean compatible with IT and OT. Do not reference retired `ITOT`, `Control_Standard`, or `Control_Library_Standard_Map`. |
| Production monitoring | Must pass explicit security acceptance | The earlier blueprint allows observability pages without login. Before production, either protect them with approved access controls or obtain documented, explicit risk acceptance for the public exposure. Do not silently treat “public” as secure. Use TLS for production connections to MongoDB/Redis where supported and required by the approved environment baseline. |
| External threat intelligence | Build ingestion and technique-evidence retrieval before ThreatFinder/path/writer implementation is accepted | Intelligence is not a late prompt add-on. ATT&CK/CAPEC techniques and sourced advisories must inform candidate retrieval, attack-path plausibility, scenario evidence and control search, while SQL TSG libraries remain canonical for approved threats, types, actors and controls. |
| External evidence versus canonical library | Keep separate collections and statuses | External techniques, advisories, IOCs and group aliases are evidence—not approved TSG master rows. They may enrich a canonical threat, or produce a clearly labelled non-canonical `cti_gap_candidate` for review. They must never silently create/activate a canonical threat, threat type, actor or control. |
| Attack-chain validity | Every multi-step path needs a supported transition | Do not treat ATT&CK tactic order or semantic similarity alone as proof that two techniques form an attack chain. Each path edge must be source-supported or an approved transition rule whose preconditions match the asset/system context; otherwise retain separate single-step paths. |
| Source freshness and geographic claims | Version every source snapshot and distinguish attempts from confirmed incidents | Refresh known feeds asynchronously, retain last-good snapshots, and stamp every run with the exact source versions used. Regional statistics (including the “over one million” figure) must carry publisher/date/definition and must not be treated as per-asset likelihood without evidence. |
| OTX integration | Use the configured OTX API key in the first CTI release | After the source-terms gate approves the intended use, ingest subscribed/approved OTX pulses asynchronously through a dedicated adapter. Until then, use fixtures and do not issue live requests. OTX is community threat intelligence: indicators and pulse text can support evidence discovery, but an IOC alone does not prove asset exposure, exploitability, a threat actor, or an ordered attack path. Keep the key in secret storage. |
| Scenario realism and claim strength | Every scenario carries an evidence mode and provenance | Distinguish source-documented behavior from a scenario inferred from ATT&CK/CAPEC and from a lower-evidence hypothesis. A scenario against the assessed asset is still hypothetical unless the organization has incident evidence for that asset. Never write “this actor attacked this asset” based only on public CTI. |
| Canonical type/actor eligibility | Only scenario-ready candidates enter path selection | An AI/CTI candidate must resolve to a live canonical threat type before it can become a scenario path, because actor selection is type-constrained. If no type match exists, keep it as a pending non-canonical discovery/curation item; do not generate a scenario from an untyped candidate or invent a type/actor. A typed, actor-eligible candidate may be scenario-eligible before master-data promotion only after all explicit path/evidence gates pass; retain its pending status until a curator separately promotes it. |
| Model score calibration | Treat raw reranker outputs as model-specific | Convert reranker outputs to the documented calibrated 0–100 scale using a versioned model profile and labelled validation pairs. Thresholds such as 75 for a match and 60 for control selection are initial operating values, not universal probabilities; recalibrate after model/profile changes and never compare raw scores across different model versions. |
| Search coverage honesty | Distinguish retrieval coverage from the scenario count | `TOTAL_SCENARIO_COUNT=0` means all valid paths found by the configured retrieval, relevance and graph-validation process. It cannot mean every theoretically possible cyberattack; report top-K/search-budget and missing-context warnings, and measure retrieval recall against a labelled benchmark. |
| Scenario eligibility vs. library promotion | Use explicit independent states | A non-canonical AI/CTI candidate may seed a scenario only after it passes evidence, deduplication, canonical threat-type, eligible library-actor, path-edge and precondition checks. Record `scenario_eligible=true` separately from `master_data_status=pending_review`. Scenario generation does not promote the candidate into a canonical library. Untyped, actor-ineligible or unsupported candidates remain ineligible and cannot count toward the configured scenario total. |
| Actor identity vs. scenario modelling | Prevent false real-world attribution | The required library actor ID is a constrained modelling reference, not proof that a real-world group performed or would perform the attack. Display a named group as source-attributed only when explicit evidence supports that association; otherwise display a generic hypothetical profile or `Actor attribution unknown`. Never expose a named group selected only by embedding similarity as a factual actor. |
| Route status | Base confidence on evidence, not system count | A single involved system does not make a route confirmed, and two systems do not automatically make a route assumed. Derive route status from frozen topology/configuration evidence and explicit path preconditions; missing connectivity remains unknown and must be reported. |
| Attack-transition rule governance | Make multi-step generation reproducible | Source-extracted sequences and human-approved transition rules are the only permitted multi-step edges. Bootstrap a small, version-controlled rule catalogue with explicit preconditions, domain, evidence/references, reviewer, version and positive/negative tests. LLM-proposed edges stay candidates until review. |
| Source-rights revocation | Separate legal disablement from network failure | Last-known-good fallback applies only when a still-approved source is temporarily unavailable. If a source's use permission changes to `conditional` or `blocked`, disable it immediately, remove its records from active retrieval, invalidate vectors/caches and purge or restrict retained material as required by the governing terms. |

### Scenario count examples

| Valid paths identified and ranked | `TOTAL_SCENARIO_COUNT` | Eligible for generation | Generated if all writing tasks succeed |
|---:|---:|---:|---:|
| 18 | 0 | 18 | 18 |
| 18 | 12 | 12 highest-ranked | 12 |
| 18 | 5 | 5 highest-ranked | 5 |
| 6 | 12 | 6 | 6 |
| 6 | 0 | 6 | 6 |
| 0 | 12 | 0 | 0 |

A positive limit must be applied only **after** threat identification, deduplication, path validation, and ranking. `next-set` writes the next batch from the already selected/eligible paths; it must not exceed the positive configured limit.

---

## 2. Target architecture and project structure

### 2.1 Architecture

```text
Calling platform backend (keeps API key; sends identity headers)
        |
        | HTTPS REST + SSE
        v
FastAPI API pods (routers -> services -> data_access / engine / search)
        |                                  ^
        | queued message: task + ids        | Redis pub/sub: status updates
        v                                  |
Redis: tsg_threats / tsg_scenarios / tsg_maintenance
        |
        v
Celery workers + beat -----> AI gateway -----> chat / embedding / rerank models
        |          |                    ^
        |          +---- SQL Server      | hybrid retrieval/rerank
        |                stored procedures (asset + canonical TSG libraries)
        |        | \---- allow-listed HTTPS sources: MITRE ATT&CK, CAPEC, CISA KEV/ICS,
        |       optional OTX/MISP, vendor and approved UAE/sector/internal reports
        v
MongoDB: runs/scenarios/audit + tsg_intel + tsg_techniques + technique edges/mappings
        |        | \---- versioned BM25 + embedding indexes --> TechniqueEvidenceResolver
        |                                                |        |        |
        +------------------------------------------------+--------+--------+
                                                         ThreatFinder / PathSelector /
                                                         ScenarioWriter / ControlMapper

Prometheus + Alertmanager + Loki/Alloy + exporters -> Grafana; Flower for worker tasks
```

**Authoritative boundary:** the LLM can judge relevance and draft language/plan content. Application code owns identity, allowed libraries, count limits, IDs, lifecycle state, review decisions, control identity, scheduling, persistence, and every deterministic rule.

### 2.2 Folder structure

```text
tsg-v2/
├── app/
│   ├── main.py
│   ├── core/                 # config, constants, exceptions, logging, metrics, DB clients, singletons
│   ├── models/               # Pydantic API schemas and domain dataclasses
│   ├── api/                  # middleware, dependencies, error handlers, routers
│   ├── services/             # use cases and workflow orchestration
│   ├── data_access/          # all MongoDB and stored-procedure access
│   ├── ai/                   # chat, embeddings, rerank, profiles, slots, validation
│   ├── search/               # library cache, text normalization, indexes, hybrid search
│   │   └── techniques.py     # versioned ATT&CK/CAPEC and intel hybrid retrieval
│   ├── intel/                 # source registry, normalized intelligence and evidence provenance
│   │   ├── adapters/          # attack_stix.py, capec.py, cisa_kev.py, cisa_advisory.py, otx.py
│   │   ├── normalize.py       # canonical normalized source schemas
│   │   ├── deduplicate.py     # idempotent source upserts and cross-source clusters
│   │   ├── refresh.py         # staged import, validation, activation and last-good fallback
│   │   └── provenance.py      # source stamps, evidence resolution and citation checks
│   ├── engine/
│   │   ├── scenarios/        # threats, paths, writer, rules, controls, prompts
│   │   │   └── technique_evidence.py # evidence fit, canonical mapping, path-edge checks
│   │   └── remediation/      # planner, scheduler, prompts
│   ├── realtime/             # EventHub, SSE streams, Redis publishers
│   └── worker/               # Celery app, jobs/leases, heartbeat, reaper, task modules
├── scripts/
│   ├── sql/                  # CREATE OR ALTER procedures and grants.sql
│   ├── smoke.py
│   ├── acceptance_eval.py
│   ├── measure_cutoff.py
│   └── monitoring*.py
├── tests/                    # unit, API, integration, SQL, worker, security, performance
├── observability/            # Prometheus, Alertmanager, Loki/Alloy, Grafana provisioning
├── deploy/                   # OpenShift API, worker, beat, route, policy, PDB manifests
├── docs/                     # this guide, SDD, SYSTEM_DESIGN, blueprint, rules
├── Dockerfile
├── pyproject.toml
├── requirements.txt
├── .env.example
└── README.md
```

**Layer rules:** `core` imports no application layer; `models` may use core types; `api` calls services; `services` orchestrate use cases and call data access/engine; `data_access` owns database calls; `engine` is pure business logic and must not import FastAPI, MongoDB, Celery, or HTTP routers. Workers call services/engine and persist through data-access methods. Avoid a dependency-injection framework and unused abstractions.

---

## 3. Environment setup and configuration

### Step 3.1 — Create the project and pinned dependencies

**Implement**
1. Create the repository and folders from §2.2.
2. Create a Python 3.12 virtual environment.
3. Pin runtime and development dependencies in `requirements.txt`; include test, lint, and type-check tools.
4. Add `.gitignore`, `.env.example`, README instructions, and a repeatable test command.

**How**
```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\python -m pytest
```
Use the equivalent `python3.12 -m venv .venv` flow on Linux. Install using the pinned constraints so dev and CI use the same dependency versions.

**Why**: A reproducible Python/runtime baseline prevents environmental drift.  
**Depends on**: repository creation.  
**Exit check**: clean checkout can install pinned dependencies and run the initial test suite.

### Step 3.2 — Configuration

Create typed settings in `app/core/config.py`. Validate required values on startup and fail fast for invalid model profiles, malformed URLs, non-positive limits where zero is not allowed, and invalid `TOTAL_SCENARIO_COUNT` values.

Required settings include the following groups (actual credential values are environment-specific):

| Group | Settings / examples | Rule |
|---|---|---|
| Runtime | `CII_ENV`, `CII_LOG_LEVEL`, `CII_CORS_ORIGINS` | Unknown/missing environment must not accidentally bypass production checks. |
| MongoDB | URI, database name, timeouts | TLS and credentials per environment policy; create indexes at startup. |
| Redis/Celery | broker URL, result backend only if required by the chosen implementation, database/prefix | MongoDB remains job truth; do not rely on Celery result storage. |
| SQL Server | connection string / host, database, credentials | Application account has stored-procedure execute rights only. |
| AI | chat, embedding and rerank model names/endpoints/keys | Names in environment; model capabilities and limits in typed model profiles. |
| Operational bounds | `CII_MAX_REQUEST_MB=2`, `CII_MAX_CONCURRENT_AI_CALLS=16` | `0` for AI calls means no limit only where explicitly defined. Request size is one limit for every request body. |
| Scenario count | `TOTAL_SCENARIO_COUNT=0` | Whole integer ≥ 0; exact unprefixed name is required. Use a Pydantic alias/field validation alias so the application setting can be typed without changing this external name. |
| Threat intelligence | `CII_INTEL_ENABLED`, per-source feed toggles, `CII_OTX_ENABLED`, `CII_OTX_API_KEY`, `CII_NVD_ENABLED`, optional `CII_NVD_API_KEY`, `CII_EPSS_ENABLED`, optional `CII_MISP_BASE_URL`/`CII_MISP_API_KEY`, approved source allow-list | Because an OTX key is available, configure its secret reference for the adapter, but do not make live OTX requests in Dev/UAT/production until the source-terms gate approves the exact use. When OTX is `conditional` or `blocked`, use frozen fixtures/mocks for development and tests. Keep actual keys out of `.env.example`, source control, prompts and logs; examples contain blank placeholders only. NVD key is optional and secret-injected if used. Published CISA/MITRE/EPSS data normally requires no private API key. Activate only feeds that pass the source-terms gate; a source failure must not block generation; do not let users or model output supply arbitrary fetch URLs. |
| Intel operations | `CII_INTEL_REFRESH_INTERVAL_HOURS=24`, `CII_TECHNIQUE_REFRESH_INTERVAL_HOURS=168`, `CII_INTEL_STALE_AFTER_HOURS=48` (minimum stale threshold), `CII_INTEL_FETCH_TIMEOUT_SECONDS=30`, `CII_INTEL_MAX_RESPONSE_MB=50`, `CII_OTX_ENABLED=false` in generic examples | Typed, bounded settings. A key enables authentication, not usage rights. For a commercial deployment, keep `CII_OTX_ENABLED=false` until a recorded terms/legal review approves the specific use; only then set it through protected environment configuration and inject the key as a secret. Use daily refresh for changing advisory/IOC feeds and weekly or release-driven checks for versioned technique catalogs; allow admin-triggered refresh. Determine stale status per source from `max(CII_INTEL_STALE_AFTER_HOURS, 2 × that source's configured poll interval)`, so a weekly release check is not falsely marked stale after 48 hours. A successful check with no new upstream release still updates `last_checked_at`; keep `last_changed_at` separate. Keep last-known-good snapshots on error. |
| Actor fit | `CII_ACTOR_FIT_MIN_SCORE=75` on a calibrated 0–100 profile; require actor profile/source evidence and recalibrate on labelled actor-fit pairs before production. This is a starting threshold, not a probability. |
| Technique/path search | `CII_TECHNIQUE_RETRIEVAL_TOP_K=50`, `CII_MAX_ATTACK_PATH_STEPS=6`, `CII_MAX_PATH_EXPANSIONS=10000`, calibrated per-source/evidence cutoffs | These are initial engineering defaults and must be load/quality tested in UAT. `MAX_ATTACK_PATH_STEPS` is a configurable path-length bound (not a scenario-count limit); the expansion budget protects against combinatorial graph growth. If the budget is reached, persist `path_search_status=budget_limited` and a coverage warning; do not claim complete graph coverage. `TOTAL_SCENARIO_COUNT` is applied only after the bounded search, evidence validation, deduplication and ranking. |
| Monitoring | optional Grafana `GF_…` lines and admin password for deployment | Must follow the production access decision in §1. |

**Configuration consistency test:** `.env`, `.env.uat`, and `.env.example` must reflect `Settings` fields and aliases, including every `CII_INTEL_*`, `CII_TECHNIQUE_*`, and source-enable setting introduced in §7.2.6. Update the config-sync test to understand `TOTAL_SCENARIO_COUNT` as the documented exception. Never introduce a setting in code without updating all applicable environment examples and tests in the same change.

**Exit check**: settings validation tests cover missing values, invalid URLs, bad model profiles, request-size limits, and negative/non-integer scenario counts.

---

## 4. Data model and SQL Server contract

### 4.1 Storage ownership

| Data | Store | Rule |
|---|---|---|
| Existing asset, supporting-system, threat, actor, and control library data | SQL Server through stored procedures | Read platform data; never access platform tables directly from application code. |
| Sessions/runs, frozen threat/path plan, scenarios, decisions | MongoDB | Every document includes the owning entity and tenant context. All mutations use expected state and/or task/epoch fencing. |
| Remediation records and immutable plan versions | MongoDB | Snapshot inputs per version; preserve older versions. |
| API clients, audit, AI call records, admin jobs, intel and technique records | MongoDB | Create indexes and retention policies explicitly. |
| Queue messages, pub/sub, and shared AI concurrency slots | Redis | Messages carry identifiers and epoch only. MongoDB is the source of truth. |
| Embedding vectors | MongoDB cache + in-process memory index | Cache key includes model and content hash; rebuild on library/model stamp change. |

### 4.2 MongoDB collections

Implement these collections and their indexes before dependent API flows:

- `tsg_sessions`: entity/tenant/user/client IDs, asset ID, frozen asset/system/context snapshot including any verified topology/identity relationship edges and their source/timestamps, status/step, job lease/epoch, complete candidate plan, selected path IDs, path ranks and generation states, review decisions, counts, timings, timestamps, last action/error, `path_search_status` (`complete|budget_limited`), per-STRIDE-category `relevance_assessment_status` / `retrieval_status` / `category_full_scan`, expansion count and stopping reason, coverage warnings, canonical-library stamp, technique catalogue/feed stamps, prompt/model/index/rule versions, source-freshness summary and immutable per-run evidence references.
- `tsg_scenarios`: deterministic scenario ID, session/path/version, source (`library`, `ai_gap_fill`, or `cti_gap_candidate`), candidate key where non-canonical, scenario statement, risk statement, threat/actor/system references, ordered attack-path steps, technique/CAPEC IDs, edge IDs, preconditions/assumptions/unknowns, source/evidence references and source stamps, route, validation findings, plan consistency result, controls and control-mapping state, decision, supersession/replacement links, generation failure details, timestamps. Add `evidence_mode` (`observed_pattern`, `technique_informed`, `hypothesis`), `attribution_level` (`source_attributed`, `actor_archetype`, `unknown`), `actor_presentation` (`source_attributed_group`, `hypothetical_profile`, `unattributed`), `scenario_eligible`, `master_data_status` (`canonical`, `pending_review`, `rejected`), source-quality summary and `coverage_warnings`. These fields separate permission to use a candidate for a generated scenario from permission to promote it into the approved master library. A non-canonical candidate can have `scenario_eligible=true` only after the gates in §7.2 and §7.3 pass; its `master_data_status` remains `pending_review`. `observed_pattern` means the behavior sequence is described by source evidence; it never means the assessed asset was compromised unless the organization has that specific incident evidence.
- `tsg_remediations`: scenario/source links, entity/tenant, register snapshot, versions, current and accepted version, independent generation/review status, job lease/epoch, progress/error, audit metadata and an incrementing `event_seq` for remediation events.
- `tsg_api_clients`: client metadata, key hash/prefix, active/revoked timestamps; never persist or return the plaintext key after initial creation.
- `tsg_embeddings`: model, content group/hash, vector and dimension. Query-vector cache should have its documented TTL; library vectors persist until content/model changes.
- `tsg_ai_calls`: task/model, prompt and response, token counts, latency, success/error, `record_id`, `request_id`, entity/session/plan identifiers where applicable; 14-day TTL per current design.
- `tsg_audit`: append-only action records with actor/client/user/entity, target, before/after summary, details, and request ID; 365-day retention per current assumption.
- `tsg_admin_jobs`: durable import, index-build, intel-refresh and technique-rebuild job progress.
- `tsg_intel_feeds`: allow-listed source registry/version, source trust tier, parser version, license/terms URL and review state (`approved|conditional|blocked`), attribution/retention/vectorization/redistribution decisions, reviewer/date, poll interval, `last_checked_at`, `last_changed_at`, last success/failure, checkpoint/watermark, checksum, record count and freshness state. Secrets are references to secret storage, never values in Mongo. A feed cannot enter an active snapshot unless its state is `approved`. A downgrade to `conditional` or `blocked` immediately disables new fetches and active retrieval, invalidates its vector/index/cache entries and launches a compliant purge/restriction job as required by the source terms. Historical audit records retain only the metadata/hash/source pointer that the applicable terms permit; if source text must be purged, record that the supporting excerpt is no longer retained instead of keeping prohibited text for reproducibility. Never use last-known-good fallback to bypass a legal or licence block; it is only for a temporary operational failure while approval remains valid.
- `tsg_intel`: normalized advisory/KEV/NVD/EPSS/OTX/MISP/report objects. Store source + external object ID, pulse/advisory/CVE identifiers, title/summary, vendor/product/version and CPE applicability, CVSS vector/score, KEV membership/added date, EPSS score/percentile/score date, source-stated actor aliases, technique IDs, URL, publisher, publication/modification/fetch timestamps, first/last seen, source tier, confidence/evidence mode, `sharing_scope`/tenant or community scope where applicable, content hash and validation status. Apply sharing/TLP/tenant filters before retrieval and vector search; do not assume an aggregator makes restricted source data globally shareable. Keep unlike score semantics in separate fields; no EPSS/CVSS/KEV value is a per-asset breach probability. Treat raw source content as untrusted; bound retention and preserve only a legally permitted minimal immutable evidence snapshot in each run. An OTX pulse author is not the threat actor.
- `tsg_intel_indicators`: normalized OTX/MISP/CISA indicator records kept separate from technique prose. Store indicator type, normalized value or approved protected representation, exact-match hash, source-object/pulse IDs, source timestamp, `first_seen`, `last_seen`, `valid_from`, `valid_until`/expiry policy, validity/revocation, confidence, TLP/sharing label if supplied, explicit `sharing_scope`/tenant scope, and cross-source correlation-cluster ID. Enforce scope filters before exact matching and retrieval. Apply source/type-specific expiry and revocation checks before matching; an old indicator cannot remain actionable merely because its source feed is still healthy. Use exact typed matches only when approved asset inventory provides the same kind of indicator; never embed raw IOC values into semantic vectors.
- `tsg_techniques`: versioned ATT&CK Enterprise/ICS (and Mobile where applicable) techniques/sub-techniques, CAPEC patterns and optional domain catalogues. Store stable external IDs, catalogue/domain/release, name, behavior summary, platforms, prerequisites, related technique/CAPEC/CVE IDs, relationships, mitigations/detection guidance, deprecated/revoked flags and source URL. Do not depend on ATT&CK fields that are deprecated or missing from newer releases.
- `tsg_actor_profiles`: versioned, reviewed enrichment keyed by canonical `actor_id`. Store actor kind (`generic_archetype` or `named_group`), concise profile, motivations/objectives only where sourced or explicitly generic, capabilities, target sectors/platforms, techniques/TTP references, source URLs/IDs, evidence strength, last-reviewed date, profile version and approval status. This collection enriches actor fit; it never creates a canonical `Threat_Actor` row or overrides `IsCapable` / `ThreatType_ThreatActor_Map`. If no approved profile exists, use only a direct type↔actor link as a generic modelling association for an explicitly generic archetype; a named actor without sufficient profile/source evidence remains ineligible. Index by actor ID, status and technique IDs.
- `tsg_intel_procedures`: source-grounded procedure candidates extracted from approved reports, advisories, campaign write-ups and applicable ATT&CK/CAPEC procedure examples. Store `source_id`, external object ID, source URL, publication/version stamp, document/content hash, exact section/paragraph or page anchors, character offsets only when stable and permitted, ordered known technique/CAPEC IDs, the minimal source-supported sequence description (only if retention terms allow it), explicit ordering/causal cue, vendor/product/platform context, parser/extractor version, validation findings, and status `candidate|source_validated|reviewed|rejected`. Never store a source excerpt beyond its approved retention/redistribution limits. Each extracted sequence must point back to specific source spans; an LLM-generated summary without a valid source span is not evidence.
- `tsg_technique_edges`: directed candidate transition between technique/pattern nodes, `edge_type`, preconditions, affected surface, procedure/source IDs and span references, confidence/evidence dimensions, status `candidate|source_validated|reviewed|rejected`, catalogue version, and (for rule-based edges) immutable `rule_id`/`rule_version`, reviewer, approval timestamp and test-fixture references. Production path search may use only `source_validated` edges whose exact source spans and preconditions passed deterministic validation, `reviewed` edges, or explicitly owner-approved rules. Edges based only on semantic similarity remain candidates. Source-extracted procedure edges and approved rule edges must be distinguishable in the audit record.
- `tsg_technique_mappings`: candidate/reviewed many-to-many links from external technique/pattern IDs to canonical TSG threat ID, threat-type ID and STRIDE category, including method, calibrated score, evidence, reviewer and status. Only reviewed/approved mappings can assert a canonical threat relationship in the production plan; candidate mappings may seed a `cti_gap_candidate` only through the separate eligibility gates and cannot silently bind to a canonical threat. Technique-to-STRIDE is a curated mapping, not a claim that ATT&CK defines STRIDE.

Create unique/idempotent indexes for `(source_id, external_object_id)` and `(source_id, external_object_id, indicator_type, indicator_hash)` as applicable, plus lookup indexes for active source stamp, technique ID, normalized indicator hash, `last_seen`, and correlation cluster. Do not create a global unique key on indicator value alone: the same indicator may have multiple independent provenance records.

Create indexes in `ensure_indexes()` and test them. Essential invariants include one active run per entity+asset, unique idempotency keys in the entity-wide namespace, unique scenario version IDs, query support for entity lists, worker lease/reaper scans, control retry scans, and remediation current/history queries. Use partial unique indexes for “active only” constraints.

### 4.3 SQL stored procedures

The latest design uses seven library tables (including `Control_Library`) and stored procedures only. Deploy these procedures with DBA review:

| Procedure | Purpose | Required validation |
|---|---|---|
| `tsg_GetAssetContext` | Return the asset only if owned by the requested entity, verify system links, and return supporting systems, service/sector/subsector and relevant technology/context fields. | Unknown or unowned asset/system and inconsistent sector-parent mapping produce the documented 403/404/422 result. System membership alone is not network reachability. The app-level `AssetContextProvider` must optionally enrich the result from explicitly allow-listed, authorized CMDB/cloud/network/identity configuration sources and freeze all returned relationships with source and timestamp; when no such evidence is available, reachability/trust remains `unknown`. |
| `tsg_GetThreatLibrary` | Return the required result sets for categories, types, threats, actors, and their relationships, restricted to live rows. | Validate every result set, field name, type, and expected count. |
| `tsg_GetControlLibrary` | Return active, non-deleted rows from `Control_Library`: `ControlLibraryID`, `ControlCode`, `AssetType`, `Domain`, `ControlName`, `ControlDescription`. | Do not read retired standards tables or the old `ITOT` column. |
| `tsg_GetLibraryStamp` | Return an exact content fingerprint for the seven tables TSG reads. | A change to any relevant column changes the stamp. Keep serving the last good library snapshot if a refresh later fails. |
| `tsg_ResolveThreat` | Insert/resolve AI-proposed or hand-written threat/type entries as pending/inactive. | Idempotent resolution; accepted/rejected wording rules; never activate automatically. |
| `tsg_ListPendingThreats` | Paginate pending threat proposals. | Entity/admin access, limits and stable ordering. |
| `tsg_DecidePendingThreats` | Approve/reject pending records. | Reject overlapping approve/reject IDs; max 100 total per request; audit outcomes. |
| `tsg_ImportThreatLibrary` | Import approved source data, supporting dry-run. | Validate source schema, deduplicate, return counts, and keep imported entries inactive unless explicitly authorized by the procedure contract. |
| `grants.sql` | Grant the application login execute permissions on required procedures only. | Test that table-level read/write is denied. |

### 4.4 Data-access rules

1. All Mongo reads/writes go through `app/data_access/`; SQL calls go through the stored-procedure client.
2. Every business query includes the correct entity and tenant filters; do not trust IDs supplied by the caller without ownership checks.
3. State-changing writes use a conditional update with the expected status/version/decision. Workers also fence every write on task ID and epoch/lease ownership.
4. Persist the frozen context once at run start. The same run must not silently change its asset/system facts during generation.
5. Persist a scenario as soon as its generation and code-side validation complete; do not wait for all scenarios in a batch to finish.
6. Write durable state first, then publish a live event. Pub/sub is notification, not source of truth.

**Exit check**: SQL integration tests cover ownership, linked systems, all result sets, library stamp changes, pending decisions/imports, and least privilege. Mongo tests cover indexes, uniqueness, atomic state transitions and fenced writes.

---

## 5. Shared API conventions

### 5.1 Authentication and identity

All business endpoints use these headers:

- `X-API-Key`
- `X-User-Id`
- `X-Entity-Id`
- `X-Tenant-Id`

Admin endpoints use `X-Admin-Key`. The platform backend—not a browser—holds the API key and opens SSE streams, relaying events to the browser if needed. Key records hold a SHA-256 hash only; show a minted secret once and use `Cache-Control: no-store` on its response.

The `Principal` dependency validates identity and resolves the calling system/client. For each resource request, validate that the resource belongs to the supplied entity and tenant. Unknown resource → 404; known resource owned by another entity/tenant → 403. Entity isolation must be tested on reads, writes, lists, SSE streams, and background-job status access.

### 5.2 Request validation and error responses

- Use Pydantic models with explicit lengths, numeric bounds, enums and `extra="forbid"` where the contract requires strict input.
- Reject request bodies larger than `CII_MAX_REQUEST_MB` with 413 before expensive processing.
- Use one RFC 9457-style response for errors: `{type, title, status, detail, code, reason, request_id}`. Include field errors where relevant without exposing secrets, SQL details, stack traces, prompts, or internal paths.
- Standard statuses: 400/422 for invalid input (use the documented contract consistently), 401 for missing/invalid identity, 403 for wrong entity/tenant, 404 for unknown resources, 409 for state conflicts, 413 for oversized request, 503 + `Retry-After` for temporary dependency/capacity failures, and 500 with a safe public message plus request ID for unexpected errors.
- Record request IDs and `client_id` in structured logs; never return the caller's client key or internal secret values.

### 5.3 API implementation pattern

Implement every endpoint in this order:

1. Define request/response schema and examples.
2. Add router method with authentication dependencies and no business logic.
3. Add service method for the use case and all state/precondition checks.
4. Add data-access method using a narrow query/projection and conditional write where needed.
5. Add worker task if work is long-running; save `queued` state first and return 202 after enqueue.
6. Add event publication after durable writes and audit records for significant decisions.
7. Add unit, API, integration, security, and concurrency tests.
8. Add OpenAPI contract checks and metrics/logging.

---

## 6. Complete API inventory

This inventory contains the 27 documented APIs plus the explicitly required remediation SSE stream as **#28**. Health/readiness/metrics are operational endpoints outside this numbered business API inventory.

**API-version clarification:** `/v1/` in these route paths means the initial version of the new HTTP API contract. It does not refer to, depend on, or require a pre-existing TSG application. The solution, data model, prompts, threat-intelligence ingestion, retrieval pipeline, workers and tests are built from scratch.

**Important: API numbers are identifiers, not implementation order.** Build and verify API-client management (#20–#22) first, then the AI gateway, then the actual library-embedding/index and search pipeline. Build the embedding administration endpoints (#18–#19) later, after the admin-job infrastructure exists. Endpoint numbers do not mean embedding functionality should be implemented before authentication or before the search pipeline.

| # | Method/path | Purpose | Build dependency / key behaviour |
|---:|---|---|---|
| 1 | `POST /v1/sessions` | Start scenario-generation run | First business workflow; validates context, persists queued run and schedules threat job; returns 202; idempotent replay returns 200. |
| 2 | `GET /v1/sessions/{session_id}` | Read session status | Entity/tenant check; current counts and step; one indexed read. |
| 3 | `GET /v1/sessions/{session_id}/results` | List session scenarios | Pagination and documented replaced-version filter; returns total count. |
| 4 | `POST /v1/sessions/{session_id}/accept` | Accept selected/all scenarios | Atomic decision update; optional `replace_accepted`; cannot run while generation is queued/running. |
| 5 | `POST /v1/sessions/{session_id}/scenarios/reject` | Reject scenarios | IDs only; no reject-all; cannot conflict with acceptance. |
| 6 | `POST /v1/sessions/{session_id}/regenerate/scenarios` | Regenerate selected scenarios | New scenario version for each requested path; async 202. |
| 7 | `POST /v1/sessions/{session_id}/scenarios/next-set` | Generate next batch | Async 202; uses only already selected paths and never discovers new threats. |
| 8 | `GET /v1/sessions/{session_id}/events` | Stream session updates | SSE snapshot + `session.updated` messages; same identity checks. |
| 9 | `GET /v1/entities/{entity_id}/scenarios` | List entity scenarios | Validate path entity equals authorized scope; filters + pagination. |
| 10 | `GET /v1/sessions/{session_id}/scenarios/{scenario_id}` | Read one scenario | Entity/tenant and session/scenario relationship checks. |
| 11 | `POST /v1/remediation` | Request a plan | Accepted generated scenario or manual scenario; async 202; manual requests require `Idempotency-Key`. |
| 12 | `POST /v1/remediation/{remediation_id}/accept` | Accept a completed plan version | Default newest completed version; only one accepted version at a time. |
| 13 | `POST /v1/remediation/{remediation_id}/reject` | Reject a completed plan version | Atomic version decision; only one accepted version at a time. |
| 14 | `POST /v1/remediation/{remediation_id}/regenerate` | Create plan version | Async 202; preserves old versions and freezes source input. |
| 15 | `GET /v1/remediation/{remediation_id}/status` | Read plan status | Independent generation/review progress and current error. |
| 16 | `GET /v1/remediation/{remediation_id}/result` | Read plan result/history | Current/shown version, scenario summary, register, plan, schedule and warnings. |
| 17 | `GET /v1/remediation` | Search/list plans | Filters for session/scenario/status/decision/risk; paginated. |
| 18 | `POST /v1/embeddings` | Request index build/refresh | Admin key; `{scope: all\|threats\|controls\|actors\|techniques\|intel_summaries, recreate: false}`; returns 202 job ID. |
| 19 | `GET /v1/embeddings/{job_id}` | Index job status | Admin key; returns progress/result/error. |
| 20 | `POST /v1/tsg/api-clients` | Mint caller key | Admin key; plaintext secret returned once; only hash persists. |
| 21 | `GET /v1/tsg/api-clients` | List caller keys | Admin key; never returns secret or hash. |
| 22 | `POST /v1/tsg/api-clients/{client_id}/revoke` | Revoke a caller key | Admin key; repeat revoke is harmless; cache convergence ≤ 60 seconds. |
| 23 | `GET /v1/tsg/library/pending` | List pending threats | Admin key; pagination. |
| 24 | `POST /v1/tsg/library/decisions` | Approve/reject pending threats | Admin key; disjoint approve/reject IDs, max 100 total. |
| 25 | `POST /v1/tsg/jobs` | Start admin job | Admin key; library import, intel refresh or technique rebuild; one active job per kind. |
| 26 | `GET /v1/tsg/jobs/{job_id}` | Read admin job | Admin key; progress/result/error. |
| 27 | `POST /v1/sessions/{session_id}/scenarios/{scenario_id}/promote-to-library` | Promote accepted non-canonical AI/CTI threat candidate as a pending library entry | Standard business identity headers plus entity/tenant checks; accepted scenario and non-canonical candidate key required; supports `ai_gap_fill` and `cti_gap_candidate`; idempotent; creates only an inactive/pending record; never auto-promotes or activates on scenario acceptance. |
| 28 | `GET /v1/remediation/{remediation_id}/events` | Stream remediation status updates | SSE snapshot + `remediation.updated`; same identity/entity/tenant checks as remediation APIs. |

Operational endpoints: `GET /health` (process alive), `GET /ready` (stores and workers ready), `GET /metrics` (Prometheus exposition). These do not replace business API authorization decisions; deployment access to monitoring must follow §13 and the go-live checks in §14.4.

### 6.1 Core request/response contracts to lock before coding

**#1 Start run — request**
```json
{
  "asset_id": 103,
  "supporting_system_ids": [321, 322],
  "service_id": 5,
  "sector_id": null,
  "subsector_id": 12
}
```
Rules: at least one distinct system ID; count is bounded only by a positive `MAX_SUPPORTING_SYSTEMS` configuration if that setting is retained (current design value 0 means no upper limit); no duplicate IDs; optional context values must be valid and consistent. Respond `202 {"session_id":"…","status":"queued"}`. With a matching idempotency key and same resource, return `200` with the original session; key reused for a different request/resource returns 409.

**#2 Status** returns session ID, entity/asset, status, step, counts (`planned`, `written`, `remaining`, `failed`, `abandoned`, `accepted`, `rejected`, `pending`, `controls_waiting`), `path_search_status`, path-search stopping reason, coverage warnings, per-source freshness summary, plan note, last action, safe error and timestamp. A `budget_limited` plan must never be displayed as exhaustive.

**#3 Results** returns `{items: [Scenario], total: number}` with pagination and a documented option/filter for superseded/replaced versions. Apply entity/tenant filters in the database query, not after results are returned.

**#4 Accept** request: `{ "scenario_ids": ["…"] }` or `{ "scenario_ids": "all", "replace_accepted": false }`. Repeat requests should be idempotent when the requested final state already holds. A newer or older scenario version may be accepted according to the latest owner rule, but at most one version per path is accepted. If `replace_accepted` displaces the accepted scenario, any remediation plan that now refers to an unaccepted scenario becomes read-only; new plan requests for it return 409 `scenario_not_accepted`.

**#5 Reject** request: `{ "scenario_ids": ["…"] }`; list must be non-empty and ≤ 50, no reject-all. Accept and reject are mutually exclusive.

**#6 Regenerate** request: `{ "scenario_ids": ["…"] }` (1–50). Creates a new version per chosen path, keeps previous versions, records `replaces`, and returns `202 {"epoch": n}`. A conflicting in-progress write returns 409.

**#7 Next set** request `{}`. Writes up to six next eligible paths in frozen rank order. The request must atomically claim the next batch so two simultaneous calls cannot serve the same paths. A call after no eligible paths remain returns 409 `nothing_left`.

**#11 Remediation** request is either `{ "scenario_id": "…", ...optional register fields... }` for an accepted generated scenario, or `{ "manual_scenario": { ... }, ...register fields... }`. The latter requires `Idempotency-Key`. Return `202 {remediation_id, session_id, scenario_id, version, status}`; return 200 on safe replay. If controls are not ready, make a bounded top-up attempt; if none become available, return 503 `controls_not_ready`.

**#12/#13 Plan decisions** request `{ "version": 1, "comment": "…" }`; version may default to the newest completed version, and comment is capped at 2,000 chars. Only completed versions can be accepted/rejected; no more than one version may be accepted at any time.

**#14 Regenerate plan** request `{}`; creates a new version from the frozen register/snapshot input and returns 202 with version. It does not mutate past versions.

**#15/#16/#17** status, result/history and filtered list have one common response model; document pagination, enum values, current-vs-accepted version semantics, date format `YYYY-MM-DD`, and unknown-field behaviour in OpenAPI.

**#18/#19** index job creation/status contracts are admin-key protected and asynchronous. Allowed `scope` values are `all`, `threats`, `controls`, `actors`, `techniques`, and sanitized `intel_summaries`. Technique catalogue refresh/rebuild remains distinct from canonical library embedding refresh so each can be versioned and recovered independently; an OTX sync is an intelligence-refresh job (#25), not an embedding job.

**#20–#22** key management is admin-key protected. A key is returned once only; list/revoke never reveal it.

**#23–#26** pending-library and admin job requests are admin-key protected, bounded, and audited.

**#27 Promote** requires the relevant scenario to be accepted, creates or resolves a pending/inactive library threat/type via `tsg_ResolveThreat`, and returns an idempotent outcome. It must not automatically approve the new threat.

---

## 7. Business logic that must become code

### 7.1 Start-run workflow (API #1)

```text
receive request
  -> authenticate API key and identity headers
  -> validate schema, IDs, scenario-count setting and request-size limit
  -> validate entity/tenant, asset ownership, supporting-system links and optional context consistency
  -> call tsg_GetAssetContext and freeze returned asset/system/context snapshot
  -> check idempotency-key and active-run invariant atomically
  -> insert queued session with active=true, epoch=1, job.due_at and frozen context
  -> enqueue tsg_find_threats(session_id, epoch) (IDs only)
  -> publish initial status if needed
  -> return 202 with session ID
```

If SQL/Mongo/Redis is temporarily unavailable, return a suitable 503 or leave a durable queued job for the reaper to resend. Never return 202 when the durable session has not been created. Concurrent active-run creation must resolve to one 202 and one 409, not two active sessions.

### 7.2 Threat, threat-type and threat-actor identification — authoritative algorithm

This is the core decision pipeline. `ThreatFinder` owns the orchestration, but each operation below is a small, independently tested function. A threat is **not considered an actor-complete threat candidate** until its canonical/proposed threat, canonical threat type, selected library actor, affected systems, technique evidence and candidate-eligibility decision are bundled together. Do not set final `scenario_eligible=true` in ThreatFinder; that state is assigned only after PathPlanner validates the entire candidate path and its actor consistency. Actor resolution happens inside this same ThreatFinder stage immediately after the threat/type candidate is validated and deduplicated; it must finish **before the candidate is returned to PathPlanner**. It is not deferred until after attack-path construction or scenario writing. Path planning may subsequently validate whether the per-threat actor decisions are coherent across a multi-step chain, but it may not invent or choose an actor retrospectively. The LLM may judge applicability or propose a gap-fill candidate; **it must never invent a library ID, independently override a library threat's type/category, or create a threat actor**.

#### 7.2.1 Source-of-truth rules

| Field | Authoritative source | Rule |
|---|---|---|
| Asset, supporting-system and topology facts | Frozen `AssetContextProvider` snapshot, based on `tsg_GetAssetContext` plus optional approved configuration/topology sources | Analyse the asset and every supplied, asset-linked system. Freeze asset properties and any verified network, identity, trust-boundary, remote-access, data-flow or dependency edges with source and timestamp. Being listed as a supporting system does not prove reachability or trust. Unknown facts remain unknown; without topology evidence, do not construct cross-system paths as validated. |
| Exposure / attack preconditions | Frozen asset/system context only; optional vetted inventory inputs if the platform owns them | Use product/vendor/version, cloud/identity dependencies, external exposure, remote-access paths, system connectivity/trust boundaries, privilege, known CVEs and OT safety constraints only when recorded and current. If a fact is absent, mark it `unknown`; do not infer a vulnerable version, exposed service or reachable system from a name alone. Record context gaps as coverage warnings. |
| STRIDE category | `Threat_Catalogue_Category_Map` for a library threat; the category currently being assessed for a gap-fill proposal | For a library threat, use only categories actually mapped in SQL. The LLM cannot reclassify it. For gap-fill, code verifies the proposal belongs to the one category being assessed. |
| Threat | Active, non-deleted `Threat_Catalogue` record | Search and relevance-check canonical rows first. Preserve `ThreatCatalogueID` when selected. An AI proposal is explicitly marked `ai_generated`; it is not represented as an approved library record. |
| Threat type | The selected threat's canonical `ThreatTypeID` relationship to `Threat_Type` | **Never ask the LLM to choose a different type for an existing library threat.** Resolve the type by ID from the same snapshot and validate that it is live. An AI/CTI candidate must map to a live type at the calibrated match bar before path eligibility. Otherwise preserve it as a clearly labelled, non-canonical pending discovery item for curator mapping; it is not scenario-eligible because actor selection is constrained by canonical type-to-actor rules. |
| Threat actor | Active, non-deleted `Threat_Actor` row with `IsCapable=true`, using `ThreatType_ThreatActor_Map` where available | Every eligible scenario has one internal acting-actor reference from the eligible library. No LLM-created actor name may be persisted as the selected actor. Keep canonical actor ID for audit, but apply the display/attribution rule below before showing a named group to a user. |
| External actor attribution | ATT&CK group/software relationships, OTX/MISP or cited incident reports, through an explicit provenance link | External names are evidence/aliases only. A specific group may be cited as reported in a source only when the relationship is source-backed and attribution policy permits it. The scenario's canonical `acting_actor` remains a live TSG `Threat_Actor`, but that selection is a modeling choice rather than proof of real-world attribution. Never infer a named group solely from semantic similarity or an IOC. If no explicit source supports associating the specific group with the relevant technique/campaign, set `attribution_level=unknown`, set `actor_presentation=unattributed` (or `hypothetical_profile` only for a genuinely generic archetype), and omit the named group from scenario prose/UI. Keep the internal library ID for audit and deterministic processing. |

**Required stage order:** (1) freeze asset/system/topology context and the library/source version stamps; (2) retrieve candidate library threats by STRIDE; (3) resolve each candidate’s canonical threat type and reject invalid relationships **before** the LLM relevance gate; (4) run the relevance gate and complete the full category scan when required; (5) retrieve applicable ATT&CK/CAPEC/advisory evidence and map or form CTI candidates; (6) perform threat/type/evidence deduplication; (7) resolve actor fit and select the acting library actor **once for each surviving candidate**; (8) emit only actor-complete `candidate_eligible_for_path` bundles to path planning, while saving blocked candidates as pending with reasons; final scenario eligibility is assigned only by PathPlanner after complete-path validation; (9) validate path transitions, topology/preconditions, and actor continuity; (10) freeze/rank/select the path plan; (11) write scenario and risk statement; (12) validate and map controls. Canonical type resolution precedes relevance evaluation because the model may not repair or override the library relationship. Actor resolution is inside threat identification and finishes before path planning; path-level actor consistency can split/reject a chain, but scenario writing cannot choose or change an actor.

Only live/approved rows may be used as canonical candidates. Pending or curator-rejected rows are not selectable as approved threats/types/actors. Rejected wording must not be proposed again. Load the relevant tables and mappings as one versioned library snapshot; store its stamp with every run so a run is reproducible against the library version it actually used.

**New product rule for `Threat_Actor.IsCapable`:** this is a hard eligibility flag: only active, non-deleted rows with `IsCapable=true` may be selected; null is invalid master data and is excluded with a data-quality warning. For each candidate, evaluate active/capable actors linked to its canonical type first and require the configured actor-fit gate. If no linked actor passes that gate (including when no linked actors exist), evaluate the remaining active/capable library actors as a flagged fallback and set `closest_attacker=true` only if a fallback passes the same gate. Never relax `IsCapable`. If no active capable actor exists globally, fail the run with `actor_library_empty`; if the library has actors but none fits a candidate, keep that candidate pending and do not include it in a path. Actor-fit scores must be a calibrated 0–100 value from a versioned evaluation profile, not raw embedding cosine or an uncalibrated LLM self-rating. Set initial `CII_ACTOR_FIT_MIN_SCORE=75` for calibration/UAT, with required profile/source evidence; tune using labelled actor-fit pairs before production. If no approved actor profile exists, use only a direct type-to-actor link as a generic modelling association when the actor is explicitly categorized as a generic archetype; mark `actor_fit_basis=type_link_only`, and do not claim a real-world group’s behavior or attribution. A named actor without sufficient profile/source evidence remains ineligible. Implement these rules in one pure, unit-tested predicate and document them in the admin/library data dictionary.

#### 7.2.2 Ordered selection pipeline

**Step 1 — Freeze and validate the assessment scope.**
1. Read the asset/system context saved at run creation; do not re-query and silently change it during a run.
2. Construct a bounded landscape containing the asset, all supporting systems, and available service, sector, sub-sector and technology facts. Use the documented character budget and clipping rules. If clipping would leave a system with insufficient facts under the documented 150-character rule, stop with a clear `plan_refused` result; do not guess from a system name alone.
3. Assign stable prompt aliases (`SYS1`, `SYS2`, …) to system IDs. The LLM returns aliases only; code converts aliases to canonical IDs and later to plain system names.

**Step 2 — Enumerate all six STRIDE categories.**
1. Process Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service and Elevation of Privilege in the fixed order, regardless of whether the first categories return candidates.
2. For each category, create one search query for the asset and one for each supporting system. Include the category definition and the available sector/service context. Exclude IDs, date fields and yes/no flags from the search text. Clip each query to 1,500 characters.
3. Query only active library threat records mapped to that category. Apply the category/allowed-row filter **before** cutting the initial results to top 10 per asset/system query. The library search combines BM25 (k1=1.5, b=0.75) and cosine similarity over normalized vectors, then Reciprocal Rank Fusion (RRF, k=60). Merge results by canonical threat ID, keeping the best rank/score and the asset/system queries that retrieved it as evidence. The top 10 is an initial page, not a completeness guarantee: use the adaptive expansion rules in Step 5 when a result page is saturated, a system/category is uncovered, relevance is borderline, or duplicates collapse many candidates. After CTI retrieval, any relevant but unmapped technique/advisory triggers a separate full-library mapping search described in §7.2.6; it must not be treated as evidence that the initial top 10 was complete.
4. A threat mapped to more than one STRIDE category may be assessed under each mapped category, but it remains one canonical threat record during deduplication.

**Step 3 — Resolve the threat type before asking the LLM to judge relevance.**
For every retrieved library threat, resolve `ThreatCatalogueID → ThreatTypeID → ThreatTypeName` from the same snapshot. Confirm the threat, type and category mapping are all live and consistent. Build the AI candidate description as `ThreatTypeName: ThreatName` plus the allowed description/context. If the type FK is missing, points to a deleted/inactive row, or the category mapping is invalid, exclude that row from selection and add a `library_data_invalid` plan note/metric; never let the LLM repair the database relationship by guessing a type. A library threat's canonical type is immutable during this run.

**Step 4 — Run the relevance gate against the entire context.**
1. Batch candidate records into prompts that stay within 80% of the configured model input budget. Use the frozen asset plus all supporting-system facts, category definition, service/sector context, and candidate type/threat descriptions. Use temperature 0.0 for the gate.
2. Ask the model to assess each known candidate, returning strict JSON with `{slot, relevant, systems, reason, impact, confidence}`. It may refer only to supplied candidate slots and known system aliases. The reason must explain why the threat applies to this asset/system scope, naming the affected systems by alias; `relevant=true` requires a non-empty valid system list, reason, impact (`HIGH|MEDIUM|LOW`) and confidence (0–100). An empty platform field means **unknown**, not “no”.
3. Validate every answer in code: every slot exactly once; booleans/enums/ranges valid; IDs/aliases from the supplied set only; no unsupported STRIDE category; no system outside the run. Re-ask unreadable/truncated output using the documented AI retry policy (split a truncated batch in half). Do not trust model prose alone to establish a canonical ID.
4. Keep only candidates for which the validated gate says relevant. Store the reason, impacted system IDs, impact, confidence and the exact candidate/library evidence. Do not turn an LLM's confidence into a substitute for the relevance decision.

**Step 5 — Expand the library check before gap-fill and do not stop at the first relevant result.**
Use paged/adaptive retrieval for each category and each asset/system surface:
1. Resolve each candidate’s canonical `ThreatTypeID` and validate its active STRIDE mapping **before** sending it to the relevance model. Invalid relationships are excluded and recorded as `library_data_invalid`; the model cannot repair them.
2. Assess the first top-10 page. Continue to the next ranked, not-yet-assessed page when a page is saturated, a supporting system/category remains uncovered, multiple candidates collapse during deduplication, a relevant CTI technique/advisory has no mapped TSG threat, a calibrated relevance result is near the decision boundary, or other configured coverage checks signal a likely retrieval miss. Each external/canonical candidate ID is assessed once per frozen run/category.
3. If at least one relevant library threat is found, stop expansion only when all configured coverage conditions are satisfied and the stability rule (initially two consecutive pages with no new relevant candidates) is met, or when the candidate corpus is exhausted. If the configured search budget is reached first, keep validated candidates but mark `retrieval_status=budget_limited`, store the stopping reason, and show a coverage warning. Do not claim exhaustive threat coverage.
4. If **no** relevant library threat is found, continue assessing all remaining active threats for that category until the eligible category corpus is exhausted. Only this full scan can establish that the library has no relevant threat. If the budget or model failure prevents completing this full scan, do not call classic AI gap-fill.
5. Keep separate status fields: `relevance_assessment_status` (`complete|partial|not_assessed`), `retrieval_status` (`stable|corpus_exhausted|budget_limited|failed`), `coverage_status` (`bounded_by_policy|corpus_exhausted|budget_limited|incomplete`) and `category_full_scan` (boolean). A gate failure after retries marks the affected work incomplete; do not treat it as an empty result. Preserve any previously validated relevant candidates, but surface partial coverage and do not infer that missing candidates are irrelevant. `retrieval_status=stable` means the configured stopping criteria were met, not that the entire library was exhausted; the user-facing run must not claim exhaustive catalogue coverage unless `category_full_scan=true` for that category.

A category that is `not_assessed` or `partial` is not an empty category. A category stopped by the stability rule is also not necessarily corpus-exhausted. Classic AI gap-fill may run at most once only when no relevant library threat or validated CTI gap candidate exists **and** `category_full_scan=true`. This avoids filling missing coverage or a model outage with an unverified AI threat. The CTI adapter/retrieval pass may still contribute independently validated evidence candidates during partial library coverage, but it must not cause the system to claim that the canonical library was fully assessed.

**Step 6 — Use AI gap-fill only for a genuinely empty relevant category.**
For a category whose full library scan completed and found no applicable library threat, make at most one `gap_fill` call. Pass the same frozen asset/system context, category definition, and the fact that all live candidates were assessed. Require `{applies, threat_type, threat, attacker, systems, reason}`; apply the 3,500-character limit and the same strict schema, alias and system validation. Reject `applies=false`, a category change, unsupported systems, empty/unsupported reason, or malformed output. Never request gap-fill to reach `TOTAL_SCENARIO_COUNT`.

Then, in order:
1. Normalize the proposed threat name (lowercase, remove punctuation, collapse whitespace) and compare it with live, pending and curator-rejected library wording. If an approved library threat is a near-duplicate at the documented match bar (75/100), reject the proposal as redundant. If a wording was curator-rejected, do not propose it again.
2. Match the proposed threat type to the live type library with the calibrated 75/100 initial match bar. If matched, replace the proposed type text with the canonical type ID/name. If no match exists, keep the proposal as `pending_untyped_candidate` for review only; do not pass it to path planning or scenario writing, and do not create or activate a SQL type during scenario generation.
3. Run the proposed threat through the same relevance gate once, in the category and scope supplied. If it does not pass validation and relevance checks, discard it and record a plan note. Do not repeatedly generate alternatives.
4. If a canonical type is resolved, record that the candidate is type-valid but leave `acting_actor_id` unresolved. Do not pick an actor in the gap-fill function. The final actor-resolution pass runs only after global threat/candidate deduplication. For the gap-fill decision, count this proposal as a validated CTI/AI threat candidate only if its threat/type/evidence/system preconditions pass; an actor is not assigned at this point. The final resolver will either assign an eligible library actor or place the candidate in pending state. **Never persist the LLM's suggested actor as the selected actor.**
5. Mark the threat `ai_generated=true`, with no canonical threat ID. After the single post-deduplication actor-resolution pass, only candidates with a valid canonical type, one valid library actor and passing relevance/evidence checks may be flagged `candidate_eligible_for_path=true`. PathPlanner must still validate the complete path before it sets `scenario_eligible=true`. Other candidates remain in the pending curation record. Promotion to the threat library is a separate explicit action after human acceptance; any new threat/type is written inactive/pending and requires curator approval.

**Step 7 — Deduplicate validated threats before path planning.**
Apply in this order:
1. Merge identical canonical library IDs. Merge non-canonical candidates by normalized name only when their canonical type IDs match or a reviewed type-equivalence/alias record permits the merge.
2. If an AI proposal's normalized name equals a live library threat name, compare the canonical type IDs before deduplication. If the type matches or a reviewed type-equivalence/alias record permits the match, retain the canonical library record and merge only the validated additional evidence. If the proposed type conflicts and no reviewed equivalence exists, do not merge or bind the proposal to the library row; mark `potential_duplicate_type_conflict`, retain the canonical row unchanged, and send the proposal to pending review. Never silently overwrite a canonical type.
3. Compare AI proposals with library threats and earlier AI proposals by embedding cosine; cosine ≥ 0.98 is only a duplicate signal. Merge only when type compatibility is established; otherwise mark `potential_duplicate_type_conflict` and retain separately for path-level assessment.
4. For threats sharing at least one affected system, use one constrained `same_attack` LLM check to identify semantically identical attacks that text/embedding checks did not resolve. The model can group supplied slots only; code validates the result and enforces the same type-compatibility rule.
5. Select the survivor deterministically for a valid merge: canonical library record first, then the lowest canonical ID/stable key. Do not prefer a candidate based on a presumed actor mapping here because actor-fit resolution has not happened yet. Merge source/evidence references without changing the survivor's canonical type or primary category; union system IDs and STRIDE categories only where the surviving type/category relationships remain valid. Record every removed key, survivor key and deduplication reason.

Do not merge different attack concepts merely because they share a STRIDE category or system. If canonical type IDs differ and there is no reviewed equivalence/alias record, keep the candidates separate and let path-level validation/deduplication decide whether their completed paths are duplicates. Do not discard one candidate merely because the other has a type-linked actor; actor selection occurs after this deduplication stage.

**Step 8 — Complete each surviving threat candidate with its actor (still inside ThreatFinder).**
This is part of threat identification, not a later scenario-generation phase. The `ThreatFinder` result contract must not expose a `candidate_eligible_for_path=true` candidate without its resolved acting actor and actor-evidence fields. A candidate does not become a scenario-eligible path until PathPlanner validates transitions, preconditions, topology and path-level actor consistency.
1. If the live actor library contains no active rows with `IsCapable=true`, fail with `actor_library_empty` before building paths. Do not make an AI call to invent a substitute.
2. For a library threat whose type has linked active, capable actors, evaluate **all** mapped actors—not just a global top-k—using `LibrarySearch.find_actors` with the allowed-row mask restricted to active, capable type↔actor links. Query text is `"<canonical type>: <threat>. <relevance reason> <sector>"`; include reviewed actor-profile/capability data and source-backed technique/group associations when available. If an eligible mapped actor is absent from search output, append it in stable library order so no allowed candidate silently disappears. For each candidate, combine retrieval/reranker ranking with the calibrated actor-fit gate and retain evidence for the fit decision. Select the highest-ranked candidate that passes the fit gate, with canonical actor ID as the stable tie-break. A type↔actor link establishes eligibility, not proof that the actor is a real-world attacker or that its documented TTPs fit this path. If no mapped actor passes the gate, continue to the fallback step below.
3. Keep an alternate only if it is active/capable, eligible for the canonical type, and independently passes the calibrated actor-fit check using an approved actor profile and/or applicable source-backed TTP evidence plus the threat, sector and technique context. Actor-name embedding similarity may retrieve or order candidates, but it is never sufficient to qualify an alternate. If actor profile/capability evidence is unavailable, a type link may be used as `actor_fit_basis=type_link_only` only for a generic archetype. If more than one generic linked actor remains indistinguishable without profiles, do not choose arbitrarily; keep the threat candidate pending with `actor_profile_insufficient`. Named actors without adequate profile/source evidence remain ineligible. Add `actor_alternates_unverified` when alternates cannot be evaluated.
4. If no type-linked actor passes the actor-fit gate—including when the type has no linked actor—retrieve up to three highest-ranked **remaining active, capable** library actors across the library and use one constrained `attacker_fit` call to assess only those supplied IDs. Validate the chosen ID against that list. A fallback actor must independently clear `CII_ACTOR_FIT_MIN_SCORE`; an unusable model answer may fall back to the highest deterministically ranked candidate only if its separately computed calibrated fit score clears the same bar. Otherwise keep the threat candidate pending and do not assign an actor. Flag `closest_attacker=true` for an accepted fallback. `IsCapable=false` and null are never eligible for fallback.
5. Gap-fill and CTI-gap candidates go through this same single actor-resolution pass after deduplication. Do not pre-select an actor in the gap-fill/CTI builder, and never substitute the AI's free-text actor.
6. Each threat leaving this step as `candidate_eligible_for_path=true` must have exactly one `acting` actor with a valid library actor ID; store every additional fit-qualified actor candidate as an `alternate` with its own score/evidence. If none fits, the candidate is pending and `candidate_eligible_for_path=false`. The path planner receives only actor-complete path candidates, and the scenario writer receives only a fully validated path; neither can introduce arbitrary actor names from a model response.

**Step 9 — Resolve actors consistently for a multi-threat scenario.**
Each threat step retains its selected acting actor, the other actor IDs that independently passed its fit gate, and the evidence for each decision. Before accepting a multi-step path as one adversary chain, intersect the **validated per-step actor-candidate sets**. If a common actor exists, choose deterministically: prefer a common actor that passed the initiating-step gate, otherwise choose the common actor with the highest aggregate calibrated fit score, breaking ties by canonical actor ID; record `path_actor_resolution_reason`. This path-level consistency check happens in PathPlanner before scenario writing and may choose only from already validated per-step actor sets—it cannot invent an actor or bypass per-threat eligibility. If the intersection is empty, split the path into independent candidates unless a source-backed handoff/cooperation edge is explicitly validated; if no defensible split or handoff exists, reject the chain. If credible source evidence supports multiple cooperating groups, store them only as separately provenance-linked `associated_actor_refs`; do not imply cooperation without evidence. A specific named group is displayed as source-attributed for the whole path only when source evidence supports that group’s relationship to the relevant ordered behavior sequence or to all material steps being attributed; an association with one isolated technique is not enough to attribute the entire chain. If evidence applies only to one step, scope the attribution to that step; otherwise set `actor_presentation=unattributed` and do not show the group name as a fact. Add fixtures for same-actor paths, incompatible step actors, source-backed handoffs, no entry point, and uncertain attribution.

**Step 10 — Return an auditable, actor-complete threat plan to PathPlanner.**
`ThreatFinder` may return only after all eligible candidates have a validated acting actor. PathPlanner receives a complete bundle and performs path-edge/precondition and cross-step actor-consistency checks; the scenario writer receives the already-validated path and must never run actor selection itself.

Every surviving threat object must contain at minimum:

```json
{
  "threat_key": "stable key",
  "source": "library | ai_gap_fill | cti_gap_candidate",
  "candidate_key": "stable non-canonical key or null",
  "threat_id": 297,
  "threat_name": "Vendor remote access compromise",
  "threat_type_id": 12,
  "threat_type_name": "Remote Access Abuse",
  "type_source": "library | canonical_match | proposed_untyped",
  "candidate_eligible_for_path": true,
  "candidate_stage_status": "actor_resolved",
  "eligibility_blockers": [],
  "primary_stride_category": "Tampering",
  "stride_categories": ["Tampering"],
  "affected_system_ids": [321],
  "reason": "The vendor VPN is in scope and can reach the SCADA environment.",
  "impact": "HIGH",
  "confidence": 84,
  "actors": [{"actor_id": 5, "name": "Organised crime group", "actor_kind": "generic_archetype", "role": "acting", "closest_attacker": false, "actor_fit_basis": "type_link_only", "fit_score": null, "fit_evidence_refs": [], "profile_version": null}],
  "external_actor_attribution": {"source_attributed_group_id": null, "evidence_refs": [], "presentation": "unattributed"},
  "technique_refs": ["Txxxx", "CAPEC-xxx"],
  "evidence": {"library_stamp": "…", "catalogue_stamps": {}, "source_refs": [], "edge_refs": [], "retrieved_by": ["asset", "system:321"], "prompt_version": "…", "model": "…"}
}
```

For AI gap-fill and CTI gap candidates, `threat_id` may be null; a path-planning candidate must have a stable `candidate_key`, a live canonical `threat_type_id`, one selected live `actor_id`, validated source evidence/preconditions and candidate-level relevance. Keep `source=ai_gap_fill` or `source=cti_gap_candidate` explicit even when its type matches the library. An untyped or actor-ineligible candidate has `candidate_eligible_for_path=false` and a recorded blocker; it may appear in an admin pending-discovery queue but cannot seed a path. **Only PathPlanner** sets `path_eligible=true` and `scenario_eligible=true`, after all edges, preconditions, topology, objectives and path-level actor checks pass. If an actor or path gate fails, scenario eligibility remains false. Scenario eligibility does not mean canonical-library promotion. Every non-canonical candidate needs a deterministic `candidate_key` so audit/curation never depends on a null canonical ID. IDs shown above are illustrative. The `actors` array contains exactly one `acting` actor plus zero or more independently fit-qualified `alternate` actor candidates; PathPlanner intersects those validated actor IDs across steps. The example `confidence` field means the calibrated candidate-relevance score only; it is not a breach probability or proof of source attribution. The example is a pre-path threat bundle, so it contains `candidate_eligible_for_path`, not final `scenario_eligible`; PathPlanner adds final path eligibility after graph/actor validation. Store source reliability, recency, asset applicability, sequence support and attribution strength as separate dimensions, alongside retrieval ranks/scores and deduplication evidence in the run/audit trace, not in user-facing prose. Convert `SYS#` aliases to real names in code before exposing reasons.

#### 7.2.3 Reference pseudocode

```python
def find_threats(frozen_context, library_snapshot):
    require_live_actor_library(library_snapshot)  # else actor_library_empty
    landscape = build_bounded_landscape(frozen_context)
    accepted = []
    pending_discoveries = []
    for category in STRIDE_ORDER:
        scan = adaptive_library_threat_scan(
            landscape=landscape,
            category=category,
            library_snapshot=library_snapshot,
            initial_top_k=10,
            # Scan resolves each threat type/mapping before the relevance gate,
            # pages candidates adaptively and returns explicit coverage status.
        )
        if scan.relevance_assessment_status == "not_assessed":
            mark_not_assessed(category, scan.coverage_warning)
            continue
        relevant = scan.validated_relevant_candidates
        save_library_scan_status(category, scan.status, scan.coverage_warning)
        # Never call classic gap-fill unless category_full_scan is true.
        # Retrieve source-backed modern techniques/advisories after the initial/adaptive
        # library scan. A stable/budget-limited scan is not corpus-exhaustive; source
        # evidence can still create a separately validated CTI gap candidate.
        intel_hits = retrieve_techniques_and_advisories(landscape, category)
        mapped, novel = validate_intel_hits_and_map_to_tsg(intel_hits, library_snapshot, landscape, category)
        # A CTI-to-library mapping is a retrieval clue, not proof that the threat
        # applies to this asset. Every mapped candidate must pass the same
        # asset/category-specific relevance and evidence gates before merging.
        mapped_assessments = assess_mapped_intel_candidates(
            mapped, landscape, category, library_snapshot, relevance_gate
        )
        for assessment in mapped_assessments:
            if assessment.status == "relevant":
                relevant = merge_or_add_validated_canonical_candidate(
                    relevant, assessment.canonical_candidate, assessment.evidence_refs
                )
            elif assessment.status == "unusable":
                pending_discoveries.append(mark_candidate_ineligible(
                    assessment.candidate, assessment.reason or "mapped_cti_assessment_unusable"
                ))
            else:  # irrelevant is rejected/audited, not eligible for path planning
                record_candidate_rejection(assessment.candidate, assessment.reason or "mapped_cti_not_applicable")

        # Novel behavior can be a non-canonical candidate even if a generic
        # library threat already exists; no automatic master-library writes.
        cti_candidates = build_cti_gap_candidates(novel, library_snapshot, landscape, category)
        for c in cti_candidates:
            # Step A: validate identity/type/source-rights/evidence/preconditions.
            # This function must not choose an actor or set path/scenario eligibility.
            if not pre_actor_candidate_valid(c):
                pending_discoveries.append(mark_candidate_ineligible(c, "pre_actor_validation_failed"))
                continue
            # Step B: require a separate structured relevance decision for this
            # asset and STRIDE category. A source match or embedding score alone
            # cannot qualify a CTI candidate.
            cti_verdict = validate_relevance_gate_result(
                relevance_gate([c], landscape, category), [c], landscape, category
            )
            if cti_verdict.status == "relevant":
                relevant.append(attach_validated_relevance(c, cti_verdict))
            elif cti_verdict.status == "unusable":
                pending_discoveries.append(mark_candidate_ineligible(
                    c, cti_verdict.reason or "cti_relevance_assessment_unusable"
                ))
            else:  # irrelevant: exclude and keep an audit rejection, not a scenario
                record_candidate_rejection(c, cti_verdict.reason or "cti_candidate_not_applicable")
        # Keep classic LLM gap-fill as the last resort only when the full library
        # scan found no relevant canonical threat and no validated CTI candidate.
        if not relevant and scan.category_full_scan and scan.relevance_assessment_status == "complete":
            proposal = one_gap_fill(landscape, category)
            proposal = validate_and_match_threat_type(proposal, library_snapshot)
            if proposal and pre_actor_candidate_valid(proposal):
                gap_verdict = validate_relevance_gate_result(
                    relevance_gate([proposal], landscape, category), [proposal], landscape, category
                )
                if gap_verdict.status == "relevant":
                    relevant.append(proposal)
                else:
                    pending_discoveries.append(mark_candidate_ineligible(proposal, gap_verdict.reason))
            elif proposal:
                pending_discoveries.append(mark_candidate_ineligible(proposal, "pre_actor_validation_failed"))
        accepted.extend(relevant)
    unique_threats = deduplicate_with_audit(accepted, library_snapshot)
    # Deduplicate blocked/pending discoveries across categories and against the
    # final candidate set before persisting the curator queue.
    unique_pending = deduplicate_pending_discoveries(pending_discoveries, unique_threats)
    # Assign actors exactly once, after the final candidate survivors are known.
    # The resolver returns path candidates and pending candidates with blockers.
    actor_results = resolve_and_validate_actors(unique_threats, landscape, library_snapshot)
    save_pending_discovery_items(unique_pending + actor_results.pending_candidates)
    assert_all_path_candidates_have_acting_actor(actor_results.path_candidates)
    return actor_results.path_candidates
```

Implementation note: the pseudocode is the orchestration outline; implement each named helper as a typed, unit-tested contract. `assess_mapped_intel_candidates()` must return one result per proposed CTI-to-library mapping with a canonical candidate, evidence references and a `relevant|irrelevant|unusable` verdict against the frozen asset context and STRIDE category. `merge_or_add_validated_canonical_candidate()` must merge evidence into an existing candidate by canonical identity or add the already-validated canonical candidate if retrieval did not find it; it must never merge on text similarity alone. `attach_validated_relevance()` stores the verdict, reason and assessment/profile version. `record_candidate_rejection()` writes a non-servable audit outcome with a stable candidate key and reason. `pre_actor_candidate_valid()` must validate canonical type, candidate identity, category/system IDs, source-rights status, evidence references and required preconditions, but **must not** choose an actor or set `candidate_eligible_for_path` until a separate schema-validated relevance/evidence gate passes; it must not set `scenario_eligible`. Relevance gates must distinguish `relevant`, `irrelevant` and `unusable` rather than reading a raw boolean from an unvalidated model response. Collect pending records during the category loop; run `deduplicate_pending_discoveries()` once against the final candidate set before persisting the curator queue. `resolve_and_validate_actors()` runs once after candidate deduplication and returns actor-complete `path_candidates` plus actor-ineligible candidates with blockers. Path candidates may enter PathPlanner but are not yet scenario-eligible. The actual functions must return typed result objects containing assessment state (`assessed`, `not_assessed`), validated records and evidence; a plain empty list must never conflate “no applicable threat” with “assessment failed.” `TOTAL_SCENARIO_COUNT` is applied later by path selection, **after** threat finding, path construction, validation and ranking.

#### 7.2.4 Worked example

Asset `103` is a grid control centre; supporting systems are `321` (SCADA historian) and `322` (remote access VPN). Under **Tampering**, hybrid retrieval finds these records:

| Candidate | Library relationship | Relevance-gate outcome | Result |
|---|---|---|---|
| `Vendor remote access compromise` | Type `Remote Access Abuse`; mapped to Tampering; canonical ID `297` | Relevant to system `322`, reason cites vendor-managed VPN; high impact | Keep threat ID 297 and its canonical type ID. Then rank actors linked to `Remote Access Abuse`. |
| `Generic server outage` | Type `Availability Failure`; not mapped to Tampering | Not eligible in the Tampering search | It is not permitted to enter this category's candidate set. |
| `SCADA command manipulation` | Type `Command Integrity`; mapped to Tampering | Irrelevant because the supplied context does not show a command-write path | Reject it; do not keep it simply because the category matches. |

If no library threat passes and every live Tampering threat has been assessed, one gap-fill call may propose a missing threat. Code checks duplicates and resolves the proposal’s type to a live canonical type where possible. It must not select an actor at this point: actor selection runs once, after the final deduplication pass. An unresolved type stays explicitly AI-proposed and cannot enter path planning; the final actor resolver must select a live eligible library actor or leave the candidate pending. If the library scan failed or remained incomplete, the category is `not_assessed`/`partial` and classic gap-fill is skipped.

#### 7.2.5 Mandatory tests for this algorithm

- Every STRIDE category is evaluated in fixed order; every supporting system plus the asset produces a query.
- Category scope is applied before top-k; candidate IDs always refer to live library rows.
- A library threat always returns the type linked by its canonical type ID, regardless of what the LLM says.
- A threat with invalid/deleted type or category mapping cannot be selected.
- Canonical type/mapping is validated before every relevance call; a threat discovered beyond the initial top-10 can be recovered by adaptive paging. Mapped CTI evidence never bypasses asset/category relevance assessment, and novel CTI candidates must pass source-rights, evidence/precondition, canonical-type and schema-validated relevance gates before actor resolution. Irrelevant candidates are audibly rejected; unusable assessments remain pending and cannot seed paths. If no candidate is relevant, all remaining active rows in that category are assessed before classic gap-fill; budget-limited or partial scans cannot trigger classic gap-fill.
- A category that fails assessment is `not_assessed`, not empty; gap-fill is not run for it.
- At most one gap-fill proposal per fully assessed empty category; no generation to satisfy the scenario count.
- Threat-name/type/actor matching at the documented 75/100 threshold; curator-rejected names are not proposed again.
- Relevance gate cannot introduce unknown system IDs, candidate IDs or a different STRIDE category.
- Duplicate library IDs, normalized names, cosine ≥ 0.98 and same-attack checks are deterministic and auditable; candidates with different canonical types are not merged unless an approved type-equivalence record exists. Test conflicting type IDs and verify path-level duplicate handling.
- Every `candidate_eligible_for_path=true` candidate returned by `ThreatFinder` has exactly one valid active/capable library acting actor and evidence. Actor selection runs once after deduplication and before PathPlanner. Test that final `scenario_eligible=true` is not set until PathPlanner validates the entire path and actor consistency. No active capable actors causes `actor_library_empty`; type-invalid rows never reach the relevance model.
- Linked-actor ranking restricts results to active/capable IDs linked to the canonical type; the acting actor must pass the calibrated actor-fit threshold; if no linked actor passes, the flagged fallback is evaluated. Alternates require cosine ≥ 0.80 **and** an independent fit/evidence check.
- No-linked-actor/no-fit fallback validates `attacker_fit` IDs against the offered top three, requires the same calibrated actor-fit threshold and sets `closest_attacker` when needed. If no candidate passes, it remains pending. Gap-fill and CTI builders must not preselect actors; assert actor resolution runs only after deduplication.
- A mapped CTI candidate and a novel CTI candidate each require an explicit asset/category relevance verdict and validated evidence before entering the candidate set; a source/embedding match alone cannot qualify them. Irrelevant results are excluded with an audit rejection, unusable verdicts remain pending, and neither can be passed to PathPlanner.
- Scenario-level actor resolution is deterministic and has unit fixtures covering same/different per-step actors, one actor fitting every step, no common actor (split/reject), a source-backed handoff, uncertain attribution, and missing entry-point evidence. The path-level actor must come from the intersection of per-step actor candidates that independently passed the fit gate; otherwise split/reject.
- Given the same frozen context, library stamp, validated AI verdicts and model/prompt versions, deduplication and actor tie-breaks return the same canonical result.
- Full threat plan records library stamp, prompt/model versions, retrieved candidate IDs/ranks, relevance decisions, affected systems, type/actor resolution, and deduplication decisions for audit.

#### 7.2.6 Threat intelligence and adversary-technique integration — required before scenario generation is accepted

A prompt-only design that supplies a small external-intelligence block only to the writer is insufficient for the requirement: a technique catalog must influence candidate discovery, relevance evidence, attack-path construction, scenario wording and control mapping. Implement this module before accepting Steps 10–13 in §8.

**Source strategy (use adapters, not one giant scraper)**

| Source | What it contributes | How TSG must use it | Trust / limitation |
|---|---|---|---|
| MITRE ATT&CK Enterprise + ICS; Mobile only if in scope | Tactics, techniques/sub-techniques, platforms, group/software/campaign relationships, observed procedures, mitigations and detection guidance | Primary behavioral catalogue; load official STIX 2.1 release bundles or TAXII; retain release, source IDs and relationships | A technique describes observed behavior, not proof it will work on this asset or be used in a specific sequence. Do not infer an ordered chain from tactic order alone. |
| MITRE CAPEC | Reusable attack patterns, prerequisites, required resources and consequences; related patterns | Enrich behavior descriptions and preconditions; link to ATT&CK and known TSG threats where justified | A pattern is a possible method, not proof of current activity or asset exposure. |
| CISA KEV | CVEs known to have been exploited in the wild | Match only when the asset/system product, vendor and version or a verified CVE are known; elevate relevance/urgency, not automatically the probability of a breach | KEV membership alone does not prove the assessed asset is affected or exploitable. |
| NVD CVE/CPE API 2.0 | CVE descriptions, severity metrics, affected-product applicability and CPE relationships | Incrementally enrich CVEs and verify vendor/product/version applicability. Use modified-date windows and pagination; maintain an optional API key for higher throughput and respect current rate limits | A CVE title or fuzzy product-name match is not enough to claim a product is affected. Validate version ranges and store the source timestamp/schema version. |
| FIRST EPSS | Daily score estimating the probability that a published CVE will be exploited in the wild over the next 30 days | Use to prioritize a CVE already shown to apply to the asset; persist the score date/version. Use daily dataset exports for bulk refresh and the API for a small set of known CVEs | EPSS is not the probability that this asset will be breached and does not prove exposure, exploitability or an active attack. It must not replace asset applicability checks. |
| CISA cybersecurity/ICS advisories, CSAF and vendor security advisories | TTPs, incident/campaign narratives, affected products/versions, mitigations and OT-specific warnings | Extract referenced ATT&CK techniques, product/CVE relationships, stated preconditions and procedure sequences. Use a bounded parser with source citations; match exact product/version for vulnerability claims | An advisory may describe an attack observed elsewhere. Do not imply that the assessed asset was targeted. Never invent a product/version match; respect OT safety constraints. |
| AlienVault OTX | Subscribed pulses, pulse descriptions/references/tags, indicators and community campaign context | Build and test the adapter in the first CTI release, but keep production ingestion disabled until the provider’s current terms explicitly authorize the intended commercial/internal service use and required retention/vectorization. Once legally approved, ingest asynchronously; use pulse behavior descriptions/references for evidence candidates and typed IOCs for exact matching only. Never use an IOC alone to create a threat actor or ordered path. | OTX is a community threat-intelligence service; its API access and open-source SDK do not mean every pulse is authoritative or that all data may be redistributed without restriction. Keep the key in secret storage and validate current provider terms. |
| MISP / approved OSINT feeds | Structured threat events and indicators; can aggregate multiple feeds | Optional connector, restricted to an approved feed allow-list; keep the originating feed and object identity to avoid double-counting an event copied through MISP and OTX | A feed aggregator is not an independent corroborating source merely because the same item appears in several feeds. |
| UAE Cyber Security Council / approved sector reports, UAE/sector advisories, internal incident and SOC evidence | Regional and sector relevance; local techniques and observed attack routes | Ingest official/approved documents with publisher/date/sector; use analyst-reviewed extraction if no stable API/feed exists; preserve the original URL/document hash and page/section references | Do not claim an attack is UAE-specific just because the source is global or an IOC geolocates to the UAE. Internal data must be tenant-scoped and permissioned. |
| MITRE EMB3D / ATLAS, where relevant | Embedded/IoT threat knowledge or AI/ML threat techniques | Enable based on asset domain (embedded/IoT or AI/ML platform); map through the same provenance, mapping and review pipeline | Domain-specific catalogues are not a replacement for Enterprise/ICS ATT&CK and do not apply to every asset. |
| PyTM, Threat Composer packs and other pattern libraries | Supplemental threat-model patterns | Optional, separately versioned supplemental import after license/terms, quality and schema review | Treat them as modeling references, not live threat feeds or proof of real-world use. |

Start with ATT&CK Enterprise + ICS, CAPEC, CISA KEV/cybersecurity/ICS advisories, NVD CVE/CPE enrichment and FIRST EPSS. Build and test the OTX adapter in the initial CTI release because a key is available, but keep it disabled in any commercial product/service deployment until written provider authorization or a suitable commercial agreement covers the intended use. The current OTX End-User Agreement describes OTX as free to end users for non-commercial use and contains use limitations against commercial exploitation and third-party service use; possessing an API key is not permission for those uses. The adapter can be enabled only after the legal/procurement source gate marks the use approved. Enable MISP, abuse.ch community APIs, UAE/sector reports, EMB3D and ATLAS only after source governance, asset-domain need and provider-specific use terms are confirmed. Source URLs and adapter configuration are deployment-controlled allow-list entries, not caller/model input. MITRE publishes ATT&CK in STIX 2.1 release collections and provides a TAXII option; CAPEC publishes downloadable attack-pattern catalogs. NVD provides its current CVE/CPE APIs in version 2.0, and FIRST publishes EPSS data daily. See the source links at the end of this guide.

**Commercial-use, retention and redistribution gate**

A public URL or a free API key is not by itself a data license. Before any live feed is fetched or ingested in any environment (including local development and UAT), record `terms_url`, `data_license`, `attribution_required`, `commercial_use_review`, `retention_allowed`, `vectorization_allowed`, `redistribution_allowed` and reviewer/date in `tsg_intel_feeds`. Use these feed states: `approved` (live ingestion/indexing is permitted for the recorded scope), `conditional` (no live requests or ingestion in any environment until the stated conditions are resolved; fixtures/mocks may be used for tests), and `blocked` (must not be ingested). Apply approval at source + use-scope level; approval for one environment or purpose does not automatically approve a different purpose or redistribution. Do not embed, retain or redistribute source content if the applicable terms do not permit it; store only allowed metadata or a link when appropriate. Review source-specific terms with the responsible legal/procurement owner; this implementation guide is not a legal opinion.

- MITRE ATT&CK and CAPEC publish royalty-free terms for research, development and commercial use subject to reproducing the required notices. Preserve their attribution and version/URL.
- CISA/NVD/EPSS are suitable core public sources, but preserve source links/timestamps and check notices for individual third-party reports or references included inside records.
- OTX requires a stricter gate: the current [OTX End-User Agreement](https://www.levelblue.com/legal/otx-eula-terms) says OTX is free to end users for non-commercial use and lists restrictions on commercial exploitation/third-party service use. Keep `CII_OTX_ENABLED=false` for a commercial TSG deployment unless the provider gives written permission or an appropriate commercial agreement covering the specific API, data retention, vectorization and service use. A working key and the open-source SDK do not establish that permission. Review both the current terms and any written agreement at deployment time.
- The abuse.ch Community APIs (including ThreatFox, URLhaus and MalwareBazaar) currently document free access under fair-use principles while noting that commercial/for-profit usage may require an enhanced paid subscription. Do not make these feeds a production dependency until usage is cleared for this use case.
- MISP is open-source software (AGPL-3.0); that software license does not automatically license the third-party data in each MISP feed. Approve each feed independently.

**Build the ingestion and index pipeline in this exact order**

1. **Create source adapters and registry.** Implement `IntelFeedAdapter` per source with `fetch`, `validate`, `normalize`, `checkpoint` and `health` methods. Use HTTPS, 30-second timeouts, response and decompressed-size limits, archive member/count/expansion-ratio limits, allow-listed hosts, bounded retries, content-type/schema checks and safe parsing. For XML, disable DTD/external-entity resolution; for archives, reject path traversal and unexpected file types. Avoid arbitrary redirects/SSRF; reject unexpected hosts after redirects. Never download/execute binaries or follow prompt-provided URLs.
2. **Normalize with full provenance.** Normalize records into `tsg_intel`/`tsg_techniques` while preserving original source, external object ID, release/version, title, source URL, published/modified/fetched times, first/last seen, publisher, confidence, content checksum and parser version. Keep actor/technique/CVE/product references as explicit fields. A record with a broken schema goes into an import error report, not the active catalogue.
3. **Deduplicate and handle revocation.** Upsert idempotently on `(source_id, external_object_id)` and compare checksums. Deduplicate cross-source records only as a correlation/cluster; retain every original provenance record. Respect revoked/deprecated ATT&CK/CAPEC entries and revised source objects. Do not count the same pulse syndicated by three feeds as three independent observations.
4. **Snapshot before activation.** Build each refresh in staging or a new versioned snapshot. Validate record/relationship counts and a sample of IDs/links, create embeddings and indexes, then atomically activate the new stamp. On failure retain the previous valid snapshot and report the feed failure. Never serve a half-built index. Save stamps such as `{attack_enterprise_release, attack_ics_release, capec_release, kev_modified, advisory_stamp, otx_cursor_or_stamp, parser_version, embedding_model}` on every run.
5. **Build the technique search corpus.** Embed the normalized technique/pattern name + behavior summary + prerequisites + platform, excluding volatile timestamps and raw IOC lists. Index text in BM25 and vectors in the new hybrid-search module built in Step 6; apply platform/domain and source-status filters before top-k, then RRF and the configured reranker. Cache vectors by `model + corpus + normalized-text hash`. Add `techniques` and, only for sanitized summaries, `intel_summaries` to `POST /v1/embeddings` scopes. Technique refresh invalidates only the affected corpus. Validate dimensions and candidate identities as in Step 6.
6. **Create explicit, reviewable crosswalks.** Store mappings from ATT&CK/CAPEC objects to TSG threat IDs/type IDs and STRIDE categories in `tsg_technique_mappings`. Existing source relationships can support a mapping, but a semantic match is only a proposed link. Record `mapping_method`, score, evidence and `status=candidate|reviewed|rejected`; an analyst/curator must review mappings used as authoritative category crosswalks. ATT&CK does not define STRIDE; do not imply that a generated mapping is an official MITRE mapping. Do not write these mappings into canonical SQL tables automatically.
7. **Extract source-grounded procedures before creating transition edges.** For each approved advisory/report/campaign write-up, split the permitted source representation into stable sections or paragraphs and retain the URL, publication/version, content hash, and page/section/paragraph anchors. A strict-schema extractor may propose an ordered list of known ATT&CK/CAPEC IDs only when the cited spans explicitly describe an order or causal sequence; every returned ID and span must be checked against the source text and current catalogue in deterministic code. Create `tsg_intel_procedures` records with the evidence, explicit ordering cue, asset/product/platform context and extractor version. If a source lists techniques without describing their order, store associations but do not manufacture a sequence. Create adjacent directed edges only from an explicitly described sequence, a documented CAPEC prerequisite direction, or an owner-approved rule; attach exact source spans, preconditions, affected surface and separate source-reliability/recency/applicability/sequence-support dimensions. An explicitly sourced edge becomes `source_validated` only after ID/span/order/precondition checks pass. A curator may mark another edge `reviewed` only by updating the version-controlled transition/mapping review artifact through the independent-review pull-request process and importing the approved version through the admin job; no direct database update is permitted. ATT&CK “group uses technique” relationships prove association, not sequence. Semantic similarity or an LLM’s plausible guess alone remains `candidate` and cannot validate an attack path.
8. **Schedule refreshes.** Refresh CISA KEV/advisory/OTX and EPSS data daily by default; update NVD incrementally on the daily maintenance cycle; check ATT&CK/CAPEC releases weekly or on release-stamp change. Allow an admin refresh. Alert when a source exceeds its source-specific stale threshold, computed as `max(CII_INTEL_STALE_AFTER_HOURS, 2 × source_poll_interval_hours)`. Track last successful check separately from last content change. Failed refresh means “serve last good data and show stale status,” not “erase data” or “fail all generation.”

#### 7.2.6.1 OTX adapter — exact build steps

Build this adapter in Step 7A, after the source registry and common schemas exist and before Steps 10–13 can be accepted. OTX is an additional evidence source, not the canonical threat library. AlienVault Open Threat Exchange is a community-driven threat-intelligence service; do not interpret the word “open” as proof that the service or every pulse is open-source or available for commercial use. The current [OTX End-User Agreement](https://www.levelblue.com/legal/otx-eula-terms) says OTX is free to end users for non-commercial use and includes restrictions on commercial exploitation and third-party service use. Therefore, keep `CII_OTX_ENABLED=false` for commercial TSG deployment until Legal/Procurement confirms written provider authorization or a suitable commercial agreement for the exact intended use (including API access, stored data, embeddings, derived output and multi-tenant service). The open-source SDK license is separate from the service and pulse-content terms. Community submissions still require provenance and validation. See the [OTX API documentation](https://otx.alienvault.com/api) and [official AlienVault OTX Python SDK](https://github.com/AlienVault-OTX/OTX-Python-SDK).

1. **Configure and protect the key.** Inject `CII_OTX_API_KEY` only as an OpenShift Secret/secret-manager reference; `.env.example` contains an empty placeholder. Never ask a user to paste the key into a prompt, send it to a model, log headers, or expose it through a status/API response. Keep `CII_OTX_ENABLED=false` for commercial TSG environments until Legal/Procurement records written provider authorization or a suitable commercial agreement in `tsg_intel_feeds` and approves the specific use. Do not enable it merely because authentication succeeds. Provide a one-time admin health check that reports `configured`, `authenticated`, last success and a safe error code, never the key.
2. **Implement an isolated adapter.** Add `app/intel/adapters/otx.py` implementing the shared `fetch`, `validate`, `normalize`, `checkpoint` and `health` contract. Use the documented `X-OTX-API-KEY` header and HTTPS. The initial pull uses the authenticated account's subscribed pulse endpoint (`/api/v1/pulses/subscribed`); fetch pulse details and indicator pages only as required by the documented OTX API contract. If additional pulse-search endpoints are enabled, make that an explicit source-registry setting. Do not call OTX separately during each scenario request.
3. **Make ingestion restart-safe.** Page through the feed using the API's pagination/checkpoint fields. Store last completed page/cursor and last successful watermark only after each page is durably normalized. Upsert pulses by `(source_id, pulse_id)` and indicators by `(source_id, pulse_id, indicator_type, indicator_hash)`. A restart replays safely without duplicates. Never assume an undocumented cursor or timestamp field; validate it against the response schema and current API docs.
4. **Normalize pulse evidence separately from indicators.** For each pulse, retain pulse ID, title, sanitized description, tags, external references, author metadata, creation/modified/fetch time and content hash. For each indicator, retain its typed value, normalized exact-match hash, pulse/source IDs, indicator time/validity and sharing label when supplied. Keep raw indicator lists out of technique embeddings and ordinary scenario prompts. Use pulse behavior text/references to propose technique links only through the common crosswalk/review pipeline; tags alone are not proof of a technique.
5. **Use IOCs only for defensible correlation.** Match an OTX indicator by exact typed value against a verified, authorized asset/SOC indicator inventory only when that inventory is present in the frozen run context. The current asset/system context does not become an IOC merely because it has a name. If no verified indicator exists, the IOC may be retained as campaign evidence, but cannot claim that the assessed asset was targeted, that a CVE is exploitable, or that a specific actor caused the threat. Never automatically fetch an OTX URL, download a file, resolve a domain as a target, or execute/sandbox a sample as part of generation.
6. **Handle source reliability correctly.** Keep OTX as community evidence with its own source tier and timestamps. Multiple copies of one OTX pulse through another aggregator count as one provenance cluster, not independent corroboration. Named-group attribution requires an explicit source-backed relationship and the approved attribution policy; pulse author, tag, IOC owner or IP geolocation is not sufficient. Do not label a scenario “UAE-specific” unless a UAE/sector source or approved organization evidence supports that claim.
7. **Apply safe retries and degraded operation.** Use a bounded timeout, limited exponential backoff with jitter, respect `Retry-After` when present, and stop/retry on a later maintenance cycle after 401/403 or persistent 429/5xx rather than tight-looping. A failed refresh keeps the last-known-good OTX snapshot active and marks its freshness degraded. A disabled, stale or unavailable OTX source must not block scenario generation; the scenario records source freshness and continues with remaining approved data.
8. **Prove the adapter with tests.** Test missing/wrong key, 401, 429 with `Retry-After`, timeout, malformed pages, repeated-page replay, pulse/indicator updates, deleted/revoked/stale items, oversized responses, duplicate pulse in MISP, prompt-injection strings inside pulse descriptions, secret-log scanning, and offline generation from the last-good snapshot. Use fixed fixtures for CI; a live API smoke test is a separate opt-in Dev check.

#### 7.2.6.2 Source-specific implementation order (build and test before Step 10)

Implement each connector behind the same adapter contract; do not call external services from the live scenario request path.

1. **ATT&CK importer.** Pin the official STIX 2.1 release bundle for Enterprise and ICS domains. Parse objects and relationships with a maintained STIX library, preserve stable external IDs, version/release, `modified`, revoked/deprecated status, source citations and procedure examples. Import only the in-scope domains; add Mobile only if the product scope needs it. Add fixtures for a known group-technique relation and a deprecated technique.
2. **CAPEC importer.** Download a versioned official machine-readable release (XML/CSV as supported), validate its schema/checksum and import attack pattern IDs, prerequisites, consequences and explicit relationships. Preserve the MITRE notices. A CAPEC pattern is a candidate behavior/precondition, not proof a path occurred.
3. **CISA KEV and advisories.** Refresh the published KEV JSON on the daily maintenance cycle. Ingest CISA cybersecurity and ICS advisories from official approved feeds/pages or structured advisories; retain the advisory ID, issue/updated date, affected product/version, associated CVEs, technique references, mitigations and paragraph/section citation. Parse vendor CSAF documents only from an approved publisher allow-list; never follow arbitrary URLs found in the advisory text.
4. **NVD CVE/CPE enrichment.** Use the current NVD API 2.0 endpoints, not retired 1.0 endpoints. Incrementally request CVEs modified since the saved UTC watermark, paginate using the returned counts/offsets, and commit the watermark only after all pages are stored and validated. Use `CII_NVD_API_KEY` as an optional secret for higher permitted request rates; without it, throttle conservatively. Prefer explicit CVE IDs or normalized CPE/product/version matching. Persist CVSS and applicable affected-version ranges separately from KEV status; a high CVSS alone is not proof of exploitation.
5. **FIRST EPSS enrichment.** Store the EPSS score, percentile, score date and source stamp only for CVEs in the active/relevant CVE set. Use the official daily CSV/GitHub dataset for batch refresh; use the API for a short list of known CVEs. Treat EPSS as a CVE exploitation-priority feature, not a per-asset breach probability. A stale or missing score is `unknown`, never zero.
6. **OTX connector.** Follow §7.2.6.1. Only after the source registry marks the use `approved`, use the authenticated account's subscribed pulses by default; review the subscriptions for relevant sectors and trusted publishers. Until approval, test with frozen fixtures and mock HTTP responses; do not call the live service. Preserve pulse/indicator separation, safe pagination, feed provenance and current sharing/terms restrictions.
7. **Optional IOC feeds/platforms.** Add ThreatFox/URLhaus/MalwareBazaar or MISP only after the per-source use/terms gate approves the deployment. Use typed IOCs for correlation/search, not for narrative generation or as vector text. An IOC-only result cannot identify a canonical TSG threat, prove an asset is exposed, or validate an attack-chain edge.
8. **Unify evidence, not source semantics.** Normalize every source to a common evidence envelope while retaining original fields and source identifiers. Do not flatten unlike confidence fields into one universal confidence. Keep separate `source_reliability`, `recency`, `asset_applicability`, `behavior_sequence_support` and `attribution_strength` dimensions; each use case has its own acceptance rule.
9. **Verify source-to-scenario traceability.** A retrieved technique/advisory must be linked to a candidate threat through a reviewed mapping or a validated exact relationship. Every proposed transition must contain the supporting source IDs and applicable preconditions. Add a golden test in which a current advisory alters ranking only for a product/version actually present in the frozen context.
10. **Create and govern the transition-rule baseline.** Because public catalogues rarely document a complete ordered sequence for every possible asset, ship a small, deliberate baseline of high-value transition rules for in-scope IT/cloud/identity/web and (if assessed) OT cases. Store rules and TSG crosswalks as version-controlled YAML/JSON with immutable IDs, version, source/evidence references, applicability predicates, required context fields, disqualifiers, reviewer/approval metadata and positive/negative fixtures. A rule must describe the state/precondition enabling the transition, not simply connect two semantically similar techniques. Changes go through a reviewed pull request with an independent reviewer and automated fixtures; import only approved versions through the admin-job path, record the rule version in each path, and never allow direct database edits or LLM output to activate a rule. Validate a chain against both (a) the directed technique/state-transition graph and (b) the frozen environment topology/identity relationship graph whenever it crosses a system or trust boundary. Where no approved transition or environment route is defensible, keep the candidates as separate paths.

**Run-time use of intelligence**

1. Freeze asset/system facts and both the canonical TSG library stamp and external-catalogue stamps in the run. Relevant facts include technology/product/version, internet/remote exposure, identity dependencies, system connectivity/trust boundaries, privileges, criticality, sensitive data and OT safety constraints—but only when supplied by the approved asset inventory. Missing values remain `unknown`; emit a context-coverage warning rather than filling them with model guesses.
2. Run the existing SQL-library-first STRIDE retrieval and relevance gate unchanged. This preserves canonical TSG behaviour and the source-of-truth rule.
3. For each STRIDE category and each asset/system surface, run a separate technique/advisory retrieval pass: hard-filter applicable domain/platform and active catalogue records; prioritize exact vendor/product/version/CVE matches when verified; combine lexical BM25, vector similarity and RRF; rerank the candidate set; then require a strict-schema relevance/precondition check against the frozen facts. A general semantic match alone is not sufficient. Run a deterministic adaptive expansion when the top-K window is saturated, system/category coverage is missing, a high-quality cue remains unmapped, or relevance is borderline; stop at corpus exhaustion or the configured compute budget. Record retrieved/assessed counts and the stopping reason. `TOTAL_SCENARIO_COUNT=0` means all valid paths found within this documented search budget, not all theoretical paths or guaranteed recall over every external record. Step 15 must measure recall on a labelled benchmark and set the accepted budget from evidence.
4. **Map evidence to existing threats first.** If a relevant technique maps to a canonical threat, attach the technique and source references to that threat. If no approved mapping exists, compare the candidate against the full relevant library threat corpus and existing scenarios using name/text similarity, IDs, affected systems, technique coverage and the same-attack deduplication check.
5. **Allow an evidence-based gap candidate even when a generic library threat exists.** This is an explicit new rule: the classic LLM gap-fill still runs only when the full library category scan finds no relevant library threat; separately, a CTI-driven candidate may be added in any category only when a fresh/traceable source supports the behavior, applicability/preconditions pass, the behavior adds material technique coverage not already represented, and duplicate checks pass. Mark it `source=cti_gap_candidate`, keep canonical threat/type IDs null unless valid library relations exist, record all evidence and uncertainty, and route it through the existing pending/curator workflow. Never promote it automatically or create fake candidates merely to increase scenario count. The separate `master_data_status` remains pending until explicit curator approval, even when the candidate is scenario-eligible.
6. **Resolve actor conservatively.** Rank only active, capable actor IDs permitted by the new product rules and `ThreatType_ThreatActor_Map`. Source-backed ATT&CK groups or report aliases can be attached as external attribution evidence; they do not replace the canonical acting actor. If specific-group attribution is weak, describe the behavior as a plausible adversary archetype, not a factual attribution.
7. **Build paths from supported transitions.** Group threat/technique steps only if the edge is supported and preconditions hold: the first step has a plausible initial condition, each subsequent step has a valid state/privilege/access transition, the involved systems are in scope and a credible route/relationship exists, and the final step reaches a meaningful attacker objective. If a transition cannot be supported, keep separate single-step paths. Record the reason/edge evidence for each transition.
8. **Write a business-readable but technically grounded scenario.** Build the scenario around an attacker objective, initial condition/access, the behavior that enables each transition, the affected system/trust boundary, the intended outcome and the defensive consequence. Prompt input contains only the selected path, supporting technique IDs/names, source-documented procedure/advisory excerpts, applicable preconditions and the frozen asset/system context. Explain “how the attack could unfold” at behavior level; do not emit exploit payloads, operational commands or ungrounded details. The risk statement states the asset/process/data consequence and plausible business impact. Technical evidence remains in structured evidence fields, not a wall of ATT&CK codes in the business paragraph. Set `evidence_mode=observed_pattern` only when a source documents the relevant behavior sequence; use `technique_informed` for a validated chain based on known TTPs; use `hypothesis` when material assumptions remain. These labels describe the evidence supporting the scenario, not proof that this specific asset was attacked.
9. **Use technique context in control mapping.** Keep the required scenario + risk statement as the query core; append relevant ATT&CK/CAPEC technique names, path transitions, affected systems and source-backed mitigations. Rerank only existing controls from `Control_Library`; external “mitigations” are search/context signals, not canonical controls. Preserve nearest-control warning/empty-library failure rules.
10. **Fail open on source outage but fail closed on unsupported claims.** If an optional source is down or stale, continue using the last good data and show the freshness state. Never generate claims that a CVE affects an asset, a technique chain is observed, an actor is responsible or a source is current unless the saved evidence supports that exact claim.

**Required evidence carried by each run/scenario**

- Library stamp, ATT&CK Enterprise/ICS release stamps, CAPEC stamp, CISA/advisory feed stamps, OTX account/subscription snapshot stamp or fetch watermark, OTX pulse IDs and content hashes, MISP cursor or fetch stamp, source parser version and embedding/reranker/model/prompt/calibration versions.
- For each threat/technique/path step: canonical TSG IDs if present; ATT&CK/CAPEC IDs; source-object/pulse/indicator IDs and URLs; publication/observation/first-seen/last-seen timestamps; source tier and evidence mode; reason it applies; asset/system IDs; preconditions and unknowns; relevance/rerank calibrated results; mapping/edge status; deduplication/corroboration-cluster disposition; and whether a real-world actor attribution is merely reported or confirmed by the source.
- A `scenario_evidence`/`attack_path_evidence` structured field (or a versioned child record) with immutable evidence summaries. Keep enough information to reproduce the decision after the source cache expires. Every source citation shown to a reviewer must resolve to a stored source/evidence ID in that run.

**Tests that block acceptance**

- A relevant ATT&CK technique alters candidate evidence/path selection when applicable and does not alter results when the platform/preconditions mismatch.
- Exact KEV/CVE evidence elevates a candidate only for verified applicable product/version/CVE; unknown version does not become vulnerable by inference.
- An OTX/MISP IOC alone never proves an actor, exploitability or a multi-step attack chain; an OTX pulse author is not the attacker; exact IOC correlation requires an approved asset inventory value; duplicate syndicated feed items count as one corroboration cluster; actor-name similarity alone cannot qualify or attribute a named group; a source-rights downgrade immediately deactivates the feed/index regardless of stale-cache fallback.
- ATT&CK group/software relations never become an ordered path without edge evidence; unsupported cross-system/lateral-movement edges are rejected.
- A relevant novel behavior can become `cti_gap_candidate` even if a generic library threat exists. Keep it non-canonical and `master_data_status=pending_review` until curator promotion, but treat scenario eligibility as a separate gate: it may seed a scenario before promotion only when the canonical threat type and eligible library actor resolve, the behavior is materially novel, evidence/preconditions and every path edge pass validation, and the candidate survives deduplication. If any gate is missing, it remains pending and is excluded from the path plan and `TOTAL_SCENARIO_COUNT`. Scenario generation must never write or activate a canonical threat row.
- Source prompt injection, poisoned text, malformed STIX/CSAF, excessive feed size, redirect to a non-allow-listed host, source outage, stale data and revoked technique records cannot corrupt the live index.
- Each path step has traceable support, source stamps are reproducible, the source block cannot cite IDs that were not stored for the run, and controls still resolve to canonical SQL IDs.
- Public/global intelligence is shared only when its license and handling label permit that scope. Tenant-private or sharing-restricted intelligence must be filtered by the approved scope before retrieval, embedding reuse or exact IOC matching, and must never leak across tenants/entities.

### 7.3 Attack-path identification, ranking and selection

The full plan is identified before applying `TOTAL_SCENARIO_COUNT`.

1. **Build candidate paths from the validated behavior graph.** Seed the scenario path planner only with actor-complete `candidate_eligible_for_path` canonical threats or explicitly eligible non-canonical candidates, linked to validated technique nodes. These are inputs to path planning, not yet `scenario_eligible` scenarios. Technique records or untyped CTI findings that have not passed the candidate-level eligibility gates remain in retrieval/curation only. Set `path_eligible=true` and `scenario_eligible=true` only after the completed path passes edge, precondition, topology, objective, evidence and path-level actor consistency checks. `candidate_eligible_for_path` is a node/candidate gate only; it does not guarantee that a valid sequence can be constructed. Model supported transitions as directed edges with evidence and preconditions. Identify plausible entry nodes from the frozen asset/system exposure facts and objective nodes from supported consequences (for example, unauthorized access to sensitive data, service disruption or unauthorized control changes). Enumerate bounded simple paths deterministically using a DFS/priority queue: no repeated node within a path, only active/source-supported or owner-approved edges, all edge preconditions checked, and maximum length controlled by `CII_MAX_ATTACK_PATH_STEPS` (initial default 6). `CII_MAX_PATH_EXPANSIONS` bounds graph traversal work. The LLM may suggest a path for evaluation, but code must verify every edge, precondition, affected system and source reference; an LLM-proposed edge is not valid until supported by the graph/rule. ATT&CK tactic order or semantic similarity by itself is not a valid edge. If the expansion budget is exhausted, keep valid paths found, mark the plan `budget_limited`, explain the stopping reason and emit a coverage warning—never silently present the partial plan as exhaustive. Every otherwise-valid threat/technique candidate not used in a valid chain becomes a one-step candidate path; do not discard it merely because it is not part of a multi-step chain.
2. **Validate in code.** Reject paths with unknown threat/technique IDs, repeated/invalid steps, failed preconditions, unsupported cross-system routes or stale/revoked references. Do not infer the presence of an entry point, credential, privilege, network route or vulnerable product from a technique name. A cross-system path must pass both the technique-transition graph and the frozen environment relationship/topology checks; being linked to the same asset is insufficient. Keep two paths separate only when their ordered steps, transitions, affected-system route or attacker objective materially differ; collapse equivalent paths with a stable deduplication rule. Record invalid-path reasons and edge evidence; do not generate a scenario from an invalid path.
3. **Derive canonical path fields.** `path_id` is a stable hash of the ordered threat-step keys plus evidence-edge IDs. Systems are the union of systems affected by the steps; impact is the maximum step impact. The path evidence tier cannot exceed the weakest required transition; preserve source reliability, evidence recency, asset applicability and sequence support as separate dimensions. Do not average these unlike dimensions into a probability. If an aggregate path-quality score is used for sorting, calibrate and version it against labelled paths. Preserve all step-level threats, types and STRIDE categories. Define `entry_threat_id/type` from the validated initiating step; define `primary_stride_category` from the terminal impact/consequence step; and store `stride_categories` as the ordered unique union across the path. If the threat ID is non-canonical, retain the candidate key and do not substitute a fabricated ID. This separates the initial threat description from the category of the path's terminal consequence. A path is considered library-grounded only if every threat step is canonical; mark and preserve any `cti_gap_candidate` steps explicitly. Keep source citations, preconditions, assumptions and unknowns with each step.
4. **Rank deterministically.** First apply the hard eligibility/evidence floor: invalid, unsupported, actor-incompatible, revoked/expired, beyond the source-specific hard-use-age limit, or materially ungrounded candidates are excluded and cannot be rescued by coverage ranking. A merely freshness-degraded but still-approved stable catalogue may be used with a warning when its source-specific use-age policy permits it. Among remaining valid paths, apply the documented coverage passes: (a) cover each STRIDE category; (b) prefer paths adding the most new supporting systems and evidenced routes. Then rank remaining paths by evidence tier: first verified product/version/CVE applicability with a viable path; next directly sourced incident/campaign/procedure evidence matching the platform or sector; next relevant ATT&CK/CAPEC behavior with matching platform and viable preconditions; then relevant library-only paths. Within a tier use impact, validated confidence, evidence quality/recency where recency is meaningful, then stable `path_id`. Do not claim a numerical breach probability or invent score weights; calibrate any reranker cut-off with labelled UAT cases. Identical frozen inputs, stamps and model outputs must produce the same order.
5. **Apply configuration only now.** Let `all_paths` be all validated/ranked candidate paths. If `TOTAL_SCENARIO_COUNT == 0`, selected paths = every valid path. If it is positive N, selected paths = the first `min(N, len(all_paths))`. Keep all candidate paths, ranks and selection reasons in the frozen plan; mark non-selected paths `target_reached` or the corresponding documented reason. Never add a path to meet N.
6. **Freeze the plan once.** Save the candidate threats, paths, rank, target setting, selected path IDs, excluded-path reason and source stamp in one fenced run update before scenario writing begins. The run cannot silently re-plan on a `next-set` call. The frozen plan carries per-category coverage state so a completed run is not misreported as a full catalogue scan when some categories stopped under the bounded stability policy.
7. **Handle zero candidates.** If assessment completed normally but no valid path exists, finish the run with `planned=0`, `written=0`, `remaining=0` and a clear `plan_note`. Do not call the scenario writer. Keep a distinct failed state for systemic errors such as unusable libraries or exhausted infrastructure retries.

Example: the threat process identifies 18 valid paths. The plan stores all 18. `TOTAL_SCENARIO_COUNT=5` makes ranks 1–5 eligible for generation; ranks 6–18 remain in the plan but are not generated under that setting. With value `0`, all 18 are eligible. The first batch contains up to six eligible paths; next-set writes the next eligible batch and never exceeds a positive count.

### 7.4 Scenario and risk-statement writing

Implement `ScenarioWriter` and `ScenarioRules` as pure engine components. The worker supplies a path and the frozen context; the writer produces one scenario object, not an arbitrary number of scenarios.

1. Validate the path's category, type, threat, actor and system references before the AI call. Accept either (a) a canonical threat with a live canonical threat ID, or (b) a non-canonical `ai_gap_fill`/`cti_gap_candidate` with a stable candidate key, `scenario_eligible=true`, a live canonical type ID, a live eligible actor ID, valid evidence and validated path edges. Do not require a canonical threat ID from a candidate that passed these gates. If any prerequisite is missing, do not ask the AI to invent or repair facts; record a controlled path-specific exclusion/failure.
2. Design the scenario-writer prompt from the business requirements in §7.4 and the structured output schema. Require exactly the documented JSON fields: title, scenario statement, risk statement, assumptions, requirements, outputs, and involved-supporting-system/entry-point fields. Store the prompt under version control and add labelled positive, negative and edge-case fixtures before tuning it.
3. Use business-readable, concise text. The statement describes the attack and consequence for this asset/systems; the risk statement connects cause, risk event and business/operational impact. Explain attacker decisions only where the source-supported behavior and asset preconditions justify them; do not invent an attacker's motives, capabilities, target selection or success. Use conditional language (“could exploit”, “may pivot”) for a plausible scenario, and do not word a threat scenario as a confirmed incident. Do not introduce unprovided systems, vulnerabilities, attackers, capabilities or impacts.
4. Apply deterministic cleanup: remove asset/system/framework/attacker names from title; remove framework codes, opaque report IDs, OTX hashes and GUIDs from scenario text; preserve public advisory IDs only when supported by the supplied intelligence block; replace technique codes with names where the documented rule says so.
5. Normalize risk wording so the statement leads with the consequence, names the asset and critical service, and never begins with “Because”. If the final fallback is still needed, use the owner-approved wording “This risk exists because …”.
6. Derive route status from evidence, not the number of involved systems: `validated` only when the frozen asset/topology inventory or verified configuration explicitly supports the required route; `assumed` when an approved transition and explicit system relationship make the route plausible but connectivity is not fully verified; `standalone` when the scenario does not claim a cross-system route; `unknown` when essential route context is absent. One system is not proof of an entry point, and multiple system IDs do not establish reachability. If an entry point is unknown, preserve that uncertainty rather than silently selecting the first system as a confirmed entry.
7. Run every approved scenario validation rule with explicit severity semantics: `blocker` prevents a scenario from becoming eligible, accepted, or visible as a valid generated result; `warning` permits persistence but requires a visible review warning; `note` is informational. For auditability, a blocked draft and its findings may be persisted only in a quarantined/non-servable state with tenant access controls; it must not count toward `TOTAL_SCENARIO_COUNT`, accepted/output counts, or appear in ordinary result views. Do not encode a blocker as `validation.status=warning`. A blocker may be cleared only by a deterministic fix followed by revalidation or an explicitly authorized exception type with its own audit trail; a user cannot waive unsupported IDs, missing evidence, invalid path edges, cross-tenant data or source-rights violations. Ensure the title is unique within its run.
8. Permit at most one repair for repairable findings and at most one consistency rewrite when the scenario does not match its planned path. Keep the repaired version only if it improves validation without worsening other findings. If consistency still fails, retain it with a visible note as specified by the rule set.
9. Persist each completed scenario immediately using a deterministic version ID and fenced/conditional writes. A temporary provider outage retries the job; it is not a business failure draft. An unreadable response after the configured retry/repair budget becomes a path-specific failed scenario. After five failed attempts, mark the path abandoned and do not serve it again.
10. After each write, refresh authoritative counts and publish `session.updated` only after persistence.

The first batch and each next-set batch contain at most six eligible paths. Six is a batch size, not a scenario-count ceiling.

### 7.5 Control identification — use both scenario and risk statement

Implement `ControlMapper.map(scenario, context)` after a scenario and risk statement have been persisted. Control mapping is a separate asynchronous stage and must not block a reviewer from seeing/accepting the scenario.

1. **Construct the query** from category, threat type/name, ordered attack path, actors, title, scenario statement, risk statement, asset name and technology, and involved systems. Clip to 4,000 characters using the documented deterministic method. Both the scenario and risk statement are required input fields.
2. **Filter the permitted pool.** Start with active `Control_Library` rows compatible with the asset/systems `AssetType`, applying the documented IT/OT resolution rule. If labels cannot be resolved or the compatible pool is empty, retry against the whole active control library rather than silently returning no controls.
3. **Hybrid retrieval.** Search only within the allowed pool using BM25 + vector similarity + RRF, returning up to 40 candidates. Do not use a direct threat→control mapping table.
4. **Rerank once per scenario.** Score each candidate against the combined scenario+risk query using the configured reranker. Validate score count, numeric range, candidate identity and output ordering.
5. **Choose controls.** Keep every control with score ≥ the configured model cut-off (initial value 60), ordered by compatibility, rerank score, preferred domain and stable ID. There is no fixed “maximum 25”; the shortlist of 40 is the candidate bound. If none passes the cut-off, keep the single highest-scoring library candidate with `match=nearest` and a visible warning.
6. **Constrained AI fallback and source-of-truth safeguard.** If retrieval is weak or a call is temporarily unavailable, AI may help reformulate/assess the combined query and explain candidate relevance, but only using existing library records and IDs. It must not author a new canonical control or return an unrecognized control ID. If the control library is truly empty, fail with `control_library_empty` and retry/alert according to the control retry policy. This keeps GRC traceability intact while providing a fallback search/relevance step.
7. **Deduplicate.** First by control ID, then identical normalized control text (including IT/OT twins), retaining the highest-scoring compatible record.
8. **Validate and persist.** Ranks must be contiguous `1..n`; IDs must all exist in the active library snapshot; no duplicate controls; score and match labels must be consistent. Store control ID/code/name/domain/asset type, rank, score, match, query/model metadata as allowed, library stamp and mapping timestamp. Mark `done` only after the conditional write succeeds.
9. **Retry safely.** Use a per-scenario control lease; failure after five attempts is retried by the maintenance sweep every 30 minutes. A failed control map does not erase an already-written scenario. Expose `controls_waiting` in status.

This creates explicit traceability: asset + systems → relevant threats → path steps → scenario + risk → retrieved canonical controls and scores → remediation plan actions.

### 7.6 Review lifecycle

- A scenario in a queued/running run cannot be accepted or rejected; return 409 `generation_in_progress`.
- Accept/reject are mutually exclusive and applied with one conditional update. Repeat decisions should not create duplicate audit effects.
- At most one scenario version per path is accepted unless `replace_accepted` is explicitly requested. If an older version is accepted while a newer version exists, obey the current owner rule and keep the decision trail clear.
- Regeneration creates a new version for the same path; it never changes the path identity or deletes prior versions.
- `next-set` serves the next eligible batch once. Atomic claim prevents two callers generating the same paths; a second competing request receives a stable 409 code.
- Accepting a scenario must not write into the threat library. Only endpoint #27 explicitly submits an accepted non-canonical AI/CTI threat candidate as a pending/inactive library entry for curator review; scenario generation and scenario acceptance never create or activate a canonical threat.
- Write an audit record for every successful review or promotion decision with user ID and `client_id`; publish the updated state after the database write.

### 7.7 Remediation planning

1. Accept only an accepted generated scenario, or an explicitly supplied hand-written scenario. Validate entity/tenant ownership and all input/register schemas.
2. If controls are missing, invoke `ControlMapper` once under a total 20-second deadline. If controls remain unavailable, return 503 `controls_not_ready` with `Retry-After`; do not generate a plan using invented controls.
3. Freeze the scenario, risk statement, mapped control list, asset/system context, caller-supplied register fields, and prompt/model revision in an allowlisted snapshot for that plan version. Redact and clip free text to 2,000 characters. Unknown register fields are rejected; empty string means not supplied.
4. Enqueue `tsg_write_plan`; the API returns 202. A manual-scenario request must include `Idempotency-Key` and persists its scenario as accepted before planning.
5. AI returns strict JSON for one “Mitigate” plan: actions, durations, dependencies, owner role, and references to approved supplied controls/systems. AI must not create dates, controls, owners, systems, technologies, vendors, metrics, thresholds or evidence not in the frozen context.
6. Code validates every control ID/code against the scenario's canonical controls, removes or flags controls outside the allowed set, validates roles/systems, validates action durations (1–3,650 days; repairs must create a warning), and checks dependencies for valid IDs and cycles.
7. Code computes the authoritative schedule using deterministic critical-path logic and the requested mitigation window; dates use `YYYY-MM-DD`. Never trust AI-generated schedule dates.
8. Save immutable version data and the calculated schedule; update current/latest version with conditional writes and task/epoch fencing. Preserve old versions for history and audit.
9. Accept/reject any completed version; only one version may be accepted at a time. If its source scenario later becomes unaccepted due to `replace_accepted`, the plan becomes read-only and decide/regenerate return 409 `scenario_not_accepted`.

---

## 8. Build sequence: implement and verify in this exact order

This is the working checklist. It starts from a clean repository, while marking baseline components to reuse if they are already present. Re-run tests after every step.

### Step 1 — Repository, Python toolchain and folder guards

**Implement**: project structure (§2), Python 3.12 venv, pinned requirements, lint/type-check/test commands, conventions test that enforces layer boundaries and allowed imports. Add README with local setup.

**How**: create empty package files, import smoke test, test runner config, dependency lock/pins. Add tests that fail when required app source is absent (so a broken guard cannot pass vacuously).

**Why**: all later modules need a stable foundation.  
**Depends on**: none.  
**Exit check**: clean install, import check, Ruff/mypy, test command all work.

### Step 2 — Typed settings, constants, errors, logging and request middleware

**Implement**: `Settings`, enums/constants, `AppError` hierarchy with reason codes, RFC 9457 exception handler, request-ID middleware, structured JSON logging, request-size guard, and metrics base.

**How**: add `TOTAL_SCENARIO_COUNT` alias and validator now; define status, STRIDE, actor, route, decision, control-match, queue, task, collection, event and stored-procedure constants centrally. Middleware rejects >2 MB before endpoint work. Logs carry request ID, entity, user and caller client ID, never secrets.

**Why**: the same limits and errors must apply to every later endpoint.  
**Depends on**: Step 1.  
**Exit check**: config alias/validation tests, request-size tests, safe 500 tests, exception contract tests.

### Step 3 — Database clients, SQL procedures, Mongo collections and indexes

**Implement**: Mongo client/lifecycle, stored-procedure client, pool/timeouts, `ensure_indexes()`, four read procedures, four write procedures, grants and SQL integration tests.

**How**: build and test asset context first, then threat library and control library, then stamp-based cache refresh, then pending threat procedures. Use fake/sample data for repeatable tests and DBA-approved scripts for real Dev/UAT.

**Why**: the first business API cannot prove ownership or ground threats without reliable context/library access.  
**Depends on**: Step 2.  
**Exit check**: asset ownership/system linking tests; all procedure result sets validated; exact stamp changes; app user has `EXECUTE` only; Mongo uniqueness indexes pass.

### Step 4 — Identity and API-client management (#20–#22)

**Implement**: API-client schemas/repository/service/router, key mint/list/revoke, `Principal` dependency, admin-key dependency, 60-second key cache, audit writes.

**How**: hash generated key with SHA-256 and store only hash/prefix. Return secret once with no-store headers. Business calls require all four identity headers and key. Entity/tenant checks are added to resource services, not only a generic middleware.

**Why**: API #1 and every business workflow require caller identity and audit attribution.  
**Depends on**: Steps 2–3.  
**Exit check**: missing/invalid/revoked key tests; one-time key visibility; admin/business separation; revocation reaches each pod within 60 seconds; audit records written.

### Step 5 — AI gateway and model profiles

**Implement**: chat, embedding and reranker clients; per-model profiles; strict JSON-schema validation; AI-call records; input/output limits; timeouts/retries; chat fallback; and shared Redis AI slots. These are interfaces to configured pre-trained models, not a model-training project.

**How**: use the configured model name to load a typed profile. The profile defines supported operation, expected embedding dimension, batch cap, timeouts, raw-score interpretation and calibrated reranker cut-offs. Validate one vector per input and expected dimension on every embedding response. Validate reranker result count, candidate identity, finite numeric values and order, then convert scores through a versioned calibration function to the documented 0–100 operating scale. Store both raw and calibrated scores for audit; do not compare raw scores from different models/versions. Thresholds 75 (initial threat/type/actor match) and 60 (initial control cut-off) remain provisional until the labelled UAT set establishes them. Recalibrate when model, prompt, corpus or preprocessing changes. Cache vectors by model identity plus normalized-text hash. Record `record_id`/`request_id`, task, model, latency, token usage where available, and outcome; never log keys. Use fake providers for deterministic unit tests, then make small non-production smoke calls to verify real endpoints and credentials.

**Why**: every retrieval and relevance decision must use a consistent, observable and bounded model interface. Embeddings and reranking must be validated before the core threat-selection workflow can depend on them.
**Depends on**: Steps 2–4 and working MongoDB/Redis clients.
**Exit check**: fake-provider tests plus successful development smoke calls for chat, embedding and rerank; dimension/count/range failures are rejected; AI-call records are written; the configured shared concurrency cap is enforced.

### Step 6 — Generate library embeddings, build search indexes and validate retrieval

**This is where the vectors actually used by TSG are created.** Step 5 builds the embedding and reranker clients; Step 6 applies them to the approved library and makes the resulting indexes available to threat and control selection. Do not defer this work until the admin embedding endpoints in Step 17: scenario generation depends on Step 6.

**Implement**: library snapshot cache, exact library-stamp refresh, canonical searchable-text builders, embedding cache, BM25 indexes, normalized vector matrices, reciprocal-rank fusion (RRF), `LibrarySearch`, and allowed-row masks for controls and actors.

**How to create and maintain vectors**
1. Load the active library rows and relationship maps through the SQL stored procedures. Preserve each source record's canonical ID and links. Exclude inactive, deleted, and rejected records from normal selection.
2. Build deterministic text for each searchable record: **threat** = `ThreatTypeName + ": " + ThreatName` (the threat type is deliberately part of the threat's searchable text); **actor** = `ThreatActorName`; **control** = `ControlName + ": " + ControlDescription`. The canonical `ThreatTypeID` and name for a selected library threat must come from its database relationship, never from embedding similarity or an LLM-generated label. **Initial product decision:** search threat and type together in the threat corpus; do not create a separate threat-type vector corpus because the canonical type is resolved through the SQL relationship and a separate corpus would duplicate ranking signals. Add a separate type corpus only after benchmark evidence shows a material retrieval gap and the schema, ranking and tests are updated deliberately.
3. Compute a stable cache key such as `model_name | corpus | SHA256(normalized_text)`. Check MongoDB `tsg_embeddings` first; call the embedding model only for missing vectors, in bounded batches. Store the vector, model/profile identity, dimension and text hash against the stable key. Never store a vector without its source record/corpus identity.
4. Validate every response: one vector per requested text, numeric finite values, expected dimensions from the model profile, no missing or duplicate results. Normalize vectors for cosine search. A dimension/profile mismatch must fail index construction and raise an observable error; never silently compare vectors from incompatible models.
5. Build in-memory indexes for the current library snapshot. Threat candidates are filtered to the requested STRIDE category **before** the `top_k` cut; actor and control candidates must respect their allowed-row masks. Merge BM25 and vector rankings with the configured RRF rule, with exact-name matching first. The index is a derived cache; SQL remains the authority for the records and relationships.
6. Swap in the complete new index atomically only after all required corpora are valid. When a library stamp or embedding-model profile changes, rebuild the affected vectors/indexes. During a refresh, continue using the last good index; a refresh must not make searches wait or expose a half-built index. A process's first build may wait because no usable index exists yet.
7. Embed each incoming search query through the same embedding profile, preferably batching all threat queries for the six STRIDE categories and the asset/supporting systems into one call. Cache reusable query embeddings by model plus normalized query hash. Reuse library vectors; do **not** re-embed the full library for each run. A maintenance task should pre-build or refresh the index on its documented schedule.

**How reranking is used**
- The reranker is a pre-trained inference model exposed through the AI gateway; do not train or fine-tune one as part of the initial implementation. Configure its provider/model name, timeout, concurrency and cut-off in the model profile/environment.
- **Threat identification:** hybrid retrieval produces candidates; the constrained relevance-gate LLM decides whether each threat applies. Reranking is additionally used where the documented library-match rule compares an AI gap-fill proposal to library candidates (match bar 75). Do not substitute the control cut-off for this match bar.
- **Actor selection:** use semantic ranking and the calibrated actor-fit gate over active/capable actors linked to the chosen type. If none passes, use the flagged fallback over remaining active/capable library actors. Alternate-actor name-vector cosine must meet 0.80 **and** pass independent profile/source-backed fit validation; cosine alone cannot qualify an actor. Do not use a reranker to bypass type-to-actor relationship constraints. Named real-world attribution is separate from the required canonical acting actor.
- **Control mapping:** form a query using both the final scenario statement and its risk statement (plus path, actor, asset and system context); retrieve up to 40 controls from the compatible library pool; rerank query/control pairs; validate that every returned score maps to the corresponding candidate; retain all controls scoring at least the configured cut-off (initially 60), deduplicate, and order deterministically. If none clears the cut-off, retain the single highest-scoring canonical library candidate with `match=nearest` and a warning. If the library is empty, fail explicitly.

**Why**: threat and actor selection rely on semantic representations; control quality relies on the scenario+risk query and reranker. Reusing validated vectors improves repeatability, latency, cost and auditability.
**Depends on**: Step 3 (libraries, Mongo cache and stored procedures) and Step 5 (working embedding/reranker clients and model profiles); worker/index lifecycle from Step 7 integrates the rebuild tasks.
**Exit check**: tests prove stable source-ID mapping, correct vector dimensions, cache reuse, rebuild after content/model change, keyword-only and semantic-only retrieval, STRIDE and allowed-row filtering, exact-match priority, RRF order, reranker score validation, control cut-off/fallback, deduplication, failure observability, and no partial index swap. Run a dev smoke test against the configured embedding and reranker providers before enabling threat-generation runs.

### Step 7 — Celery, queues, job leases, reaper and worker lifecycle

**Implement**: three queues (`tsg_threats`, `tsg_scenarios`, `tsg_maintenance`), task routes/registrations, leased-task base, heartbeat, fenced writes, retry/backoff, reaper and worker gauges.

**How**: queue messages contain IDs and epoch only. Claim via conditional Mongo update; lease is 120 seconds and heartbeat every 30 seconds. Reaper runs every 60 seconds, requeues expired claims and resends queued work older than 120 seconds only when the broker queue has no waiting message. Late ack and prefetch 1; thread pool only, one process per worker pod. Track each task module and route in a test.

**Why**: long AI calls must survive worker crashes without duplicate or stale writes.  
**Depends on**: Steps 2–6.  
**Exit check**: duplicate-delivery, kill-worker, expired lease, old-epoch, retry/backoff, missing task registration and queue routing tests pass.

### Step 7A — External intelligence ingestion, technique catalogue and supported attack graph

**Implement now—before ThreatFinder, AttackPathSelector or ScenarioWriter is accepted.** Implement the source adapters, `tsg_intel`/`tsg_intel_indicators`/`tsg_intel_procedures`/`tsg_techniques`/`tsg_technique_edges`/`tsg_technique_mappings`, versioned staging/activation, technique embeddings/index, evidence resolver and refresh job task. Implement procedure extraction with exact source-span validation before transition-edge generation; never infer an ordered chain from a list of techniques or a group-to-technique relationship. API job-management endpoints #25 can be completed in Step 17; workers and direct admin task tests are enough to develop the data pipeline now.

**How**: follow §7.2.6 in order: source registry/allow-list; adapter and schema validation; normalize/deduplicate; staged snapshot and stamps; technique embedding + BM25/vector/RRF + reranker; traceable technique-to-TSG crosswalk; supported edge graph; schedule refresh; last-good fallback. Build test fixtures from frozen public samples so unit tests never require live internet. The standard threat-library path remains first; CTI expansion is a second evidence channel, not a replacement for the canonical library.

**Depends on**: Steps 3, 5, 6 and 7. The data pipeline must expose a stable `TechniqueEvidenceResolver` contract before Step 10 starts; Steps 10–13 must call it for threat evidence, path validation, scenario writing and control search.

**Exit check**: full Step 7A acceptance tests in §7.2.6 pass; a local run can query the last-good technique snapshot with no live feed request and can report its exact source/index stamp.

### Step 8 — Health/readiness, SSE EventHub and status publication

**Implement**: `/health`, `/ready`, `/metrics`, Redis pub/sub EventHub, session SSE endpoint #8, `publish_session_status`.

**How**: readiness checks MongoDB, SQL Server, Redis and at least one worker per routed queue with cached/short-lived dependency status so probes do not hang indefinitely. SSE authorizes before opening the stream, sends current status first, sends `session.updated` only after writes, uses 15-second ping comments and disables proxy buffering. Reconnect returns a fresh snapshot.

**Why**: the platform needs accurate progress and deployment probes before scenario workflows are exposed.  
**Depends on**: Steps 2, 3, 4 and 7.  
**Exit check**: 200/503 readiness scenarios; no cross-entity subscription; SSE reconnect/snapshot, slow-client and Redis disconnect tests pass.

### Step 9 — Run schemas, repositories and the first business API (#1), then status API (#2)

**Implement**: `AssetContextProvider` and its frozen context contract; combine `tsg_GetAssetContext` with any explicitly approved topology/identity enrichments, preserving unknowns when no provider exists. Then implement `StartRunRequest`, `SessionStatus`, session repository, `RunService.start`, request idempotency, active-run index, a stub `tsg_find_threats` task, API #1, then status query/service/API #2. Do not implement result/list/detail endpoints yet; they depend on completed scenario documents and are finalized in Step 14.

**How**: follow §7.1 exactly. First test `AssetContextProvider` with and without topology data: linked-system membership must never be turned into an invented route, and the context snapshot must include relationship-source timestamps. Then test #1 against a stub worker: POST must persist a queued run, enqueue an ID+epoch message, and return 202 in <500 ms. Then make #2 read the real saved state using one indexed projection. Keep #3, #9 and #10 response models in the design, but implement their queries and endpoint handlers in Step 14 after scenario persistence and review semantics exist.

**Why**: proves request-to-database-to-queue-to-worker end-to-end before introducing LLM complexity.  
**Depends on**: Steps 1–8.  
**Exit check**: idempotent replay, two simultaneous starts, invalid asset/system, wrong entity, SQL failure, queued-job rescue, indexed reads, API latency, and known/unknown topology snapshot tests pass.

### Step 10 — `ThreatFinder` and full threat plan

**Implement**: per-category hybrid queries; canonical type validation before the relevance gate; expansion to unjudged library threats; ATT&CK/CAPEC/advisory evidence matching; CTI and AI gap-fill candidate validation; global candidate deduplication; one final actor-resolution pass; path-ready bundle and trace records.

**How**: implement §7.2 as small testable functions. Do not mix Mongo writes or HTTP concerns into engine classes. Validate canonical type relationships before calling the relevance model; collect technique evidence; deduplicate candidates; then call the actor resolver once on final survivors. Candidate builders must not assign actors. The resolver returns eligible actor-complete bundles plus pending candidates with explicit blockers. Define prompt templates, rules and schemas from this guide, approved catalogues and the labelled benchmark; add golden fixtures for all six STRIDE categories, actor fit, gap-fill and source-backed CTI. The engine returns a validated plan object; the worker owns persistence.

**Why**: threat identification, actor eligibility and evidence validity are among the highest-risk parts of the new system.  
**Depends on**: Steps 5–9.  
**Exit check**: all six categories evaluated; no premature gap-fill; affected systems and actor IDs validated; unknown topology remains unknown; duplicate thresholds; category retry; no active capable actor in the library; library-only acting actor and no-false-attribution tests pass.

### Step 11 — `AttackPathSelector`, ranking and `TOTAL_SCENARIO_COUNT`

**Implement**: path grouping validator, path ID generation, path metadata derivation, three-pass deterministic ranking, scenario-count selection and one-write plan freeze.

**How**: implement §7.3; use `Settings.total_scenario_count` instead of a hard-coded `MAX_SCENARIOS=15` or code-only target. Keep all valid paths/ranks in the frozen plan; store which are selected and why. Store plan before handing off to scenario writer.

**Why**: the count must reflect valid paths, not an arbitrary target or AI-generated filler.  
**Depends on**: Step 10.  
**Exit check**: all six count examples in §1; stable ordering for identical inputs; no limit at zero; positive limit applies after complete identification; only scenario-eligible candidates enter the plan; cross-system paths require frozen relationship evidence; zero candidate paths finish with zero scenarios; next-set cannot exceed selected count.

### Step 12 — `ScenarioWriter`, validation/cleanup, and first scenario batch

**Implement**: scenario prompts; title, statement, risk statement, assumptions, systems, route; structured attack-path and source evidence; rules/findings; one repair + one consistency rewrite; immutable version ID; scenario-write task. Use the Step 7A technique/advisory evidence only for the frozen selected path.

**How**: implement the complete scenario contract in §7.4 as new, independently tested rules. Include only the selected path's validated technique/incident evidence and clearly marked assumptions; require that every technique/source ID exists in the run snapshot. The model may not create a new path, assert an unknown product version/CVE, or claim a named actor without evidence. Write up to six eligible paths in parallel; save each result as it completes; protect each write with the worker task ID + epoch; update run and path status. AI outages cause bounded job retry, not a fake failed scenario.

**Why**: this generates the main user-facing product from the frozen plan.  
**Depends on**: Step 11.  
**Exit check**: rule unit tests, invalid JSON, title uniqueness, risk statement wording, opaque-code cleanup, plan mismatch repair, sibling similarity, duplicate task delivery and failed-path abandonment tests pass.

### Step 13 — `ControlMapper`, asynchronous map task and retry sweep

**Implement**: combined scenario+risk query, `AssetType` pool resolution, top-40 hybrid retrieval, reranking/cutoff, nearest-control fallback, twin deduplication, control state/lease, retry sweep and control counts.

**How**: implement §7.5. The query must contain both scenario and risk statements plus validated ATT&CK/CAPEC technique names, transition summaries and any source-backed mitigation language; never let external feeds become control IDs. Dispatch mapping after scenario persistence so scenario review is not blocked. Map only current generated scenarios; do not map hand-written scenarios automatically unless remediation requests a top-up. Retry failed mappings and sweep stale queued/running/failed work on the documented schedule.

**Why**: each generated scenario needs traceable applicable controls while generation and controls recover independently.  
**Depends on**: Step 12.  
**Exit check**: test scenario-only/risk-only/combined query effects; allowed AssetType pool; score cut-off; no-pass nearest selection; no duplicates; unknown control IDs rejected; empty library fails explicitly; every completed scenario has at least one control when library data is available.

### Step 14 — Results/list/detail, review, next-set, regeneration and promotion APIs (#3–#7, #9–#10, #27; complete #2 status behaviour)

**Implement**: `ReviewService`, `ScenarioQueries`, results/detail/entity-list query paths, atomic accept/reject, replace accepted version, next-set claim, regenerate versioning, final status-count semantics for #2, and promotion of accepted AI/CTI candidates to pending library entries.

**How**: implement APIs in §6 in the listed order. Add audit records and publish after successful writes. Use conditional updates, never read-then-write without an expected-state filter for a decision. Define conflict reason enums (`generation_in_progress`, `nothing_left`, `already_decided`, `scenario_not_accepted`, etc.).

**Why**: makes the scenario pipeline reviewable and safe under repeated clicks/concurrent callers.  
**Depends on**: Steps 8–13.  
**Exit check**: concurrent accept/reject, double-click, next-set race, regenerate race, replacement semantics, old-version acceptance, entity-list isolation and promotion idempotency tests pass.

### Step 15 — Threat-intelligence integration acceptance, evidence QA and coverage calibration

**Implement**: end-to-end acceptance of the Step 7A intelligence pipeline as consumed by Steps 10–13; golden scenarios for representative UAE-relevant IT, cloud, identity, financial/government, web/API, third-party and ICS/OT assets; calibration of source tiers, retrieval top-k, reranker cut-offs and technique relevance thresholds; source/technique coverage reporting.

**How**: replay a labelled set of known incidents/advisories and deliberately irrelevant records. Measure precision of relevant technique candidates, supported-edge validity, path-search budget exhaustion, duplicate rate, source freshness, evidence coverage, false group attribution, exact CVE/product match behaviour, control applicability, latency and model cost. Tune against reviewer labels rather than inventing score weights. Record a coverage warning for asset contexts that omit version/exposure/identity/connectivity fields. Build comparisons with CTI enabled versus disabled; CTI must add relevant coverage without increasing unsupported claims or duplicate scenarios. Use published UAE/sector reports only with their publisher, date, definition and source reference. Aggregate attempt counts are trend context, not a per-asset probability score.

**Why**: a technically connected feed is not proof of realistic output; relevance, path validity and attribution must be measured before production.  
**Depends on**: Steps 7A and 10–14.  
**Exit check**: labelled golden set meets the precision/coverage/latency targets defined in Step 21; every path step has evidence or a clearly labelled approved assumption; no incorrect specific actor attribution or unsupported CVE claim appears in the regression set.

### Step 16 — Remediation APIs, planner, scheduler and event API (#11–#17, #28)

**Implement**: remediation schemas/repository/service/tasks, snapshot builder/redaction, `RemediationPlanner`, `ActionScheduler`, accept/reject/version logic, status/results/list, remediation event publisher and SSE route.

**How**: implement §7.7. The POST remains asynchronous and returns 202 after durable persistence/enqueue. Implement event details from §9. The remediation stream is an asynchronous long-lived GET response; the generation itself is a Celery background job. Audit every plan request/decision/regeneration and every terminal failure. Add `tsg_remediations` to lease/reaper job collections and add its indexes.

**Why**: remediation depends on accepted scenarios and canonical controls; it must not run before review and control mapping are stable.  
**Depends on**: Steps 5–8, 13–14.  
**Exit check**: snapshot immutability, control top-up timeout, strict action schema, dependencies/cycle validation, critical-path golden dates, any-version decisions, only-one-accepted-version, scenario-unaccepted conflict and #28 SSE tests pass.

### Step 17 — Embedding admin APIs, pending-library workflow and admin jobs (#18–#19, #23–#26)

**Implement**: manual embedding refresh/progress APIs, pending list/decision services, library importers, admin-job models/repository/tasks and `tsg_schedule_admin_jobs` beat entry.

**How**: these endpoints operate the vector/index lifecycle already implemented and tested in Step 6; they are not where embedding or reranker support is first created. `POST /v1/embeddings` validates `{scope: all|threats|controls|actors|techniques|intel_summaries, recreate: false}`, authenticates with the admin key, persists an admin job, enqueues it, and returns `202` with a job ID. `GET /v1/embeddings/{job_id}` returns durable state, progress, row counts, start/finish times and safe failure details. The job recomputes only requested, missing, or invalidated vectors unless `recreate=true`, then swaps in a complete valid index. Every admin job has durable state, progress, result/error, requesting actor and finish time. Allow only one active job per kind. Support dry-run imports; use stored procedures for all library writes. Pending proposals remain inactive until a curator approves them. Admin endpoints use the admin key, not a business API key.

**Why**: operators need a controlled way to refresh/rebuild indexes after library or model changes, while ordinary TSG runs reuse the already-built index.
**Depends on**: Steps 3–7 (library, AI gateway, vector pipeline and jobs), plus the admin-job repository and auth foundation.
**Exit check**: valid/invalid scope tests, admin authorization, 202 + status transitions, progress, idempotent rebuild, model/library version invalidation, concurrent duplicate job rejection, restart/reaper recovery, dry-run imports, duplicate import, approve/reject limits, audit coverage and embedding progress tests pass.

### Step 18 — Complete metrics, logs, dashboards and alert rules

**Implement**: API/worker metrics, AI slot metrics, run/scenario/decision/plan counters, dependency health, queue visibility, Grafana dashboard, Prometheus rules, Alertmanager routing, Loki/Alloy log collection, Flower and exporters.

**How**: every metric used by an alert/dashboard must exist in an application registry or exporter. Test alert expressions with `promtool` where available. Decide alert recipients and public-monitoring risk before production; visibility in a dashboard alone is not a notification channel.

**Why**: operators need to find a failed job by request/session/plan ID and understand the next action.  
**Depends on**: Steps 2, 7 and the modules whose metrics are being graphed. May run in parallel after Step 2, but production gate depends on all relevant modules being complete.  
**Exit check**: metrics present, dashboard values match API/job records, every alert has a test, forced-failure test fires the expected alert.

### Step 19 — Image, CI pipeline and OpenShift manifests

**Implement**: Docker image, dependency/security scans, lint/type/test pipeline, OpenAPI compatibility check, manifest validation, API/worker/beat deployments, route, ConfigMap/Secrets, NetworkPolicy, PDB and smoke script.

**How**: pin the Python base image and installed dependencies. Run the same test command in CI and locally. Use least-privilege service accounts, non-root containers, dropped capabilities, resource requests/limits, secret references rather than plain-text secrets, and edge TLS on the existing route. Confirm egress requirements explicitly for SQL, Mongo, Redis, AI proxy and intel feeds.

**Why**: creates a repeatable release and prevents environment-only failures.  
**Depends on**: Steps 1–8 and stable module interfaces; can be started in parallel but cannot pass acceptance until feature tests pass.  
**Exit check**: build succeeds, image scan passes, manifests validate, smoke tests pass on a disposable environment.

### Step 20 — UAT deployment and integration verification

**Implement**: apply stored procedures/grants, populate UAT secrets, deploy the newly built service and smoke-test it in an isolated namespace with dedicated database names, Redis databases/key prefixes and queues. No prior TSG service is required or assumed.

**Deployment order**
```text
1. Mirror/pull required base and observability images
2. Deploy/verify MongoDB, Redis, SQL connectivity and secrets
3. DBA applies scripts/sql/*.sql and grants.sql
4. Deploy workers for all three queues
5. Deploy Celery beat and verify it is alive
6. Deploy API pods and Route with edge TLS
7. Wait for /ready = 200; verify all queues have a worker
8. Deploy/verify observability using approved access controls
9. Run smoke.py, API contract suite and end-to-end workflows
10. Run rollback rehearsal
```

**Why workers and beat before API**: `/ready` requires at least one worker on each routed queue. Give the new deployment its own queue names and Redis key prefixes; never share mutable job state with unrelated services.
**Depends on**: Steps 15–19.  
**Exit check**: `/ready` healthy through the route, all workers/beat registered, secrets not visible in manifests/logs, smoke tests pass, rollback succeeds.

### Step 21 — Quality, security, load, recovery and production sign-off

**Implement/execute**
1. Build and version a labelled benchmark from representative asset/system contexts and expert-reviewed expected threats, threat types, eligible actors, attack-path edges, realistic scenario/risk statements and applicable controls. Include IT, cloud, identity, data, web application and OT scenarios relevant to the intended deployment, plus negative/no-match cases. Record reviewer, adjudication, source stamps and benchmark version.
2. Evaluate retrieval recall@10 and precision of the relevance gate by STRIDE category; validate canonical actor/type/control IDs; require every multi-step edge to be source-backed or an explicitly approved rule; measure control precision/recall and scenario factual-claim traceability. Initial proposed quality gates: threat retrieval recall@10 ≥ 0.90 on the labelled set; relevant-threat precision ≥ 0.85; selected-control precision ≥ 0.85; 100% of path edges evidence-backed/approved; 100% of canonical IDs resolve to active records; zero unsupported named-actor, CVE/product-version or asset-compromise claims in the regression set. Review and revise thresholds only with recorded benchmark evidence.
3. Calibrate and record the reranker score transformation for the exact model/profile on labelled query-candidate pairs before setting production cut-offs. 60 for control selection and 75 for candidate matching are initial operating values—not probabilities or cross-model comparable scores.
4. Load-test expected peak (initial planning assumption: 200 runs/hour and ~1,000 active users) and tune AI slots/worker replicas from measured throughput.
5. Run restore/recovery drills for Mongo, Redis loss, SQL outage, AI outage/rate limits, worker termination and stale leases.
6. Run security tests for entity/tenant isolation, key revocation, admin separation, dependency scanning, secret leakage, database least privilege, event stream access, source licensing, evidence-retention and monitoring exposure.
7. Test each workflow from API request to final persisted output, including zero scenarios, partial path failure, controls delayed, remediation rejection/regeneration, and event-stream reconnection.
8. Obtain explicit owner sign-off for the benchmark version, measured quality/load results, data-source licensing, residual risks and operational runbooks.

**Exit check**: all production gates in §14 pass, and the documented quality thresholds and capacity targets are met on the stated deployment profile. Any exceptions are quantified, documented and explicitly accepted; they are not labelled as quality gaps.

---

## 9. Remediation event API (#28) — full contract

### 9.1 Endpoint and execution model

`GET /v1/remediation/{remediation_id}/events` is a **Server-Sent Events (SSE)** endpoint. The HTTP request opens a long-lived stream. It does not generate a plan synchronously. Plan generation is asynchronous in `tsg_write_plan`; durable remediation status is held in MongoDB; workers publish status-change notifications through Redis pub/sub; each API pod relays events to its connected callers.

### 9.2 Authentication and authorization

Require `X-API-Key`, `X-User-Id`, `X-Entity-Id`, and `X-Tenant-Id`. Perform the ordinary key/identity validation before starting the stream. Load the remediation using both resource ID and authorized entity/tenant filters. Return ordinary RFC 9457 problem responses **before** streaming:

- 401: missing/invalid caller identity/key;
- 403: remediation belongs to another entity/tenant;
- 404: unknown remediation ID;
- 503: MongoDB/Redis required for a reliable initial status is unavailable.

Never disclose that another entity's remediation exists. Log stream opened/refused/closed with request ID, caller client ID and remediation ID; do not log the API key.

### 9.3 Event payload

Initial snapshot and each change use `event: remediation.updated`. Example:

```text
event: remediation.updated
id: rem-123:7
retry: 3000
data: {"event":"remediation.updated","event_seq":7,"remediation":{"remediation_id":"rem-123","scenario_id":"scn-1","session_id":"ses-1","latest_version":2,"latest_status":"running","accepted_version":null,"decision":"pending","progress":{"generation":"running","review":"pending","overall":"running"},"error":null,"updated_at":"2026-10-09T12:00:00Z"}}

```

`remediation` is the same `RemediationStatus` model returned by #15. `event_seq` is a monotonically increasing integer stored on the remediation record and incremented atomically whenever a published status transition is committed. The SSE `id` contains the remediation ID and sequence. The first message always gives the current snapshot, then the stream sends newer notifications. A 15-second comment ping keeps idle connections alive; headers include `Content-Type: text/event-stream`, `Cache-Control: no-cache`, and `X-Accel-Buffering: no`.

### 9.4 Ordering, reconnect and failure model

- **Write before publish:** save the new status/progress/error and increment `event_seq` in MongoDB before publishing to Redis.
- **Order:** each stream tracks the latest sequence it has emitted. Ignore duplicate/older sequence notifications. If sequence skips or an event payload cannot be validated, re-read the current status from MongoDB and emit a fresh snapshot.
- **Redis pub/sub is not durable:** do not promise replay of every intermediate event while a client is disconnected. The event stream is a status-notification channel, not an event ledger. On every reconnect, send a fresh authoritative snapshot; clients must treat the latest snapshot/status API response as truth.
- **Race-free subscription:** subscribe to the Redis channel before reading the initial Mongo snapshot; buffer incoming messages while snapshotting, emit the snapshot, then emit only buffered events with a higher sequence. This prevents an update between subscription and snapshot from being lost or emitted out of order.
- **Publisher failure:** business write remains successful because the durable status is already saved. Log/metric the publication failure; reconnecting readers get the current status. Do not roll back a saved plan because notification delivery failed.
- **Client disconnect:** release the subscriber; reconnect is safe. Workers do not depend on a client being connected to complete a plan.
- **Long-lived connection capacity:** enforce server/proxy timeouts, pings, connection limits and monitoring. Do not require sticky sessions; Redis fan-out handles multiple API pods.

### 9.5 Integration points

Call `publish_remediation_status(remediation_id, event_seq)` after every durable status/progress/version/decision/error transition: plan requested/queued, worker started, stage progress changed, plan version completed, retryable failure, terminal failure, accepted, rejected, regenerated, or the source-scenario conflict state changed. The route itself reads status; it does not trigger workflow actions.

### 9.6 Required tests

- Unit: event envelope schema, sequence comparison, duplicate/old sequence ignored, gap causes snapshot refresh, payload validation.
- Integration: auth before stream, first current snapshot, update after Mongo write reaches stream, no event before durable write, multi-pod Redis fan-out, reconnect snapshot, publisher outage does not undo plan, slow client and disconnect cleanup.
- Security: missing key, invalid key, wrong entity, wrong tenant, unknown ID, admin key not accepted as business key, no secret in logs/event payload.
- Performance/reliability: concurrent SSE clients, bounded memory per slow reader, ping/proxy timeout, disconnect/reconnect storm, event delay target <2 seconds under expected load.
- Contract: generated OpenAPI describes the endpoint; streaming response is documented as `text/event-stream`, not a normal JSON response.

---

## 10. Background tasks and state machines

### 10.1 Queues

| Queue | Task family | Worker |
|---|---|---|
| `tsg_threats` | initial threat identification and path planning | `worker-threats` |
| `tsg_scenarios` | initial/next-set/regeneration scenario writing, control mapping, remediation writing | `worker-scenarios` |
| `tsg_maintenance` | reaper, control retry sweep, library index builds, admin jobs and scheduled intel/technique refresh | `worker-maintenance` |

Task message = task name + record ID + epoch (and only other small stable routing identifiers if specifically required). Never serialize full scenario/context or credentials into Redis messages.

### 10.2 Run lifecycle

```text
queued -> running(threats) -> plan frozen -> running(scenarios) -> done
        \-> failed only for terminal/systemic errors
```

The scenario/control lifecycle dimensions are distinct: a scenario can be written and reviewable while control mapping is queued/running. `done` for the run means the selected generation work is complete or has reached a documented partial/exhausted outcome; control readiness is exposed via per-scenario state and `controls_waiting`.

### 10.3 Job lease invariant

Claim only when status is queued or an existing running lease has expired. Heartbeat at 30 seconds, lease 120 seconds, reaper every 60 seconds, maximum five job attempts. Every worker write must filter on the current task ID and epoch. When a caller submits next-set or regenerate, increment epoch; an old worker can no longer save over the newer request. Duplicate deliveries that cannot claim the job do nothing and are not counted as failures.

### 10.4 Status counts

Counts are derived from current scenario/path records, not independently incremented in many code paths. Use one aggregation, then a conditional write that prevents an older count calculation from overwriting a newer result. Define exactly how `planned`, `written`, `remaining`, `failed`, `abandoned`, `accepted`, `rejected`, `pending` and `controls_waiting` treat replaced versions, paths excluded by a positive scenario limit, and failure drafts. Unit-test the contract.

---

## 11. Error handling, timeout and retry policy

| Condition | Expected behaviour |
|---|---|
| Invalid input | 422 with safe field details. |
| Missing/wrong/revoked key | 401. |
| Other entity or tenant | 403; unknown ID | 404. |
| Active run, duplicate decision, generation in progress, no next paths, plan source unaccepted | 409 with stable machine-readable reason. |
| Body > `CII_MAX_REQUEST_MB` | 413. |
| AI/provider throttling/outage, store unavailable | 503 + `Retry-After` for synchronous API dependency errors; worker retries for async jobs. |
| AI response is invalid JSON/schema | bounded re-ask; after allowed attempts, path-specific failure or job failure according to the step rules. Never accept unvalidated AI JSON. |
| Unexpected exception | 500 with request ID to caller; stack trace/details only in protected logs. |
| Job lease expires/worker dies | reaper requeues; task/epoch fencing prevents stale writes. |
| Redis event publication fails after durable save | log/metric failure; do not roll back state; reconnect receives fresh status. |
| Intel feed unavailable | omit intel block and continue. |
| Empty canonical control library | clear `control_library_empty` failure and alert/retry; never invent canonical controls. |

Bound every network wait. Baseline values from the design: Mongo connection/wait bounded; SQL query 30 seconds; Redis 5 seconds; AI timeout per model profile. One AI call has up to 4 attempts total (3 in-call retries). A background job/path has its own attempt counter, up to 5 attempts with the delay sequence above. Do not multiply these without bounds; track both counters separately. Do not retry permanent validation/authorization errors.

---

## 12. Testing strategy and minimum acceptance matrix

### 12.1 Test layers

1. **Pure unit tests**: text normalization, hybrid retrieval/rank fusion, STRIDE filter, dedupe, actor match, path validation/ranking, count selection, scenario cleaning/rules, control selection/dedup, schedule/critical path, event ordering.
2. **AI contract tests**: fake provider returns valid, malformed, truncated, unknown-ID, wrong-dimension and delayed responses. Validate input/output schemas and bounded re-ask behaviour.
3. **API tests**: schema validation, status codes, RFC 9457 bodies, auth, entity/tenant filter, idempotency, pagination, OpenAPI compatibility.
4. **Integration tests**: real MongoDB/Redis and disposable SQL test schema/seed; actual stored-procedure calls; end-to-end task enqueue, worker claim, persistence and event publish.
5. **Concurrency/fault tests**: simultaneous starts, double accept/reject, next-set race, duplicate Celery messages, killed worker, expired lease, Redis unavailable, SQL outage, AI throttling, SSE reconnect.
6. **Regression/golden tests**: use versioned prompts, canonical-library stamps and frozen expected fixtures; evaluate representative and adversarial cases against expert-reviewed expected outcomes. When models change, compare quality metrics and perform targeted review before release.
7. **Performance/security tests**: load profile, p95 latency, AI slot saturation, tenant isolation, key lifecycle, secret/log scanning, dependency/image scan and database least privilege.

### 12.2 Mandatory cases before moving to the next step

| Area | Minimum cases |
|---|---|
| Configuration | `TOTAL_SCENARIO_COUNT` values 0, 1, N, >candidate count; negative, float, string invalid; alias found consistently in `.env` files. |
| Start run | valid request; duplicate idempotency replay; key reused for another asset; wrong entity; unlinked system; invalid sector/subsector; two simultaneous starts; SQL/Mongo/Redis outage. |
| Threat finding | all six STRIDE categories; irrelevant shortlist expands to remaining library records; gap-fill occurs only after full-category scan; category fails twice; no active capable actor in the library; AI-suggested actor maps only to an eligible library ID; actor-name similarity alone cannot qualify an alternate; untyped/actor-ineligible candidate is saved for curation but excluded from path selection; eligible non-canonical AI/CTI candidate can produce a scenario without being promoted, and promotion remains explicit/idempotent. |
| Path planning | valid 1-step path; valid chains of variable length through configured `CII_MAX_ATTACK_PATH_STEPS`; cycles/repeated nodes rejected; invalid/missing technique-edge evidence rejected; cross-system chain rejected when environment topology/identity route is absent; path expansion budget produces `budget_limited` + coverage warning; path deduplication; stable deterministic rank; category/system coverage without bypassing the eligibility floor; incompatible step actors split/rejected unless an evidence-backed handoff exists; route status does not depend on system count; no artificial filler. |
| Scenario selection | all six examples in §1; ranking precedes count application; zero valid paths = zero generated; next-set cannot exceed selected count. |
| Scenario writing | malformed JSON; unsupported field; invalid category; unique title; risk wording; opaque-code cleanup; one repair; one consistency rewrite; blocker prevents eligibility/acceptance/ordinary visibility while optional audit draft remains quarantined and non-servable; warning is visible; no ordinary acceptance can bypass evidence, tenant or source-rights blockers; repeated failure becomes abandoned. |
| Controls | both scenario statement and risk statement included in query; asset-type compatible pool; 40 candidate cap; reranker score validation; cutoff and nearest fallback; twin dedupe; unknown control rejected; empty library explicit failure. |
| Review | accept/reject mutual exclusion; only one accepted version per path; replacement and older-version policy; generation-in-progress 409; repeated requests idempotent; promotion works for accepted AI/CTI candidate keys, remains pending/inactive and is idempotent. |
| Remediation | accepted scenario precondition; manual input idempotency; snapshot immutability; controls top-up and deadline; invalid control/system/owner rejected; dependency cycle rejected; deterministic schedule; version history; only one accepted version. |
| Remediation events | initial snapshot; ordered and deduplicated `event_seq`; update after persisted write; gap re-sync; reconnect snapshot; wrong entity/tenant refused; pub/sub failure; slow client/disconnect. |
| Workers | lease/heartbeat/fencing; retry delays; max attempts; duplicate delivery; queue re-send only if broker queue has no waiting message; all tasks registered/routed. |
| Threat intelligence | OTX key is secret-injected; pulse pagination is idempotent; exact IOC match requires an approved asset indicator; pulse author/tag/IP geolocation alone cannot attribute an actor; duplicate syndicated pulses count once; stale data is labelled; source prompt injection, XML/archive bombs and OTX outages do not corrupt/fail the live pipeline; NVD watermark/pagination recovers after a partial failure; EPSS scores keep their score date; a source not `approved` by the terms gate cannot be activated/indexed, and an approved source later downgraded to `conditional`/`blocked` is removed from active retrieval with a terms-compliant purge/restriction job. |
| Evidence/realism | evidence-mode labels distinguish source-documented behavior, technique-informed chains and hypotheses; every transition has a source/approved rule and preconditions; source-extracted sequences contain valid technique IDs and exact source spans; a technique list without explicit order creates no transition edge; no unsupported CVE/product/actor or inferred asset compromise; scenario includes objective, initial condition, causal transitions and business consequence; a non-canonical candidate can be scenario-eligible without being promoted, but only after every eligibility gate passes. |
| Production | UAT smoke, end-to-end workflows, load, worker-crash/restore drills, alert test, TLS/access-control review, rollback rehearsal. |

### 12.3 Performance targets

Use these as initial targets until UAT load testing replaces assumptions with measured capacity:

- status/results/list read p95 < 300 ms;
- start/accept/reject/next-set/regenerate API response p95 < 500 ms (long work is asynchronous);
- first six eligible scenarios p95 < 10 minutes, subject to AI provider speed/quota;
- saved state to SSE client update < 2 seconds;
- availability target 99.5% during business hours;
- recover interrupted jobs within 3 minutes;
- load target currently assumes ~200 runs/hour and ~1,000 active users, with at least two API pods and horizontally scaled workers in UAT/prod.

A target is not evidence. Record the actual test hardware, model versions, input mix, concurrency, p95/p99, errors, tokens and queue wait for sign-off.

---

## 13. Security, audit and production safeguards

- **Identity**: key validation on every business request; user, caller client, entity and tenant recorded. No API key in browser code, prompts, logs, error details or event payloads.
- **Isolation**: entity/tenant filters on every data access and subscription. Negative tests attempt cross-entity and cross-tenant reads, lists, decisions, streams and job-status access.
- **Least privilege**: SQL app login can execute only required stored procedures, not directly read/write platform or library tables. Mongo roles limited to the app database and required operations; Redis protected by credentials/TLS as required.
- **Secrets/config**: deployment secrets injected by Secret references, `.env` files excluded from version control, rotate production keys, no secret printed by smoke/debug scripts.
- **LLM safety**: prompt input is treated as untrusted data; use allowlisted context snapshots and strict schemas. The model cannot own library IDs, STRIDE classification, count, selected path IDs, review decisions, control identity, schedule dates or persistence state.
- **Audit**: append-only audit record for key mint/revoke, run request, scenario accept/reject/regenerate, promotion, plan request/regenerate/accept/reject and every admin curation/import action. Record actor user and caller `client_id` to distinguish direct platform calls from chatbot calls.
- **Network and TLS**: verify edge TLS on the existing OpenShift route; enable TLS for managed Mongo/Redis in production where supported/required; explicitly validate network egress for the AI gateway and intel sources. Do not expose internal service ports publicly.
- **Observability exposure**: monitoring and alert-management endpoints must be private by default. Production release is blocked until protected access is configured and tested, or a narrowly scoped exception is formally risk-accepted. Review Loki write access and Alertmanager silence permissions; read-only dashboards do not make every observability endpoint safe.
- **Audit/data retention**: confirm whether prompts/responses may contain regulated or sensitive asset details. Enforce the 14-day AI call TTL and 365-day audit retention unless a formal owner decision sets different retention. Restrict access to stored prompts/responses.
- **Threat-intelligence operations**: expose per-source last-success/check age and last-change age separately, refresh duration/failure count, staged/active record counts, catalogue stamps, revoked-record count, duplicate/correlation clusters, technique retrieval count, relevance pass rate, supported-edge rejection count, CTI gap candidates, path-search expansion usage/budget-exhaustion rate, evidence citation validation failures and query/index latency. Alert when the source-specific freshness policy is breached; never log API keys or raw sensitive tenant incident data.

---

## 14. Deployment and production readiness

### 14.1 Local developer run

1. Create `.env` from `.env.example`; configure local SQL Server, MongoDB, Redis and model credentials.
2. Apply `scripts/sql/*.sql` and `grants.sql` to the disposable dev database.
3. Run tests and `ruff`/`mypy`; verify `TOTAL_SCENARIO_COUNT=0` from settings inspection.
4. Start worker processes for all three queues and Celery beat.
5. Start API; confirm `/health`, `/ready`, `/metrics`.
6. Mint a caller key using the admin endpoint, save it in the local calling backend, and run the documented smoke workflow.
7. Generate scenarios against a seeded test asset; check logs, Mongo state, control mapping and SSE. Use isolated local database names, Redis databases/key prefixes and Celery queues for this new service.

### 14.2 CI gates

Every pull request must run:

- formatting/lint, type checks and unit tests;
- code-layer guard and configuration/env alias sync tests;
- SQL script lint/schema integration tests where configured;
- API schema/OpenAPI backward compatibility test;
- collection/index declaration tests and task registration/routing test;
- dependency vulnerability and container-image scans;
- event stream and tenant isolation tests for any change touching API/data/events.

A release tag cannot be created from a red pipeline.

### 14.3 UAT rollout and rollback

1. Build and tag immutable image; publish it to the approved registry.
2. Create/update ConfigMap and Secret from `.env.uat`; verify no secrets are exposed in rendered manifests.
3. DBA deploys stored procedures and grants; confirm app login least privilege.
4. Confirm this deployment uses its own queue names, Redis key prefixes, secrets and database configuration; verify only the intended new workers consume its messages.
5. Deploy queue workers; deploy beat; verify queue/task registration.
6. Deploy API and route with edge TLS; wait for `/ready` 200.
7. Apply observability using the approved access configuration; verify targets, dashboard and alerts.
8. Run smoke, complete workflow tests, golden/regression quality evaluation, security checks and load tests.
9. Rehearse rollback to previous image and, if required, matching prior SQL scripts. Mongo schema evolution must be backward-compatible/additive until a release is proven.

### 14.4 Go-live checklist

- [ ] All documented endpoints #1–#28 are implemented and described in generated OpenAPI.
- [ ] ATT&CK Enterprise/ICS + CAPEC catalogues are version-stamped; CISA KEV/cybersecurity/ICS-advisory, NVD CVE/CPE and FIRST EPSS adapters run; the OTX key is stored as a secret reference, the subscribed-pulse adapter passes fixture/mock tests, and any live integration test runs only after the source-terms gate approves its use; optional MISP/abuse.ch/UAE/sector/internal sources are enabled only when source-specific terms and data handling are approved.
- [ ] Technique evidence influences retrieval/path validation/writing/control mapping; sources are not merely included in a generic writer prompt.
- [ ] The external transition graph contains no unsupported edges; every multi-step path has evidence-backed transitions and valid preconditions.
- [ ] Canonical threat/type/actor/control IDs remain controlled by approved TSG libraries. A CTI gap candidate may be used in a scenario only after the explicit eligibility gates pass; its master-data status remains non-canonical/pending until curator promotion, and it never creates a canonical ID automatically.
- [ ] Source outage/staleness, source-rights revocation/purge, attribution/display, product-version mismatch, tenant-scope, poisoned-content, redirect/SSRF, evidence-retention, route-status, candidate-before-promotion and stale-index rollback tests pass.
- [ ] `TOTAL_SCENARIO_COUNT=0` creates no arbitrary ceiling and includes every valid selected path; positive count generates at most N highest-ranked paths; zero valid paths generates zero scenarios.
- [ ] Business rules are mapped to code and tests; no unsupported threat, actor, control, system, impact, or date is introduced by AI.
- [ ] Both scenario statement and risk statement are used to retrieve/rerank controls.
- [ ] All saved controls refer to canonical active library records and include rank/match/source metadata.
- [ ] Sessions, scenarios, decisions, remediation versions, and admin jobs survive worker restarts; duplicate jobs cannot overwrite newer state.
- [ ] Entity/tenant isolation, key rotation/revocation, admin separation, secret handling and SQL least privilege pass security tests.
- [ ] Remediation SSE has ordered sequence handling, current snapshot on reconnect, auth tests, and the documented best-effort notification guarantee.
- [ ] Operational alerts fire in UAT and have a real notification channel or an accepted no-notification decision.
- [ ] Monitoring exposure and datastore TLS decisions have written security approval.
- [ ] Mongo restore, Redis failure, SQL outage, AI outage, kill-worker and rollback drills pass.
- [ ] Labelled-benchmark quality metrics, load/performance evidence and remaining risks are reviewed and signed by the owner.

---

## 15. External source references and operating rules

These are implementation references, not a claim that every item is enabled in every deployment. Re-check the provider's current version, licensing/terms, API limits and schema during source onboarding.

- [MITRE ATT&CK STIX data (Enterprise, ICS and Mobile release bundles)](https://github.com/mitre-attack/attack-stix-data) — preferred machine-readable behaviour catalogue.
- [MITRE ATT&CK data and tools / TAXII](https://attack.mitre.org/resources/working-with-attack/) — official alternate access path; bulk release bundles are preferred over frequent per-query TAXII calls.
- [MITRE ATT&CK Terms of Use](https://attack.mitre.org/resources/terms-of-use/) and [usage/data guidance](https://attack.mitre.org/resources/working-with-attack/) — preserve the required copyright attribution; use tactics/techniques/procedures as a behaviour model, do not claim 100% technique coverage or treat matrix order as a universal attack sequence.
- [MITRE CAPEC downloads](https://capec.mitre.org/data/downloads) and [CAPEC Terms of Use](https://capec.mitre.org/about/termsofuse.html) — attack-pattern catalogue and mappings; reproduce MITRE copyright/license notices when copying.
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [official KEV JSON feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json), [KEV data license](https://www.cisa.gov/sites/default/files/licenses/kev/license.txt), and [CISA Cybersecurity Advisories](https://www.cisa.gov/news-events/cybersecurity-advisories) — exploitation and procedure/advisory evidence, with exact asset applicability checks and original advisory citations. The catalog feed is also mirrored as CSV/JSON with a CC0 license in the official [CISA KEV data repository](https://github.com/cisagov/kev-data); third-party links referenced by an entry retain their own terms.
- [NVD CVE/CPE APIs and data feeds](https://nvd.nist.gov/developers) — use current API 2.0 endpoints and incremental modification windows; legacy API 1.0 endpoints are retired. Follow official pagination and rate limits.
- [FIRST EPSS data/API](https://www.first.org/epss/data.html) — daily CVE exploitation-priority signal; use daily data exports for bulk refresh and API lookups for specific CVEs, with score dates preserved.
- [AlienVault OTX API](https://otx.alienvault.com/api), [OTX Python SDK](https://github.com/AlienVault-OTX/OTX-Python-SDK), and [OTX End-User Agreement](https://www.levelblue.com/legal/otx-eula-terms) — use subscribed pulses/typed indicators only after the deployment’s precise API/data/service use is licensed. The current EULA says OTX is free for non-commercial use and restricts commercial exploitation/third-party service use; obtain written authorization or an applicable commercial agreement before using it in commercial TSG. The SDK is open-source software but does not grant service/data rights.
- [ThreatFox Community API](https://threatfox.abuse.ch/api/), [URLhaus Community API](https://urlhaus.abuse.ch/api/) and [MalwareBazaar Community API](https://bazaar.abuse.ch/api/) — optional malware/IOC enrichment. Their community API docs warn that commercial/for-profit use may require an enhanced paid subscription; confirm terms before activating in a commercial service.
- [MISP default OSINT feeds](https://misp-project.org/feeds/) and [MISP open-source platform](https://github.com/MISP/MISP) — optional approved feed integration/platform. The MISP software license is not automatically the license for each feed's data. Retain original feed provenance to avoid double-counting syndicated records.
- [UAE Cyber Incident Response Plan](https://u.ae/en/about-the-uae/strategies-initiatives-and-awards/strategies-plans-and-visions/Cypersecurity/Cyber-Incident-Response-Plan), [UAE Cyber Security Council — State of Scams in the UAE 2024](https://prod.csc.gov.ae/en/w/the-2024-state-of-scams-in-the-uae), and [State of UAE Cybersecurity Report 2025 announcement](https://www.wam.ae/en/article/bidpi10-uae-cyber-security-council-cpx-unveil) — regional/sector context sources. Ingest reports with their publication date, scope, methodology/metric definition and citations; use them for prioritization context, not as a real-time feed unless one exists. Do not assume that every statistic is a count of confirmed attacks or incidents.

**Procedure-to-path invariant:** use source-documented ordering only when the source explicitly explains the sequence and deterministic validators confirm every cited technique ID, source span and precondition. A technique’s appearance in the same report, an ATT&CK group association, or a model-generated rationale is not enough to create an edge. Keep the raw source/reference provenance available to authorized reviewers subject to licensing and retention limits.

**Important data interpretation rule:** reported cyber-attack volumes vary by reporting period and whether the number means blocked attempts, detections, incidents, or confirmed compromises. Store that definition with a statistic. Do not translate a headline number into a likelihood or risk score for a particular asset.

## 16. End-to-end worked example

**Input**: entity `86`; asset `103` “Grid control centre”; systems `321` “SCADA historian” and `322` “Remote access VPN”; `TOTAL_SCENARIO_COUNT=0`.

1. The platform calls #1 with identity headers. TSG verifies ownership/system links, freezes the context and returns 202 with a session ID.
2. The threats worker searches each STRIDE category using asset and system queries. Suppose it retrieves 34 candidate threat records. AI relevance validation keeps 9; no category requires gap-fill. Deduplication removes one duplicate, leaving 8 validated threats. Each threat has a traceable reason, impacted system(s) and a library actor.
3. Path planning groups coherent threats into candidate attack paths. Suppose it finds 18 valid paths after validation and deterministic ranking. All 18 are written into the frozen run plan. Because count is zero, all 18 are selected for generation.
4. The scenario worker generates the first six paths. One scenario describes a credible sequence leading to loss of grid-control capability; code cleans its title, validates its risk statement and route, and persists it. Each completed scenario is visible before control mapping has to finish.
5. The control worker constructs a query using the scenario statement **and** the risk statement, the threat/path, actor, asset/technology, and involved systems. Hybrid search returns up to 40 controls from the compatible `AssetType` pool. The reranker scores them; TSG keeps every score ≥60. If none passes the threshold, it retains the single nearest canonical library control with a warning. It never invents a control record.
6. The platform reads #2/#3 or receives #8 SSE updates. The reviewer accepts one scenario through #4; the decision is atomically saved and audited. A request to generate the next set writes the next six eligible paths. With a positive count such as 5, only ranks 1–5 would ever be eligible, even if more paths were identified.
7. For an accepted scenario, the platform calls #11. TSG freezes scenario, risk, control and register data, queues the plan and returns 202. The remediation worker drafts actions; code validates control references/dependencies and computes dates. #15/#16 expose status/result; #28 streams `remediation.updated` events. On reconnect, #28 sends the latest authoritative snapshot.
8. After UAT sign-off, deploy the scenario, control, decision and remediation workflows with monitored queues, verified recovery, secured observability, TLS/access review and recorded benchmark-quality evidence.

---

## 17. Final implementation rule

**Build the data contracts and deterministic rules first, then the smallest end-to-end API, then the AI engines, then review/remediation, and finally operational hardening.** Every generated item must be traceable to frozen input, canonical library records where applicable, and the versioned intelligence evidence/transition edges that support it. CTI candidates remain visibly non-canonical until curated. The configured count controls selection only; it never changes what the identification stage found, and it never authorizes filler content.
