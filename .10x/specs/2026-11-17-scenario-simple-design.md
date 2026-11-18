# Plan: make the scenario module simple (safe plan, about -880 lines, no behaviour change)

## Context

**The ask (17 Nov 2026):** the codebase is still over-engineered: `app/` is 26,188 lines for a simple application. Start with
the scenario module (threat scenario generation), then remediation and the service mapper in later rounds.

**What was done to plan it (read-only):**
- A 223-agent audit of the scenario code (about 10,600 lines with the evidence code): 22 finders, every finding checked by
  skeptics, three maps (flow, runtime mechanisms, test constraints), one critic.
- A design pass: nine lane planners, one integrator, three critics (file conflicts, frozen contracts and tests, the owner's
  decisions), one revision.

**What the audit showed:** most of the scenario code is real rules and safeguards. The accidental part is classes that only
hold injected dependencies (the scenario service holds 11), data passed through three or four shapes before it is stored,
leftovers of the removed intel sources, one-use helpers and never-read stored fields.

**The owner's decisions (17 Nov):**
- Depth: the safe plan. Every rule, retry and safeguard stays; nothing a user sees changes.
- Of the user-visible cuts, only never-read stored fields go. Control matching stays its own job; AI re-ask, batch halving
  and the writer's rewrite round stay; text shaping, spare paths and repeat checks stay.
- Evidence comes from MITRE ATT&CK Enterprise and ICS only; everything left from the other sources goes.
- Dead enum values of the removed sources are removed and `tests/contract/enums.json` is re-pinned for exactly those.
- Tests are rewritten to match: every behaviour test kept, only how it reaches the code changes.

**Expected result:** `app/` 26,188 -> about 25,300 lines (scenario code about 8% smaller), about 40 more from the enum re-pin.
The scenario service class, the intel service class and about ten dependency-holder classes become plain functions;
`worker/scenario` goes from 5 files to 4; `app/core/callables.py` and `app/domain/library/` are deleted.

## How the owner's answers settle the plan's open gates

- **G1 = yes.** The owner chose "never-read stored fields", so the stored-record goldens are regenerated for the removed
  never-read keys only (gate 5 below lists the allowed differences). Prompts stay byte-identical.
- **G2 = no.** About 8 lines for touching two prompt goldens: skipped. Lane D applies W11's Counter part instead.
- **Enum re-pin = yes.** Added as a third lane of wave 3: delete the removed-source members (4 `IntelKind`, the
  `Applicability` enum, `EvidenceRole.DIRECT`, `EvidenceDecision.NOT_APPLICABLE` and `NO_PRODUCT_LINK`,
  `EvidenceReason.NO_PRODUCT_LINK`, `EvidenceFact.KEV_LISTED`, `RANSOMWARE`, `ADVISORY`, `IntelState.QUARANTINED`); grep each
  for zero app uses first; switch the about 12 test files that use one as a sample value to a live one; regenerate
  `tests/contract/enums.json` and check its diff holds these removals and nothing else. `Evidence.applicability` stays a
  stored key typed `str | None` (frozen API field). The 4 dead `FindingCode` members are not part of this (not a
  removed-source leftover).
- The other "needs the owner" items in section 5 keep the default shown in brackets there.

## Step 0, before any code (10x-team state, then start)

1. Copy the two workflow results into the repo so they survive a reboot: the audit
   (`C:/Users/gopal/AppData/Local/Temp/claude/436ea5bf07340f16/f582bceb-48e6-4f0b-9a21-10840e7dcff2/tasks/wtoirjm5x.output`) and the design with every lane's change list by id
   (`C:/Users/gopal/AppData/Local/Temp/claude/436ea5bf07340f16/f582bceb-48e6-4f0b-9a21-10840e7dcff2/tasks/wd06q3xwy.output`), both under the session's temp folder, to `.10x/reviews/2026-11-17-scenario-audit.json`
   and `.10x/specs/2026-11-17-scenario-lanes.json`. The change ids used below (R1, W2, intel-4, IS-1, ...) are defined there.
2. Write `.10x/specs/2026-11-17-scenario-simple-design.md` (this plan), `.10x/adrs/007-scenario-plain-functions.md`
   (decision: plain functions and module-attribute seams; alternatives: controls merge, visible cuts, rebuild: all declined
   by the owner), the role notes under `.10x/decisions/*/scenario-simple.md`, and update `status.md` and `handoff.md`.
3. No commit or push without asking the owner.

Execution: one workflow per wave (parallel lanes as in the tables), a gate after each; tests run with `pytest -n 6`
(pytest-xdist is installed; MongoDB must be running).

Checked against the code: golden compare uses `sort_keys=True` (tests/scenario_goldens.py:48); `ControlMessage` is not in tests/contract/enums.json; `PathProblem`, `ReviewFlag`, `IntelState` are pinned (members stay); `app/domain/scenario/` and `schemas/scenario_internal.py` are exempt from the 500-line cap, `app/worker/` is not; `callables.py` has 3 importers. The working tree already holds staged changes to 4 tests/contract files and session_start.json, so every gate compares against a recorded baseline, not against git. tests/test_ai.py:1313 already patches `write_job.get_scenario_chat_model`, so only line 1320 of that test changes.

Two owner answers are asked BEFORE wave 0 (section 5, G1 and G2). A change marked [G1] or [G2] is applied only on a yes; without it the change is dropped and nothing else in the plan depends on it.

## 1. Target shape (lines now -> after, approximate)

| File | Now | After | Holds afterwards |
|---|---|---|---|
| app/domain/scenario/runs.py | 560 | ~530 | Plain functions (no ThreatScenarioService, no getter); promote helpers folded in from library/curation.py |
| app/domain/scenario/session.py | 835 | ~816 | Same public functions and signatures; no missing_facts [G1], no counts.replaced [G1] |
| app/domain/scenario/plan.py | 899 | ~860 | Same public functions; no pool passed around; GapFillResponse stays; no turns/groups, prompt_version, library_stamp [G1] |
| app/domain/scenario/write.py | 1022 | ~940 | No class: map_controls(rerank, ...) returns the stored dict; no ControlRule/ControlMapping/_ScenarioInSet; evidence branches and blocked cards unchanged |
| app/worker/scenario/write_job.py (+ path_writing.py, deleted) | 193+273 | ~415 | BatchWriter, PathWriter, PathSaver; write_scenario_batch(lease) fetches its own models |
| app/worker/scenario/tasks.py / plan_progress.py / controls_job.py | 114 / 144 / 281 | ~103 / ~126 / ~236 | 4 Celery tasks; plan_run(lease, find_threats, switch) and plan_it unchanged; PlanProgress(lease, run); RunControls with _renew, _give_back |
| app/crud/scenarios.py / work_control.py | 668 / 270 | ~645 / ~250 | Two repository classes stay (the `served` condition too); get_asset_context function; work_control plain functions |
| app/domain/jobs.py, api/routes/scenarios.py, api/deps.py | 308 / 214 / 144 | ~288 / ~200 / ~136 | Call `runs.fn(...)` and `work_control.fn(...)` through the module |
| app/schemas/scenario_internal.py | 442 | ~385 | No MappedControl, ControlRule, ControlMapping; PlannedActor, GapFillResponse, BriefSystem, FrozenContext.from_record stay |
| app/core/callables.py, app/domain/library/ | 12, 48 | 0, 0 | Deleted |
| constants/scenario.py, evidence.py, shared/names.py, parallel.py | 261 / 260 / 181 / 45 | ~248 / ~255 / 174 / ~41 | Same, minus the severity tables and TOKEN_MAX_CHARS |
| Intel: domain/intel/**, worker/intel.py | 2677 | ~2380 | Functions in admin, evidence, refresh, facts; state-holding classes stay; switch.py untouched |
| Intel store: intel_records.py, crud/intel.py, schemas/intel.py, constants/intelligence.py | 434 / 201 / 111 / 141 | ~360 / ~191 / ~99 / ~137 | No stored quarantine rows (FetchResult.rejected stays), no paged-feed fields, no SnapshotDescription |

Expected app total: 26,188 -> about 25,300 (about -880; about -815 if G1 and G2 are both "no"). Each merged pair is counted once. Record the real number at every gate; do not chase the estimate.

## 2. Waves

Rules inside a wave: a lane edits only the files listed for it. All lanes share one working tree, so a lane's own test runs during the wave are advisory; the gate decides. Lanes edit code and tests only: NO lane regenerates a golden. No agent runs `git add`.

### Before wave 0 (one agent)
Record in the scratchpad the sha256 of tests/contract/*.json, app/prompts.toml and every tests/goldens/scenario/*.json (the baseline). Get the owner's answers to G1 and G2.

### Wave 0 (one agent, serial): shared shapes and the pure file move
Owns: schemas/scenario_internal.py, core/constants/scenario.py, core/constants/evidence.py, worker/scenario/path_writing.py + write_job.py (move only), plus the consumer edits named here.
- Worker W1: move path_writing.py into write_job.py unchanged and delete it (classes stay three; file about 448 lines). Tests (import or patch target only): test_run_actions.py:52,531,542; test_scenario_sets.py:23,174,180; test_scenario_goldens_write.py:18; test_scenario_writing.py:66.
- Shapes S4: one severity rule; delete FINDING_SEVERITIES, FINAL_FINDINGS, STORY_FINDING_SEVERITIES. Tests: test_scenario_writing.py:18-19,131-134,581.
- Shapes S13 = worker W7(4): delete TextCleaning.TOKEN_MAX_CHARS and PathFailure.final (+ the `final=True` argument, now in write_job.py). Test: test_scenario_set_cut_off_half.py:59.
- [G1] S8 = session S2: delete FrozenContext.missing_facts, session.py:52-57, the runs.py:146 details line. Tests: test_property_selection.py:216-220 deleted, test_scenario_goldens_session.py:149; golden session_start.json regenerated by the gate agent.

### Wave 1 (8 lanes in parallel)
| Lane | Files owned | Change ids | Test files |
|---|---|---|---|
| A runs+routes | domain/scenario/runs.py, api/routes/scenarios.py, api/deps.py, api/status_stream.py, domain/jobs.py | R2, R3, R4 (scenario side), R5, R6, R7, R8 | test_admin_and_intelligence_rules.py:23-35 (first; lane G edits it after), test_entity_scenario_count.py |
| B crud | crud/scenarios.py, domain/remediation/plans.py (line 265 only) | crud-3, crud-5, crud-6 (scenarios.py part) | test_scenario_sessions.py:63-65 |
| C plan | domain/scenario/plan.py, domain/shared/parallel.py, domain/shared/names.py, schemas/scenario_internal.py (the library_stamp field only) | plan-3, plan-4 (full), plan-5, plan-7; [G1] plan-1, plan-6 (prompt_version key), library_stamp (plan.py:716 + the ThreatFindings field) | [G1] test_attack_paths.py:205-212,302 and test_scenario_goldens_plan.py:77 |
| D write | domain/scenario/write.py, scripts/scorecard.py | W8, W9, W10, W11 (`now` part), W6 (signature side); [G2] W5 and S12 reduced to write.py:636,640 (line 349 stays); if G2 is "no": W11's Counter part instead | test_evidence_story.py:43,366,593-594, test_scorecard.py, test_scenario_writing.py:193-198 (the 4 W6 rows); [G2] test_evidence_at_write.py, test_off_equals_original.py, test_mandatory_evidence.py, test_scenario_writing.py:886 |
| E session | domain/scenario/session.py | S3, S7; [G1] S4 (counts.replaced) | [G1] test_replacement_job.py:80,160,185 |
| F worker | worker/scenario/* | W2 (a) and (b) only, W3 (parameter still named mapper), W4, W5, W7(1-3), W8; the build_failure_card caller: PathSaver.save passes `self._threats[path["steps"][0]]` | test_writing_job.py, test_run_actions.py:101,117, external_intelligence/test_end_to_end.py:70-75, test_control_mapping.py:492-506, test_controls_fixes.py:72,99, test_attack_paths.py:308-309 (after lane C), test_ai.py:1320, test_scenario_goldens_controls.py:112 |
| G intel store+refresh | domain/intel/refresh.py, sources/*, safety.py, patterns.py, worker/intel.py, crud/intel.py, schemas/intel_records.py, schemas/intel.py, constants/intelligence.py, constants/__init__.py | intel-1, IS-3 = intel-6, IS-1 (store side only), IS-7, intel-12 (reduced), IS-5 | tests/external_intelligence/{operations,records,sources,models}, evidence_fakes.py:117-119,160-219, conftest.py:55, test_intel_worker_jobs.py:143, test_d51_admin_jobs.py:69,132, test_d51_mongo.py:41,61, test_admin_and_intelligence_rules.py:22,62-68 (after lane A), switch/test_switch_admin.py:128 (before lane H) |
| H intel admin | domain/intel/admin.py, api/routes/intel.py | intel-2 | external_intelligence/fakes.py + its 8 callers (test_switch_admin.py:67 after lane G), test_intel_admin_api.py, test_d51_admin_jobs.py:176-178 (after lane G) |

Corrections to the lane texts:
- Worker W2(b): map_threat_scenario_controls calls get_library_search() and get_rerank_model() before claim_controls_delivery and keeps `.snapshot()` AFTER the claim, where it is today (lease and retry mechanics unchanged).
- Worker W2(c) is skipped: plan_run keeps (lease, find_threats, switch) and the plan_it closure stays; W8 only deletes the made_with lines in plan_run.
- IS-1 store side only: save_intel_records(records, fetched_at) -> int (new versions); delete the quarantine write, SaveCounts and RejectedRecord.as_doc. FetchResult.rejected and a plain 3-field RejectedRecord stay, so the four safety tests pass unchanged and the refresh log keeps `quarantined=len(result.rejected)`. The dead guard at index.py:80-81 moves to wave 2 step 1.
- intel-12 reduced: `_technique_from` (38 lines, cap 40) keeps its two tuple parameters and flat_strings stays in sources/common.py; test_poisoned_sources.py is not edited. sort_into and limit_rejected are inlined as the lane wrote (cap kept).
- W6: build_failure_card takes `threat: dict`; its caller line belongs to lane F (above).

Sequenced shared test files (first lane, then second): test_admin_and_intelligence_rules.py (A, G); test_attack_paths.py (C, F); test_d51_admin_jobs.py (G, H); switch/test_switch_admin.py (G, H).

Wave 1 golden step (one agent, after all lanes are in and gates 1 and 3 pass): regenerate with `CII_WRITE_GOLDENS=1`, one test file at a time, in the order plan -> controls -> write -> session; apply gate 5 after each file.

### Wave 2 (serial steps, one agent each, in this order)
1. Intel search step. Files: domain/intel/index.py, facts.py, evidence.py, sources/attack.py:103, worker/intel.py, worker/lifecycle.py, schemas/intel_records.py, worker/scenario/write_job.py. Ids: intel-4, intel-5, intel-7 (with the index.py:80-81 guard), IS-6, intel-8 = IS-2, IS-4, intel-9 (reduced: reuse_for gone and direct getters; the per-search pointer check stays), intel-3 together with worker W6 (BatchWriter calls `evidence.attach_evidence`; no EvidenceAtWrite, no EvidenceParts). Tests: tests/external_intelligence/{evidence,search,concurrency,worker}, evidence_fakes.py, tests/conftest.py (clear evidence._scored), test_evidence_outage_words.py, test_control_query.py:120,132.
2. Service to functions. Files: runs.py, routes/scenarios.py, deps.py, domain/jobs.py, crud/work_control.py, crud/scenarios.py, worker/scenario/controls_job.py:84, domain/remediation/plans.py:251, domain/shared/audit.py, domain/library/* (deleted), api/routes/admin.py. Ids: crud-1, crud-4, crud-6 (work_control part), crud-2, R1 (written directly against `work_control.fn` and `get_asset_context`, so tests/service_builders.py and the 10 test files are rewritten once), shapes S3. audit.py gets one line and no inspect: `principal = kwargs.get("principal") or next(arg for arg in args if isinstance(arg, Principal))`. Tests: the 11 files of R1, 7 of crud-1, 6 of crud-2, test_promotion.py, test_admin_and_intelligence_rules.py:24,41-46, test_ai_usage.py:363.
3. Control mapping shape. Files: write.py, schemas/scenario_internal.py, controls_job.py, worker/remediation.py (mapper argument only), constants/planning.py. Ids: write W1 + shapes S1 as one pass; [G1] write W3 + W4 = shapes S2 in the same pass. pick_controls_to_keep takes four plain numbers (write W2 rejected: tests pass min above max, which Settings refuses); map_controls reads the settings. With G1: made_with keeps the 6 read keys and ControlMessage.NEAREST_ONLY, SHORTFALL, OTHER_TYPE are deleted. Without G1: the stored record stays byte-identical; if pick_controls_to_keep then passes 40 lines, do W1 only. Tests: test_control_selection.py, test_control_mapping.py, test_ai_controls.py, test_control_query.py, test_remediation_plan.py:1052, test_query_instruction.py, plan_job_fakes.py, test_scenario_goldens_controls.py; [G1] goldens controls_cards.json, controls_cases.json (regenerated by the gate agent).

### Wave 3 (2 lanes in parallel)
- Sweep of names with no user left. Files: core/constants/common.py (PromptVersion.PLANNER if plan-6 ran; SCENARIO_WRITER, SCENARIO_WRITER_EVIDENCE if W5 ran), constants/scenario.py (PlanTraceLimits.ASSET_ITSELF if plan-1 ran), core/callables.py deleted with crud/admin.py:110 annotated directly (shapes S9), EvidenceCorpus.rows. Grep each name for zero uses before deleting. No test or golden file changes.
- Docs. Files: docs/SOLUTION_DESIGN.md (.docx edited in place where that is the source; D14 on turns and groups, D36 planner label, lines 330 and 338), API_DEVELOPER_HANDBOOK.md, API_CONSUMER_GUIDE.md:77, TSG_END_TO_END_FLOW.md:216: only for what was really applied. Code is truth; keep it short.

## 3. Test seam (old -> new)

| Old seam | New seam |
|---|---|
| tests/service_builders.py `threat_scenario_service(**parts)` + `dependency_overrides[get_threat_scenario_service]` | Same file, `use_scenario_parts(monkeypatch, **parts)`: `monkeypatch.setattr(runs, "<getter / send_job / publish_session_status>", ...)`; returns the `runs` module, so `service.method(...)` lines stay |
| `get_work_control_repository().x(...)`, WorkControlRepository(own repos) | `work_control.x(...)`; patch `work_control.get_threat_scenario_session_repository` etc. Callers always go through the module attribute |
| `AssetRepository(StoredProcedureClient(sql_test_engine))` | `monkeypatch.setattr(app.crud.scenarios, "get_stored_procedure_client", lambda: StoredProcedureClient(sql_test_engine))`, or patch `get_asset_context` where it is read |
| `get_scenario_write_job()` / `get_controls_job()` partials | Patch `write_job.get_scenario_chat_model`, `write_job.get_library_cache`, `controls_job.get_library_search`, `controls_job.get_rerank_model`; call `write_scenario_batch(lease)`, `map_threat_scenario_controls(id, task_id)`. `plan_run(lease, find_threats, switch)` is unchanged |
| `ControlMapper(rerank).map_controls(...)`, `ControlRule(...)`, `mapping.items[i].code` | `write.map_controls(rerank, ...)` returning the stored dict; four numbers to `pick_controls_to_keep`; `items[i]["code"]` |
| `PlanProgress(lease, run, sessions, scenarios)`, `RunControls(..., sessions, scenarios, context)` | `PlanProgress(lease, run)`, `RunControls(record_id, task_id, snapshot, rerank)`; repositories come from the getters the test database fixture already serves |
| `path_writing.<name>` imports and patches | `write_job.<name>` |
| fakes.py `intelligence_service(**parts)` + dependency_overrides | `intelligence_service(monkeypatch, **parts)` patches getters on `admin`, returns the module; `get_evidence_index_keeper` raises unless given |
| `EvidenceFinder(...)`, `get_evidence_finder()` patch, `EvidenceAtWrite(...)` | evidence_fakes `use_index(monkeypatch, ...)` then `evidence.find_evidence(...)`; patch `evidence.find_evidence`; `evidence.attach_evidence(run, threats, paths, ids)`; autouse fixture clears `evidence._scored` |
| `SourceRefresher(...)`, `run_refresh_job(job_id, jobs, provider)` | Patch `refresh.get_*` and `refresh.MitreAttackSource`; `refresh.refresh_due_sources(now, keep_going=...)`; `run_refresh_job(job_id)` |
| `PlainFactWriter(sanitiser)`, `as_name(x)` | `monkeypatch.setattr(facts, "_SANITISER", ...)` + `facts.write_facts(hit)`; `is_plain_name(x)` |
| `save_intel_records(records, rejected, now)` in tests and fakes | `save_intel_records(records, now)` returning an int; `result.rejected` asserts in the safety and source tests stay as they are |

FastAPI `dependency_overrides` stays only for dependencies that remain real `Depends` (principal, valid_session). All module patches go through `monkeypatch` so they undo themselves.

## 4. Gates after every wave (and after each serial step of wave 2)

Run in parallel shards (owner rule), from the repo root with the project .venv:
1. `python -m pytest tests/test_code_conventions.py tests/test_outside_contract.py -q`: layer rules, 40-line functions, 150-line classes, 500-line files; the contract pins.
2. The golden step where the wave has one (order plan -> controls -> write -> session), then `python -m pytest tests/test_scenario_goldens_plan.py tests/test_scenario_goldens_write.py tests/test_scenario_goldens_session.py tests/test_scenario_goldens_controls.py -q` without the write flag.
3. `python -m pytest tests -q` (whole suite), `ruff check app tests scripts`, `ruff format --check app tests scripts`, `mypy app`.
4. Hash check against the scratchpad baseline: tests/contract/*.json, app/prompts.toml, input_cards.json and input_write_plan.json equal the baseline after every wave. Other goldens are compared with the previous gate's snapshot: only the files named for that wave or step may differ. Re-snapshot the goldens after each passed gate.
5. Golden diff check, per regenerated file. Allowed and nothing else: removal of missing_facts, prompt_version, library_stamp, counts.replaced, content.applicability, rewritten, controls.warning / shortfall / left_out_over_max, the dropped made_with keys; `turns` and `groups` removed from plan_*.json and changed to `{}` in the trace view of session_progress.json. Any changed prompt string or `asks` entry fails the gate. Expected files: wave 0 session_start.json; wave 1 the six plan_*.json and session_progress.json [G1], write_original.json and write_evidence.json card parts [G2]; wave 2 step 3 controls_cards.json and controls_cases.json [G1]. controls_alternatives.json, controls_embedded.json and session_views.json never change.
6. Record `git ls-files app | grep '\.py$' | xargs cat | wc -l` beside the wave number.
7. After wave 2 and wave 3 only: mutation check on origin_of_its_jobs and on pick_controls_to_keep, and one live end-to-end run (start, write a set, controls, next set, regenerate, cancel, promote) with intelligence on and off. No commit or push without asking the owner.

## 5. Skipped, and items for the owner

Skipped by the integrator (beyond each lane's own skip list, which stands):
- write W12 hidden blocked cards: about 4 lines, and it needs a NEW delete of the path's earlier failed card plus 10 or more test files; nothing gets simpler. The `served` condition stays at all 7 app sites.
- write W7 = shapes S10 (non-technique evidence branches) and write.py:349: removing them changes two pinned prompt strings in write_evidence.json (the lib:5 block). Precedent.ABOUT_SENTENCE and RELATED_RECORD stay.
- plan-2 = shapes S5 (GapFillResponse): it changes which gap-fill replies are re-asked (extra keys, `systems: null`); the owner kept the AI re-ask.
- intel-11 (switch lock): a kept intel safeguard would make callers wait for the store read during an outage; switch.py is not touched.
- intel-10 (evidence choice in one pass): -10 lines for rewriting what produces the stored intel_search.considered rows.
- session S1 (NONE_FITS readers): about -11 lines over 5 files, 10 test calls re-signed and 4 behaviour tests deleted, one owner-dated. Session S6 goes with it (the function would sit at 39 of 40 lines).
- shapes S6 (PlannedActor, attacker_check): -13 app lines against 13 test sites in 5 files.
- worker W2(c): plan_run fetching four models saves about 5 lines and turns one partial into a 4-getter patch used through 11 test files.
- IS-1 test-seam half (deleting FetchResult.rejected): it would change what four prompt-injection tests observe.
- intel-12 parts that push `_technique_from` over 40 lines (keyword parameters, flat_strings inline).
- shapes S7 (FrozenContext(**record)), shapes S11 (BriefSystem as dict), session S5 (plan-check notes), write W2 as written, R4 remediation half and all remediation or mapper clean-up, intel-9 full version: as before.
- input_cards.json and input_write_plan.json are fixed inputs: never edited or regenerated.

Needs the owner (the plan's default in brackets):
- G1, before wave 0: may the stored-record goldens be regenerated for the removed never-read keys only (session_start, session_progress, six plan_*, controls_cards, controls_cases)? [No change touching them is applied until yes.]
- G2, before wave 0: may the card parts of the prompt goldens write_original.json and write_evidence.json lose content.prompt_version, rewritten and the always-empty content.applicability, with every prompt byte-identical? Note scripts/scorecard.py:49 reads content.prompt_version today and would switch to evidence_mode. [Not applied until yes; about 8 lines.]
- plan-trace turns and groups: GET /v1/sessions/{id}/plan-trace keeps both fields but answers {} for new runs. tools/ux/tsg_console.html reads neither. [Apply with G1; the owner named plan-trace turns.]
- Tests of removed behaviour are deleted, not rewritten: 4 dead plan-guard rows (W6), the quarantine-row store cases, 3 paged-feed cases, advisory/non-technique hits (intel-7), the missing_facts list. [Delete; a "no" drops W6 and keeps those intel tests' code paths.]
- intel-9: may the per-search pointer check go, leaving only the 60 s follower thread? [No: reduced version.]
- IS-1: rejected ATT&CK objects are no longer stored as rows; the log line and the returned list stay. [Apply.]
- R4: the MongoDB-unavailable warning now logs for plan and mapper streams too. [Apply.]
- W12 was on the owner's list and is skipped: removing it needs a new delete and saves about 4 lines. [Skipped; say so if it is still wanted.]
- Removed-source evidence branches in the writer (W7) stay because a prompt golden pins them. [Kept; removal needs a named gate-5 exception for the lib:5 block.]
- Enum re-pin (enums.json) for dead members: 4 FindingCode, Applicability, EvidenceRole.DIRECT, 2 EvidenceDecision, EvidenceReason.NO_PRODUCT_LINK, 3 EvidenceFact, 4 IntelKind, IntelState.QUARANTINED. [Not done.]
- Evidence.applicability / joined stored keys and API field. [Kept: frozen API and prompt goldens.]
- MAX_SUPPORTING_SYSTEMS dead cap; retired-index drops at start-up; count_current_scenarios; both scenario repository classes staying classes under ADR-004. [All left as they are.]
- Worker folder ends at 4 files, not 2 or 3: three needs write_job.py at about 530 lines, over the 500 cap. [4 files.]
- R1 and the control-mapping step touch app/domain/shared/audit.py (one line) and one argument in app/worker/remediation.py, files of later modules. [Apply: the minimum those changes need.]

## 6. Top 5 risks

1. A module-level fake leaks or is not seen (a test forgets `monkeypatch`, or app code does `from module import fn` and escapes the patch). Mitigation: callers use module attributes (`runs.fn`, `work_control.fn`, `admin.fn`, `evidence.find_evidence`); helpers accept only `monkeypatch`; the intel helper makes unpatched heavy getters raise; a missed AssetRepository swap is caught by patching `get_stored_procedure_client` in the shared fixture.
2. A golden regeneration hides a prompt change or captures half-done code. Mitigation: one agent regenerates after all lanes of the wave are in, in the fixed order, one test file at a time; gate 5 per file; the hash baseline for contract, prompts.toml and the two input files.
3. Stored documents drift where they are read: controls record (shortlist, query, 6 made_with keys feed the reuse check), intel_search.considered rows, the snapshot pointer's 7 keys. Mitigation: controls_alternatives.json, controls_embedded.json and the `asks` of write_evidence.json must stay unchanged; intel-10 is not done.
4. origin_of_its_jobs reads the wrong argument after R1, so AI usage rows get the wrong origin. Mitigation: the one-line read by keyword or by type; mutation check plus test_ai_usage.py:363 before leaving wave 2 step 2.
5. Same-file collisions and half-applied cross-lane signatures (runs.py, write.py, write_job.py, scenario_internal.py, intel_records.py, four shared test files). Mitigation: the ownership table and the sequenced-file list; the path_writing merge sits in wave 0; build_failure_card's caller is named for lane F; every other cross-lane signature change sits in a wave 2 serial step; the 40-line cap is rechecked after each step that inlines (create_threat_scenario_session, delete_run, pick_controls_to_keep, write_fetch_result, _technique_from, _save_written).

## Lines per lane (estimates; each merged pair counted once; G1 and G2 answered yes)

| Lane | Lines now | Lines after | Net |
|---|---|---|---|
| runs+routes | 1740 | ~1661 | -79 |
| crud | 938 | ~892 | -46 |
| plan | 1080 | ~1028 | -52 |
| write | 1022 | ~946 | -76 |
| session | 835 | ~816 | -19 |
| worker | 1006 | ~885 | -121 |
| shapes+constants | 1022 | ~909 | -113 |
| intel-domain | 2677 | ~2381 | -296 |
| intel-store | 968 | ~854 | -114 |
| Sum of lanes | | | -916 |
| Lines two lanes both count (service constructor, EvidenceParts, library_stamp, callables) | | | about +35 |
| app total | 26188 | ~25300 | about -880 |

## Verification (end to end)

- After every wave: the gates in section 4, with the suite run as `.venv/Scripts/python.exe -m pytest tests -q -n 6`.
  Known local failure to ignore: `tests/test_config.py::test_env_files_match_settings[.env.uat]` (the owner kept the
  `CII_NVD_API_KEY` line in the local `.env.uat`).
- OpenAPI output byte-identical to the baseline; `app/prompts.toml` hash unchanged; `tests/contract/*.json` unchanged except
  `enums.json` in wave 3 (the re-pin diff checked line by line).
- After waves 2 and 3: mutation checks (section 4, gate 7) and one live end-to-end run with intelligence on and off:
  start, write a set, controls, next set, regenerate, cancel, promote.
- Final: line count of `app/` recorded in `.10x/status.md`; QA and security notes under `.10x/reviews/`.
