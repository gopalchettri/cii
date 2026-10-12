# TSG v2: Scenario Generation Build Plan (one-stop document)

**Date:** 2026-10-10 · **Status:** owner rulings applied, ready to build · **Working copy:** `docs/BUILD_PLAN.md`
(created in step S0)

This document holds everything needed to build threat-scenario generation: the rules to follow, every build step in
order with its implementation logic, the full design of how a scenario is generated, a glossary, and the gap analysis
against `docs/TSG_Final_Development_Specification.md` (v4.0) that it came from.

> **Names (owner, 2026-10-11):** the scenario engine's files and functions were renamed so each says what
> it does. The step log below keeps the file names of its day; BLUEPRINT §10 maps each to its new name.

## Contents
- Part 0: How to use this document
- Part 1: Owner rulings
- Part 2: The build checklist (S0–S43, in order)
- Part 3: How a scenario is generated, step by step (the target design, with examples and implementation logic)
- Part 4: Glossary
- Appendix: Gap analysis, spec v4.0 vs the codebase

## Progress tracker (updated at every exit check)

| Step | What | Files | Tests | Status |
|---|---|---|---|---|
| S0 | Plan saved | `docs/BUILD_PLAN.md`, memory pointer | — | ✅ 2026-10-10 |
| S0b | G118 step tracing (`DEBUG_STEP_OUTPUT`) | `core/redaction.py`, `core/tracing.py`, `core/config.py`, `core/logging.py`, `@traced` on 31 workflow functions, env files | `tests/test_step_tracing.py` (7), `test_config.py` (+1); 301 pass | ✅ 2026-10-10 (real-AI traced run in S12) |
| S1 | G106 `TOTAL_SCENARIO_COUNT` | `core/config.py`, `core/constants/runs.py`, `engine/scenarios/attack_paths/path_selector.py`, env files | `test_config.py` (+5), `test_attack_paths.py`, `test_scenario_limits.py`; 306 pass | ✅ G106 |
| S2 | G108 safe gap-fill | `engine/scenarios/finding/ai_gap_fill.py`, `attackers.py` (assigner covers AI threats by type), `threats.py`, `library_match.py`, `models/threats.py`, `constants/planner.py` | `test_threat_finding.py` (+3, 2 updated); 309 pass | ✅ G108 |
| S3 | G109 no cross-type merge | `engine/scenarios/threat_list/duplicate_merge.py`, `same_attack.py`, `threats.py`, `constants/planner.py` | `test_threat_finding.py` (+3); 312 pass | ✅ G109 |
| S4 | G110 actors after dedupe | `engine/scenarios/finding/threat_finder.py` (fold → actors), `same_attack.py` (`pick_surviving_threat`), `attackers.py` (check covers AI threats) | `test_threat_finding.py` (+2); 314 pass | ✅ G110 |
| S5 | G117 gate picks attacker | `prompts.py` (gate asks `attacker`, version planner-2026-10-10.1), `planner_replies.py`, `models/threats.py`, `relevance.py`, `attackers.py` | `test_threat_finding.py` (+2); 317 pass. Review S0b–S5: URL user:password leaked through redaction → fixed in `core/redaction.py` (+1 test) | ✅ G117 |
| S6 | G111 retry fingerprint | `models/scenarios.py` (extra=forbid), `services/scenarios/runs.py` (`request_fingerprint`), `data_access/sessions.py` | `test_runs.py` (+2); 319 pass; review: no new gap | ✅ G111 |
| S7 | G112 AI number checks | `ai/embeddings.py` (`EmbeddingNotFinite`), `ai/rerank.py` (0-1 check), `ai/common.py`, `constants/common.py` | `test_ai.py` (+6); 325 pass; review: unusable AI answers failed as "unexpected" → now `UnusableAiAnswer(JobFailed)` with code `ai_answer_unusable` | ✅ G112 |
| S8 | G113 partial outcome | `constants/runs.py` (`PARTIAL`), `worker/tasks/scenarios.py` (`finished_outcome`) | `test_attack_paths.py` (+1); 326 pass; review: no new gap | ✅ G113 |
| S9 | G114 one threat = one path | deleted `engine/scenarios/grouping.py`; `paths.py` (one path per threat, no chat dependency), `prompts.py` (planner-2026-10-10.2), `planner_replies.py`, `models/threats.py`, `constants/ai.py`, `planner.py` (plan note: "still to write") | `test_attack_paths.py` (grouping test → `test_every_threat_becomes_exactly_one_path`); 326 pass; review: unused chat dependency removed | ✅ G114 |
| S10 | G116 stale text | `constants/planner.py`, `.env*` comments, `services/scenarios/context.py` (uses `SYSTEM_ALIAS`) | 326 pass; review: no new gap | ✅ G116 |
| S11 | Phase 1 close-out | Phase 1 (S1–S10 rows below); docs: BLUEPRINT gap register G106–G118, IMPLEMENTATION_GUIDE, RUNNING | 326 pass, ruff, format, mypy clean | ✅ Phase 1 closed 2026-10-10 |
| S12–S13 | Measurements | scratchpad `dev_measure_run.py` (no product code) | M1: 224 relevant category judgements missed by the top-10 shortlist. M2: the AI attacker pick was "Nation-state/APT" for 8 of 10. M3: 0 of 451 threats lack a category. M4: 9 of 42 threats then, 106 of 159 after G121, use a closest attacker (library gap, see Blockers). Trace on the real run: 0 failed, 0 secrets | ✅ owner rulings 6, 8, 9 → S13a–S13c |
| S14 | Prompt draft → owner gate | `docs/SCENARIO_PROMPTS_DRAFT.md` (draft v2) | review document | ✅ approved by the owner 2026-10-10 |
| S13a | | `data_access/library.py` (`_library_threats`), `models/library.py` (`threats_without_category`), `threats.py` (`_library_data_notes`), `constants/planner.py` | `test_library.py` (+1), `test_threat_finding.py` (+1); 328 pass; review: the size guard split the loader | ✅ G119 |
| S13b | | `prompts.py` (planner-2026-10-10.3), `planner_replies.py`, `models/threats.py`, `relevance.py`, `attackers.py` | `test_threat_finding.py` (G117 tests → `test_the_ranking_alone_chooses_the_acting_attacker`); 327 pass | ✅ G120 (owner: ranking, after M2) |
| S13c | | `categories.py` (whole category, shortlist first), `relevance.py` (shared pool), `ai_questions.py` (`max_items`, `run_in_parallel`, `run_in_shared_pool`, `raise_most_retryable`), `threats.py` (one gate pool, `GATE_CALLS_AT_ONCE` 16), `attackers.py` + `same_attack.py` (batches at once), `constants/planner.py` | `test_threat_finding.py` (+4); 331 pass. Asset 1179: 159 threats → 159 paths in 78 s (whole category judged one batch after another ≈ 290 s). Review: a pool per category let the largest category set the pace (106 s) → one shared pool; the attacker check ran its batches one after another (78 s) → sent at once | ✅ G121 |
| S13d | | `engine/scenarios/threat_list/attacker_assignment.py` (`_closest_pool`: attackers linked to some type) | `test_threat_finding.py` (closest-attacker test now asserts the vetted pool); 331 pass | ✅ G122 (owner ruling 10) |
| S15 | | `docs/IMPLEMENTATION_GUIDE.md` (decisions #14–#19, spec errata, flow, prompt tables, Step 12 HOW), `docs/BLUEPRINT.md` (FR-THR-06, FR-PATH-01, R-2, AI tables, T9, T-PATH), `docs/BUILD_PLAN.md` Part 3, new `docs/HOW_SCENARIOS_ARE_GENERATED.md`, memory | grep for v1-copy / AI grouping / IsCapable finds nothing stale | ✅ |
| S16 | | `core/constants/writing.py` (new: `ScenarioStatus` done/failed/blocked, `FindingSeverity` blocker/warning/note moved from runs.py, `FindingCode`, `FINDING_SEVERITIES`, `Route`, `PlanCheckStatus`), `constants/ai.py` (`REWRITE_SCENARIO`, `PLAN_CHECK` at 0.0), `constants/runs.py` (`Generation.WRITER_BATCH` 6, `MAX_PATH_ATTEMPTS` 5), `constants/planner.py` (2 `AnswerProblem`s), new `models/writing.py` (`WriterBrief`, `ScenarioDraft`, `Finding`, `PlanCheck`, `WrittenScenario`, `ScenarioAnswer`, `PlanCheckAnswer`), `models/scenarios.py` (view status, warning-only validation), `worker/tasks/scenarios.py` | new `tests/test_scenario_writing.py` (6); `test_runs.py` severity; 337 pass. Review: plan said written/failed/abandoned, but `done`/`failed` are what §8.2 and the read APIs already serve and abandoned is a path state, so a third status `blocked` (spec §7.4.7 quarantine) was added instead; writer log events and messages are added with their users (S21–S25), not as dead constants | ✅ |
| S17 | | new `engine/scenarios/writing/brief_builder.py` (`build_brief`: the path's one threat checked whole, only its systems by name with cleaned facts, the run's other systems apart, acting attacker, redacted reason; facts held within half the model input), `core/exceptions.py` (`PathNotWritable`, code `invalid_plan`), `constants/writing.py` (`PathProblem`), `constants/common.py` (`PATH_NOT_WRITABLE`) | `test_scenario_writing.py` (+9: only the path's systems, no id/alias/email, asset-only threat, 6 refusals, long facts cut and still JSON); 346 pass. Review: a long fact could have made the writer prompt too long, failing the path 5 times → facts are cut to the budget, longest first | ✅ |
| S18 | | new `engine/scenarios/writing/writing_prompts.py` (`WRITER_PROMPT_VERSION` writer-2026-10-10.1; both system prompts generated from the approved draft byte for byte; `writer_prompt` = BRIEF JSON, other_scenarios only when regenerating; `plan_check_prompt` = PLAN by names + SCENARIO as written), `prompts.py` (unused `RULE_LINKS` deleted) | `test_scenario_writing.py` (+3: prompts equal the approved text, brief JSON, plan by names); 349 pass. Review: no new gap | ✅ |
| S19 | | new `engine/scenarios/writing/draft_cleanup.py` (`clean_draft`, `clean_title`: framework names/codes and every asset, system and attacker name out of the title with the words tying them in, threat-name fallback; `lead_with_consequence`: "Y, because X." or the owner's "This risk exists because"; technique codes, hashes, GUIDs out of every text; blank/repeated assumptions dropped), `names.py` (`name_variants`, `find_name_mentions`, plural option) | `test_scenario_writing.py` (+12: 7 titles, 4 risk openings, codes/hashes/GUIDs/assumptions); 361 pass. Review: a pattern cache via `functools.lru_cache` broke the thread-safe singleton guard → removed (re's own cache holds a run's names; ceiling noted) | ✅ |
| S20 | | new `engine/scenarios/writing/exact_rules.py` (`check_exact_rules` → findings + route: blockers = internal label SYS/THR, advisory number never supplied; warnings = asset not in statement/risk, acting attacker not in statement, another library attacker named, a system outside the scenario named, a link claimed between two of its systems (route `unknown`)), `constants/writing.py` (`FindingMessage`), `names.py` (`halves` only for the acting attacker) | `test_scenario_writing.py` (+11: clean pass, 7 single faults, nested names, link vs no link); 372 pass. Review: "Third-party/Vendor" matched by its half flagged every "vendor session" as another attacker → halves only for the acting attacker. To measure in S29: how often the writer paraphrases its attacker (each paraphrase is an attacker_not_named warning and costs a rewrite) | ✅ |
| S21 | | new `engine/scenarios/writing/ai_plan_check.py` (`PlanChecker.check_against_plan` → `PlanCheck` + notes; at most 10 problems of 300 characters; unusable after one re-ask → UNCHECKED + note "plan check not made"; outage raised), `constants/writing.py` (`Writing` limits), `log_events.py` (`WRITER_PLAN_CHECK_NOT_MADE`), `models/writing.py` (`ai_calls` dropped: the chat model cannot see its re-asks; S29 counts calls from `tsg_ai_calls_total`) | `test_scenario_writing.py` (+4: consistent, problems as notes and cut, unusable → note, outage raised); 376 pass. Review: no new gap | ✅ |
| S22 | | new `engine/scenarios/writing/scenario_writer.py` (`ScenarioWriter.write_scenario`: write with a shape check and one re-ask → clean → rules + plan check → ONE rewrite in the same conversation listing every problem → keep the draft with fewer problems, blockers first, rewrite on a tie; unusable rewrite keeps the first), `ai/chat.py` (`ask_again_for_checked_json` via the approved §9 correction turn, no new prompt wording; correction turn moved out of the class), `ai/chat_messages.py` (`build_call_record` moved, unchanged), `ai_questions.py` (`ask_ai_again_with_problems`), `constants` (`ENTRY_POINT_NOT_OFFERED`, `WRITER_REWRITE_UNUSABLE`), `tests/fakes.py` | `test_scenario_writing.py` (+7: clean in 2 calls, re-asks, failure, asset-level entry, better rewrite in 4 calls, worse rewrite dropped / tie kept, unusable rewrite), `test_ai.py` (+1: the real rewrite conversation); 384 pass. Review: `ChatModel` grew past the 150-line class limit → the correction turn became a module function | ✅ |
| S23 | | `data_access/scenarios.py` (`save`: insert, or replace the path's failure/blocked card under the same id, False when already written; `TitleTaken` from the unique `one_title_per_run` index on `(session_id, title_key)` over current written scenarios; `find_written`; `count_for_run`: one aggregation; blocked never served by #3/#9/#10) | `test_scenario_writing.py` (+3: repeated save once / card replaced, title clash refused (other runs, blocked, replaced do not count), counts by aggregation + blocked hidden); 387 pass. Review: the plan said SHA-256 ids; the BLUEPRINT schema says `uuid5(run:path:version)` and the job uses it (S25). The title index ignores documents without `title_key`, so older data can never block its creation | ✅ |
| S24 | | `data_access/job_records.py` (`JobLease.write(changes, array_filters)`: one plan path changed through the same fence on status, task id and epoch) | `test_worker.py` (+1: the owner changes one path; after a newer epoch the old delivery raises LeaseLost and changes nothing); 388 pass. Review: no new gap | ✅ |
| S25 | | new `worker/tasks/writing.py` (`tsg_write_scenarios` → `BatchWriter`: paths already written skipped with no AI call; up to 6 at once in a thread pool (log context copied); each saved the moment it is done, in the job thread: written / blocked (hidden) / failure card; unique title via the index; path state + counts + plan note in ONE fenced write per path; live update), new `engine/scenarios/writing/scenario_record.py` (uuid5 ids, written/failure documents, title candidates), `draft_cleanup.title_suffix`, `models/writing.PathFailure`, `sessions.find_for_writing`, `celery_app.TASK_MODULES` | `test_writing_job.py` (5), `test_worker.py` (`WRITE_SCENARIOS` registered); 393 pass. Review: `BatchWriter` grew to 152 lines → stateless plan-path helpers moved to module functions; mypy could not read a star-unpacked except tuple → a named constant. Interim: until Step 13 maps controls, a finished run shows step "controls" (its controls are queued), which is the truth | ✅ |
| S26 | | `worker/tasks/writing.py` (`_next_batch`: never-tried paths first, then retries, best rank first; hand-over to itself in one fenced write; finish: complete, or partial when a path was abandoned or a category not assessed; `timings.scenarios_s`) | in `test_writing_job.py`: 14 paths → 3 deliveries by themselves, unique titles, counts; unreadable path → 5 attempts → abandoned → partial; unsupported path abandoned at once; an outage retry skips saved paths; a blocked scenario hidden and retried; a late/duplicate delivery claims nothing (claim guard) | ✅ |
| S27 | | `core/metrics.py` (`tsg_scenarios_total{outcome}`), `constants/writing.py` (`ScenarioOutcome` written/blocked/failed/abandoned), `worker/tasks/writing.py` (counted at each save, abandoned once more), Grafana `observability/grafana/dashboards/tsg.json` (panel "Scenario paths settled per hour, by outcome"; lower panels moved down) | `test_observability.py` (the dashboard metric exists), `test_writing_job.py` (+14 written; +5 failed, +1 abandoned); 393 pass. No alert (owner asks first) | ✅ |
| S28 | | `tests/test_scenario_writing.py` (T-WRT suite: 64 cases across S16-S28) + `tests/test_writing_job.py` (job cases) | every listed case covered; the gaps found and added: a live update after every save (14 saves → 14 updates), the unique-title order (title → threat name → (2), (3); a qualifier the title already says skipped), a stored scenario read back through the API view; 395 pass | ✅ |
| S29 | | scratchpad `dev_write_run.py`; G125 (`ai.call_unavailable`); docs (BLUEPRINT W1-W10, S9, §8.2, schema, G123-G126; guide decisions #20-#21; HOW Stage F; RUNNING); owner rulings applied: prompt v2.1 rule 7 (`writer-2026-10-10.2`), retired-record check (G126) | Run 1: 139/139 in 7.7 min, first 6 at 1.6 min, 3.63 writer calls per scenario, 96 rewrites, 0 failed. Owner "Okay" 2026-10-10 → rule 7 + retired check built; 400 pass. Run 2 (rule 7 v2.1) measured for the rewrite rate | ✅ owner gate passed 2026-10-10 |
| S30 | | `docs/BUILD_PLAN.md` (S31-S35 detailed control steps; rulings: never widen to incompatible controls, pool by the asset and the scenario's systems, no AI-written controls, no "preferred domain") | measured first: 1,288 controls, AssetType IT 731 / OT 557; asset 1179 OT with OT, OT, IT systems | ✅ |
| S31 | | new `core/constants/controls.py` (`Controls` moved from library.py and extended, `ControlMatch`, `COMPATIBLE_ASSET_TYPES`), new `engine/scenarios/control_mapper.py` (`compatible_asset_types`), `search/snapshot.py` (`find_controls(..., allowed_types)`: masked before the top-k; untyped controls always fit) | new `tests/test_control_mapping.py` (+6: the pool by asset and systems, never widened; the mask before the cut); 406 pass. S29 follow-up measured (run 2, rule 7 v2.1): 144/144 in 7.5 min, rewrites 69% → 53%, writer calls 3.63 → 3.18 per scenario, outages = HTTP 429 rate limits (G125 shows them), all recovered; G127 fixed (the plan check judged recorded vendors "invented": it now reads the recorded facts) | ✅ |
| S31r | | Review of S16-S31 (independent reviewer + own cross-check): `scenario_record.py` (G128), `writer_prompts.brief_text` + `rules.py` + `cleanup.py` (G129, G132), `ai/common.py` (G130 `ai_misconfigured`), `worker/tasks/writing.py` + new `worker/plan_progress.py` (G131, G135, G136), `constants/controls.py` (G133), `data_access/scenarios.py` (G134); S32 pieces: `models/controls.py`, `ControlsNotMapped`, `no_compatible_control` | +15 tests, each failing without its fix; 421 pass; ruff, format, mypy clean | ✅ 9 findings, all fixed at the cause |
| S32 | | `engine/scenarios/control_mapper.py` (`ControlMapper.map_controls`: pool → `control_library_empty` / `no_compatible_control` (`ControlsNotMapped`) → search top 40 in the pool → one rerank → ≥ cut-off exact, else the single nearest with `ControlMessage.NEAREST_ONLY` → twins folded → ranks 1..n; `control_search_text`: both statements, cut at 4,000, redacted), `models/controls.py`, `models/library.LibraryControl.fits` (one rule for the search and the mapper), `constants/controls.py` (`ControlMessage`), `tests/fakes.py` | `test_control_mapping.py` (+5: both statements + compatible only, nearest + warning, twins, empty vs nothing fits, outage + query cut); 426 pass. Review: 1 embedding + 1 rerank call per scenario, no DB read; no new gap | ✅ |
| S33 | | new `data_access/scenario_controls.py` (`ControlLeases`: claim one waiting scenario in one conditional update, renew / finish / give back / fail fenced on the claim's task id, `requeue_stalled` sweep), new `data_access/run_counts.py` (`RunCounts.refresh`: one aggregation, written only when newer, `counts_at`), `worker/plan_progress.py` (scenario counts through `RunCounts`; plan figures and note stay in the fenced write), `worker/tasks/writing.py` (`BatchWriter` takes the database) | `test_control_mapping.py` (+4: one claim per scenario + a stale worker cannot finish, queued again then failed at 5, the sweep requeues lost / dead / long-failed only, an older count never wins); 430 pass. Review: 1 conditional update per claim, 2 indexed operations per sweep; no new gap | ✅ |
| S34 | | new `worker/tasks/controls.py` (`tsg_map_controls` → `RunControls.map_all`: claim → map under a renewed per-scenario lease → finish with items, warning, query and made_with → counts → live update; outage → given back + message retried; `ControlsNotMapped` / `JobFailed` → that scenario failed with its code; `tsg_retry_controls` sweep on beat every 300 s, one message per run), `worker/jobs.py` (`keep_lease_alive` takes any `RenewableLease`), `worker/tasks/writing.py` (one controls message per batch that wrote scenarios), `celery_app.py` (registered, beat entry), log events | `test_control_mapping.py` (+3: all mapped + step + counts + repeat maps nothing, outage given back + no-fit fails the scenario not the job, sweep sends once per run), `test_writing_job.py` (3 controls messages for 3 batches), `test_worker.py` (every task built); 433 pass. Review: per scenario 1 claim + 1 embedding (cached on retry) + 1 rerank + 1 save + 1 count + 1 publish; no new gap | ✅ |
| S35 | | scratchpad `dev_full_run.py` (plan + write + controls in one process); docs: BLUEPRINT C1-C7 and Rules S10-S12 as built, HOW_SCENARIOS_ARE_GENERATED Stage G, IMPLEMENTATION_GUIDE Step 13 | Asset 1179, stopped by the owner at 48 written / 42 mapped: controls 1-16 per scenario (OT 74, IT 10: an OT asset with one IT system), 29 of 42 nearest-only below the 60 cut-off on the laptop's CPU reranker (bge-reranker-v2-m3, ~55 s per scenario); 0 failures. Open: calibrate the cut-off on the UAT reranker | ◐ partial: stopped by the owner |
| S36 | | S36 gate report (3 scenarios with their controls) | owner: "stop now and proceed" | ✅ gate passed 2026-10-10; cut-off calibration open |
| S37 | | `docs/BUILD_PLAN.md` (S38-S43 detailed review steps; rulings: decisions final except `replace_accepted` (G137, the state table contradicted Rules S4/S5), accept-all idempotent, `library_inactive` from the in-memory library, regenerate ends the run (no hidden resume), run writes carry the state filter, `manual_scenario` with Step 16) | read first: Rules S3-S7, S13, spec §6.1 #4-#7/#27, §7.6, `tsg_ResolveThreat` (built, tested), the write job | ✅ |
| S38 | | new `core/constants/review.py` (`Review` 50 ids / 64 chars, `TargetProblem`, `PromotionOutcome`, `ReviewMessage`), `constants/runs.py` (10 `ConflictReason`s), `access.py` (5 audit actions, `AuditTarget.SCENARIO`), `common.py` (`SCENARIO_BLOCKED`, `REGENERATE_BLOCKED`), new `models/review.py`, new `engine/scenarios/attack_paths/path_progress.py` (moved from `worker/plan_progress.py` + `why_no_path_left`), `metrics.DECISIONS` (`tsg_decisions_total`) | `test_review.py` (6 body cases → 422; `why_no_path_left` 3 reasons); 433 still pass after the move | ✅ |
| S39 | | new `data_access/scenario_review.py` (`ScenarioReview`: targets in one `$in` read, accept-all set, accepted version per path, `set_decision` = one `update_many` on the expected decision, `record_promotion`), new `engine/scenarios/review_checks.py` (per-id reasons), new `services/scenarios/review.py` (`ReviewService.accept/reject`, `check_review_open`, `decided_stamp` with `decided_by_client`), new `api/routers/review.py` (#4, #5), `api/dependencies.py` (`Caller`, `CallersRun`), `models/library.ThreatLibrary.known_threat_ids`, `main.py` | `test_review.py` (+8: decide once + counts + audit + live update + repeat quiet; every id at fault named, nothing written; one accepted version + `replace_accepted` + older version; accept-all idempotent; reject final; accept vs reject and two versions at once → one wins (fails without the decision filter, checked); Rule S3 + 403); review: accept-all could take two current versions of one path (unhealed regenerate crash) and report a false race → skips the second as `duplicate_version` (+1 case) | ✅ |
| S40 | | new `data_access/run_actions.py` (`RunActionRecords`: `find_for_action` (plan paths only when needed), `queue_again` = ONE conditional update on epoch + done/failed + step scenarios → a fresh job and `last_action`, `RunClash.CHANGED` / `ACTIVE_RUN`; `find_plan_threat` for S42), new `services/scenarios/run_actions.py` (`RunActions.next_set`, `regenerate` API side), `api/routers/review.py` (#6, #7, 202 `{epoch}`), `constants/runs.py` (`RunClash.CHANGED`) | new `tests/test_run_actions.py` (4: an interrupted run resumed and finished complete by the job, error cleared, one audit; twice → 409, two at once → one 202 (fails without the epoch/state filter, checked); nothing_left / target_reached / scenarios_abandoned; asset_busy names the active run + 403). Review: no new gap; `timings.scenarios_s` counts from the plan freeze (a resumed run includes its idle time), documented in S43 | ✅ |
| S41 | | API: `RunActions.regenerate` (per-id `unknown` / `failure_scenario` / `version_not_current` / `duplicate_version` → 409 `scenarios_not_regenerable`), route #6. Job: new `worker/path_writing.py` (`PathWriter`, `write_at_once`, `save_with_unique_title`, moved out of `BatchWriter`), new `worker/regenerator.py` (`Regenerator`: n+1 saved, then n superseded, then the path served; failure → `regenerate_error` on n; blocked → hidden n+1 + `scenario_blocked`; outage on the last try → `unavailable` reasons, run partial; crash between writes healed with no AI call), new `data_access/scenario_versions.py`, `scenario_record.written_record(replaces=)`, `writer_brief` (siblings bounded), `tasks/writing.write_batch` dispatch | `test_run_actions.py` (+6: v2 written, v1 superseded and still accepted, writer saw v1, complete; failed → v1 current with its reason, attempts unchanged, partial, cleared by a later success; crash healed with no AI call; 409 per id + busy; two versions of one path; siblings within budget), `test_control_mapping.py` (+1 G139). Review found 3 gaps, each fixed at the cause and tested: siblings unbounded in the prompt (kept within a quarter of the budget); G138 counts used the list filter (an accepted replaced v1 counted as written: R-7 now); G139 the controls claim/sweep skipped an accepted replaced version (mapped now; fails without the fix, checked); 458 pass | ✅ |
| S42 | | new `services/scenarios/promotion.py` (`LibraryPromotion.promote`: accepted + AI threat or 409; the plan threat read alone (positional projection); in memory first by normalised name: live/pending → `existing`, curator-rejected → `curator_rejected` (never proposed); only a new name → `tsg_ResolveThreat` (pending); `library_promotion` set once, audit once), `data_access/library.py` (`propose_threat`), `models/library.py` (`ThreatProposal`, `ProposedThreat`), `constants/library.py` (`LibrarySource`, `ResolveOutcome`), `engine/scenarios/finding/library_matcher.py` (`library_threats_named`), `data_access/run_actions.find_plan_threat`, route #27 | new `tests/test_promotion.py` (4, on the SQL test database: twice → inserted then existing, row `IsActive 0` under the existing type, one audit; rejected / live / pending wording never reaches SQL; not accepted / library threat / 404 / 403; SQL down → 503, nothing recorded). Review: `$elemMatch` cannot project a nested array (500) → positional projection; the test now removes its own rows from the SQL test DB (seed-exact library tests ran after it); 462 pass | ✅ |
| S43 | | review: independent reviewer + own cross-check → G141-G148 fixed in `job_records.py`, `scenarios.py` (title index over every written version; `MAPPED_VERSIONS`), `scenario_controls.py`, `scenario_review.py` (unordered bulk decision write), `review.py` (audit first, `decision_id`), `review_rules.py`, `regenerator.py` (crash healed whole), `tests/test_writing_job.py` (regenerator messages captured); docs: BLUEPRINT Rules S3-S7, S13, R-6/R-7/R-8, §12.2, §13, G137-G148; IMPLEMENTATION_GUIDE Step 14; HOW Stage H; RUNNING; scratchpad `dev_review_run.py` | 468 pass; ruff, format, mypy clean; each of G141-G148 fails without its fix (mutation-checked). Dev run, asset 1179 (stopped run, real stores and AI, no UAT): accept 3 + repeat (1 audit), reject 1, reject an accepted one → 409 `already_accepted`; regenerate 1 → v2 in ~8 s, 4 AI calls, v1 stays accepted and superseded, a new title; a second regenerate while queued → 409; next set → 6 paths in 9.2 s (16 AI calls), then closed as the reaper closes an unsent job (`last_action` failed, not running); accept repeat 8 ms (184 ms when a process first loads the library); 0 secrets in the log. Promote not run on dev (the run has no AI threat; it would write to the shared dev library): covered on the SQL test database | ✅ report sent 2026-10-11 |
| S44 | | `docs/BUILD_PLAN.md` Phase 7 (S44-S56; rulings: one plan endpoint with two bodies, the corrected prompt, one re-ask, the 20 s top-up enforced by the lease fence, decisions fenced by a counter, YYYY-MM-DD dates), new `docs/REMEDIATION_PROMPT_DRAFT.md` (v1 prompt + 4 gap fixes, approved) | owner: 4 prompt gaps confirmed and the fixed prompt approved; the 6 provisional rules of 2026-10-09 kept | ✅ owner gate passed 2026-10-11 |
| S45 | | new `core/constants/remediation.py` (`Remediation` limits, `RiskLevel`, `YesNo`, `ControlCoverage`, `ControlType`, `ActionPriority`, `RemediationProgress`, `RemediationMessage`), new `models/remediation_requests.py` (`RegisterData`, `ControlRef`, `LibraryRef`/`TypeRef`/`CategoryRef`, `ManualScenario` (= `StartRunRequest` + threat + statements), `PlanRequest`, `DecisionRequest`, `RegenerateRequest`), new `models/remediation.py` (`PlanDraft` answer contract, `PlanRequested`, `RemediationStatus` + progress); constants and models added with their users (ConflictReasons, audit, task, collection, events in S50-S53) | new `tests/test_remediation_models.py` (12: blank = absent, exact decimals + limits, calendar window, register controls, one of two bodies, decision/regenerate bodies, answer contract, overall progress). Review: a type or category name could exceed its SQL column (300 / 200) and fail inside the procedure → per-row limits (+3 cases); Yes/No uses the enum; JSON-float rounding past 15 digits noted (ponytail) | ✅ |
| S46 | | new `engine/remediation/references.py` (`resolve_controls`: id, then code, then name, case-blind; id decisive; id+code naming two rows refused; strict = every unknown/repeat in one 422, tolerant = unknown kept as text, repeats dropped), `models/library.ResolvedControls`, `RemediationMessage` (4 messages), `engine/remediation/__init__.py`. In `engine` (not `search/`): the layer rule keeps search from importing the name rules. Threat identity (L2) moves to S55 with its only user | new `tests/test_remediation_references.py` (5). Review: an unknown id beside a live code fell back to the code (a different control than the id named) → the id is decisive; IT/OT twins sharing a name resolved by row order → lowest id (+1 test, fails without the fix) | ✅ |
| S47 | | new `engine/remediation/scheduler.py` (`schedule`: durations repaired, prerequisites by position, offsets, critical path, inclusive YYYY-MM-DD dates, calendar clamp, plan timeline + `critical_path`), new `engine/remediation/schedule_checks.py` (sequence, urgency, window, stated days, control delivery), `models/remediation.ActionSchedule`, `constants/remediation.py` (`PlanWarning`, `PlanText`, v1 words) | new `tests/test_remediation_schedule.py` (8: the golden example (40 days, ends 2026-11-09, A1 01-14 Oct), no window, every repair, prose vs ids, sequence/urgency/window/stated days, calendar clamp, control delivery canonical, no action). Review: the window is validated at the request and built by code, so v1s half-window warnings are unreachable and not ported; the AI contract makes depends_on/implements_controls always lists | ✅ |
| S48 | | new `engine/remediation/register.py` (`clip`: the one door, redacted + cut at 2,000 + " [truncated]"; `register_half`: register controls resolved tolerant, ratings as JSON numbers (int when whole), the window with inclusive total_days, the echo-only block, v1s three advisories at the final ratings own scale), new `engine/remediation/snapshot.py` (`build_snapshot`: R4s fixed key order; library details from memory; `covered_by_register` decided in code, IT/OT twins included; a control retired since mapping left out with a warning), `SnapshotWarning` | new `tests/test_remediation_snapshot.py` (4: key order, coverage + twin + retired, numbers and the three advisories (20.00 = 4.47 x 4.47 rounded: no flag), the risk owner never in the AI view + the visible cut). Review: the twin key was first computed from the cut description, so a description over 2,000 characters would never match its twin → keyed on the library row; a regenerate rebuilds the register half from the stored register data (one code path, current library matches) | ✅ |
| S49 | | new `engine/remediation/prompts.py` (the owner-approved system message word for word, `PLAN_PROMPT_VERSION`, `plan_prompt`: the snapshot without register, warnings and database keys, `control_id` added to `DATABASE_KEYS`), new `engine/remediation/planner.py` (`RemediationPlanner.plan`: one REMEDIATION_PLAN call at temperature 0 with one re-ask → `finish`: invalid_plan on no action, strategy + register echoes by code, controls kept only when library-mapped, not register-held and not repeated, stamped from the library row, v1's warnings in v1's order, then the scheduler), `FinishedPlan`, PlanWarning/RemediationMessage additions | new `tests/test_remediation_planner.py` (12: the prompt equals the approved doc + nothing hidden reaches the AI, a clean draft, each removal, invalid_plan, urgency for the four labels only, the three coverage flags, one re-ask then generation_failed (also cut off), an outage left to the job); 8 mutations all killed. Review: a kept control kept the AI's own name → stamped from the library (G153); a repeated control stayed twice → removed (G154); 'even after one correction' was wrong for a too-long prompt → neutral message. Measured: real plan prompts 12-17k of 60k characters (ponytail note). BLUEPRINT R3/R6 corrected (one re-ask), G149-G154. 509 tests | ✅ |
| S50 | | new `data_access/remediations.py` (`RemediationRepository`: indexes (unique `scenario_id`; `{entity_id, created_at -1}` and `{entity_id, X, created_at -1}` per list filter), `insert` (False on a duplicate scenario), `find_status`, `find_for_scenario`, `find_snapshot` (one version via positional projection)); new `data_access/remediation_versions.py` (`RemediationVersions`: `find_for_change`, `append_version` (R8: one pipeline write fenced on epoch + done/failed, the latest outcome frozen onto its item, `$literal` keeps '$' text as text), `decide` (fenced on `decision_seq`, incremented)); `Collection.REMEDIATIONS`; `RemediationStatus.entity_id` (the 403 check); indexes at start-up | new `tests/test_remediation_store.py` (3: one plan per scenario + status + one snapshot, the version append guard + frozen outcome + '$' text, a stale decision refused); 6 mutations all killed. Review: a pipeline update was needed because $push and $set on one array conflict; a free text starting with '$' would have been read as a field path → `$literal`. Moved: `list_for_entity` to S53 (its RemediationSummary model lives there). For S52: the insert must set `decision_seq: 0` (a missing field never matches 0); JobLease.fail writes the session-only `last_action.outcome`; the finish must make the record's decision pending when no version is accepted. 512 tests | ✅ |
| S51 | | `ControlLeases.claim_scenario` (one scenario: queued, failed, expired, done with no item, or never asked; a live lease → none) and `find_mapped`, one shared claim update (`_running`); the sweep split out as `ControlSweep` (8 public methods > 7); `controls_record` moved from the controls task to `engine/scenarios/control_mapper.py` (one builder for the job and the top-up); new `services/remediation/controls_top_up.py` (`ControlsTopUp.map_now`: claim under a unique `api:<request>:<uuid>` owner, map in a pool thread the request waits for at most `TOP_UP_SECONDS`, fenced finish + counts + live update; late/outage → given back (generated: queued + MAP_CONTROLS sent now; hand-written: failed) and 503 `controls_not_ready` Retry-After 30; no fitting control → 409 with its code); constants | new `tests/test_controls_top_up.py` (6: mapped in the request, a live lease → 503 + a mapping finished meanwhile used, past the deadline → given back + sent + the late result never saved, a hand-written scenario fails, an outage gives back, no fitting control → 409); 6 mutations all killed. Review: a claim that found the controls mapped meanwhile would have answered 503 → `find_mapped`; an empty library or no compatible control is not temporary → 409, never 503 + Retry-After; the given-back scenario waited up to 30 min for the sweep → MAP_CONTROLS sent now. For S55: the sweep re-queues any failed mapping after 30 min, so a hand-written scenario's would be mapped in the background (R1T says never). 518 tests | ✅ |
| S52 | | new `services/remediation/requests.py` (`PlanRequestService.request`: 404/403/409 not accepted, 409 `plan_already_exists` before any mapping (details: the plan's id), the top-up when controls are missing, register resolved, snapshot v1, one insert (the duplicate-key loser → 409 with the winner), job sent, audit `plan.requested` with the risk owner masked, publish; `new_plan_record` with `decision_seq: 0`, `new_version`), new `services/remediation/queries.py` (#15), new `api/routers/remediation.py` (POST /v1/remediation 202, GET /v1/remediation/{id}/status), new `worker/tasks/remediation.py` (`tsg_write_plan`: leased (epoch = version), `RemediationPlanner.plan`, one fenced `finish` with `versions.$[v]` filters, `tsg_plans_total{outcome}`); `publish_remediation_status` (+ `REMEDIATION_CHANNEL`); `JOB_COLLECTIONS` gains tsg_remediations (reaper + indexes); `JobLease.finish(changes, array_filters)`; `_failed` writes the run-only `last_action` on runs only; `RemediationRepository.find_scenario`; task route + module; constants | new `tests/test_remediation_requests.py` (5: request → job → done → status, every refusal (404/403/409×2/422×2, status 404/403), a request made at the same moment → 409 with the winner, missing controls topped up + a second request refused before any mapping, a failed version keeps generation_failed with no run-only field); 6 mutations all killed. Review: a remediation record failed by the lease or the reaper got the run-only `last_action` → written on runs only; test scenarios of entity 86 leaked into another test's entity list → own entity. Not done: the worker writes no audit (`plan.completed`): no worker audits, the version record is the trail (BLUEPRINT R3 to update in S56); the Grafana panel for tsg_plans_total in S56. For S55: a hand-written scenario must carry every field the #9 list reads. 523 tests | ✅ |
| S53 | | new `models/remediation_views.py` (PlanView: the stored AI layout shown flat, dates YYYY-MM-DD; VersionView: the latest version's status/error from the record; ScenarioSummary; RemediationResult; `shown_version`: accepted else newest done; RemediationSummary + RemediationList), new `data_access/remediation_reads.py` (`RemediationReads`: find_status, find_result without snapshots, list_for_entity (one index scan + one count), find_scenario_summary; split out because RemediationRepository reached 8 public methods), `services/remediation/queries.py` (result, list_plans, `find_remediation_status_for_caller`, `read_current_remediation_status`, one `_owned` check), routes #16 GET …/result?include_history and #17 GET /v1/remediation (filters session_id, scenario_id, status, decision, risk_level; paged), #28 GET /v1/remediation/{id}/events (one shared SSE loop `_status_stream` for #8 and #28), `Event.REMEDIATION_UPDATED`, paging params shared in api/dependencies | new `tests/test_remediation_reads.py` (4: the shown-version rule, history without snapshots (also at the read) + a failed latest's status/error from the record, each filter newest first, another entity) and a plan stream test in test_realtime.py (status at once, two published changes, 403/404); 7 mutations all killed. Review: the hub's first subscription makes every stream re-read once, which hid a wrong channel (a channel mutation survived) → both stream tests (#8 too) now prove delivery with a second change through one helper. 528 tests | ✅ |
| S54 | | new `engine/remediation/decisions.py` (pure: `version_status` (the latest's from the record), `newest_done_version`, `record_decision` (accepted / pending while the latest or a done version waits / rejected), `decision_update`: one $set + array filters, None for a repeat; accepting moves accepted_version and puts the earlier one back to pending; rejecting the accepted one clears it), new `services/remediation/decisions.py` (#12/#13: 404/403, read-only plan → 409 scenario_not_accepted, 404 version_not_found, 409 not_complete, one decision_seq-fenced update, one re-read then 409 changed_concurrently, audit plan.accepted/rejected), new `services/remediation/regenerate.py` (#14: read-only/in-progress refusals, snapshot made now from the stored register, a warning per control no longer mapped, one conditional append, send/audit/publish, 202), new `services/remediation/snapshots.py` (`SnapshotMaker`: one path for R1 and R8; requests.py now uses it; `still_accepted`), `append_version` also re-derives the record's decision and bumps decision_seq (pipeline helpers), routes accept/reject/regenerate, constants | new `tests/test_remediation_review.py` (4: v1 → v2 with the outcome frozen + a lost control warned + 409 while written + 422 on a body field, one accepted version at a time + a repeat writes and audits nothing + rejects and the record's decision, every refusal + v1 rejected while v2 is written stays pending + a read-only plan, a raced decision reads again once then 409) and the store test (a decision read before an append is refused); 9 mutations all killed (3 survived at first → tests added: a repeat's response, the latest-waits rule, the append's sequence bump). Review: the spec's R9 derived the record's decision only on decisions, so a rejected plan regenerated stayed 'rejected' while v2 awaited review → re-derived on every append too, and a version being written or failed counts as waiting; append_version over 40 lines → helpers. 532 tests | ✅ |
| S55 | | library: `ThreatLibrary.types` (every live type with its STRIDE category and linked actors) and `category_ids`, `AttackerAssigner` reads a type's links from the type list too; new `engine/remediation/threat_identity.py` (Rule L2, pure: live → pending → curator-rejected → new; id wins, id and name must agree; a known threat under another type → 422 type_mismatch naming the library's type; the category rule; every fault in one 422), new `engine/remediation/manual_records.py` (key-derived ids; the manual run (done, inactive) and scenario (accepted, no title, every field a generated one has, route standalone for 1 system else unknown); given controls in order, match given), new `data_access/manual_scenarios.py` (upserts: a retry lands on the same documents), new `services/remediation/manual_scenarios.py` (asset checks, identity, strict controls, attackers ranked (closest flagged for a new type), a new wording proposed pending + audit library.proposed, save, counts), new `services/remediation/manual.py` (Idempotency-Key required, shared with runs; replay 200; a generated run's key, another asset or another body → 409; a crash before the scenario was saved is made again; a duplicate at the same moment replays), `PlanRequestService.plan_scenario` shared by both paths; the route answers 200 on a replay; the snapshot shows a given control to the AI as exact (relevance null); the sweep never maps a hand-written scenario (R1T); #6 refuses a hand-written scenario (`hand_written`) | new `tests/test_threat_identity.py` (4) and `tests/test_remediation_manual.py` (4: saved + planned + replayed + the entity list + #6/#7 refused, the key rules with no library write on a taken key, new wordings proposed pending (a new type linked to its closest attacker) and a rejected one not, strict controls (nothing saved) else the top-up) + a sweep test; 12 mutations all killed (2 survivors first → tests pinned the kind rule's no-side-effect and a reformatted strict check). Review: regenerating a hand-written scenario passed the target rules and would 500 (a manual run has no write job) → `hand_written` refusal; the sweep would have mapped a failed hand-written top-up in the background → filtered; the approved prompt knows exact/nearest only → a given control reads as exact. 541 tests | ✅ |
| S56 | | independent review (14 points) + own cross-check, every point fixed at its cause: risk owner masked in traces; the register resolved before anything is saved or mapped; a stored register notes a later library change (never 422); an abandoned queued top-up cancelled; the register's controls by name over the model's input; `plan.completed` audited (`record_audit` moved to data_access so the job can audit); no unredacted text or database id to the AI; every mapped control retired → mapped again; #16 builds the shown version only; a demoted version's stamp cleared; blank statements refused; the run's counts follow every top-up change; category id/name cross-checked; also `register` → `register_data` (shadowed pydantic). Docs: BLUEPRINT M11 'as built' + status rows + §13.3, gaps G155-G177; IMPLEMENTATION_GUIDE Step 16; RUNNING; Grafana panel for tsg_plans_total. Dev run on asset 1179 (real stores and AI): plan A (window) 5 actions, 24 days, no warning; plan B (no window) 4 actions, 18 days, 1 warning; regenerate v2 6 actions 33 days; accept v1 then v2 (v1 back to pending); 9-14 s and 1-2 AI calls per version (one re-ask: a missing action_plan) | new tests across 9 files (G155-G177, each pinned); 14 review-fix mutations all killed. 549 tests; ruff, format and mypy clean | ✅ |

**Blockers / unresolved (owner / curator):**
- **Library data:** 137 of 164 threat types (376 of 451 threats) link no attacker in `ThreatType_ThreatActor_Map`, so
  106 of 159 threats on asset 1179 take a "closest" attacker plus an AI check. A curator linking attackers to those
  types fixes it at the source; the largest are Input Manipulation (41 threats) and Embedded Device -
  Application/System Software (30/26).
- **Volume:** judging every threat finds about 140-160 relevant threats per asset (run to run, the AI's verdicts
  vary by a few percent). With `TOTAL_SCENARIO_COUNT=0`, every one is written (up to 4 AI calls each in Step 12):
  set a positive count if fewer scenarios per run are wanted.

---

## Part 0: How to use this document (read first, every session)

1. **Where it lives.** Step S0 copies this file to `docs/BUILD_PLAN.md` and adds a memory pointer naming the current
   step. From then on, `docs/BUILD_PLAN.md` is the working copy: tick each box when its step passes, and update the
   memory pointer.
2. **Order.** Do the steps strictly in order, S0 → S43. Never start a step before the previous step's **exit check**
   passed. Three steps are **owner gates** (S14, S29, S36): stop, report and wait.
3. **Every step has the same parts:**
   - goal;
   - files;
   - exact changes;
   - tests that fail without the change;
   - exit check;
   - a one-line plain-English report to the owner.
4. **Standing rules in every step:**
   - **Checks:** `.venv\Scripts\python -m pytest -q -p no:cacheprovider`, `.venv\Scripts\python -m ruff check app
     scripts tests`, `.venv\Scripts\python -m ruff format --check app scripts tests` and `.venv\Scripts\python -m mypy
     app` must all pass at every exit check.
   - **Guards** (`tests/test_code_conventions.py`):
     - class ≤ 150 lines and ≤ 7 public methods;
     - function ≤ 40 lines;
     - file ≤ 300 lines;
     - one-way layer imports;
     - database calls only in `data_access/`;
     - data shapes only in `models/`;
     - no inline log or raise strings (use `LogEvent`, `ErrorMessage`, `PlanMessage`);
     - each constant defined once in `core/constants/<topic>.py`.
   - **Code style:**
     - descriptive function names;
     - comments as dense as the surrounding code;
     - a `ponytail:` comment on every deliberate simplification.
   - **Fact-forcing gate hook:** the first Write/Edit of a file is refused. State the importers, the affected API or
     schema, and the user instruction, then retry.
   - **Never:**
     - print or copy `.env` / `.env.uat` values;
     - touch `prompts_05_Oct_2026.py`;
     - commit or push unless the owner asks;
     - change UAT without asking;
     - run destructive data deletes.
   - **Fixes:** real fixes only (the root cause), never a guessed threshold. Every fix gets a gap-register number
     (G106+) in `docs/BLUEPRINT.md`.
   - **Reporting:** plain English, with an example; lead with the result.
5. **Module review at every exit check** (owner, 2026-10-10). Before a step is ticked, review the code it touched:
   1. **Gaps:** cross-check it against Part 3 and the spec for logical or fundamental gaps (wrong order, missing
      case, silent failure, race, a state that can't be reached or can't be left).
   2. **I/O:** one database or AI call per batch, never one per item in a loop; no repeated reads of the same
      data; bounded waits.
   3. **Size:** no god class, god function or god file (the size guards plus judgement: one job per function).
   4. **Production readiness:** errors handled, edge cases covered, concurrency-safe writes, auditable, no secret
      logged, traced with `@traced`.
   5. **Real fixes:** fix every finding at its cause, so the symptom can't recur, with a test that fails without
      the fix. Record it in the step's tracker row ("review: …").
6. **Interim state.** Until S25 registers `tsg_write_scenarios`, a run planned by the worker is failed by the reaper
   with `job_never_started`. Dev checks use `scratchpad/dev_plan_run.py`. **No UAT deploy until S29 passes.**
7. **No human in the loop during a run.** Stages A–G (Part 3) run by themselves; the first human action is review
   (Stage H). The owner gates are one-time development decisions, never steps inside a run.

---

## Part 1: Owner rulings this plan follows (2026-10-10)

1. **Rule book: mostly the owner's** (Appendix A).
   - Keep the owner's rule for:
     - C1: backups are the next 3 linked attackers;
     - C2: the closest attacker when a type links none (measured in S12);
     - C3: entity-only isolation;
     - C4: no requires/produces;
     - C10: public monitoring, with a written risk acceptance at go-live;
     - C11: an AI timeout is not retried in the call;
     - C12: the worker never imports services.
   - Follow the spec in the two safety cases:
     - C5: only exact code checks can block a scenario;
     - C9: an attacker is shown only as a type of attacker, never as a confirmed named group.
   - Spec self-contradictions (Appendix B): run states follow §10.2, collections §4.2, folders §2.2; the type corpus
     stays; no requires/produces.
2. **Build order:** scenario writer (Step 12) → controls (Step 13) → review (Step 14). Threat intelligence (ATT&CK and
   the rest) comes later.
3. **One threat = one scenario path.** The AI never joins threats into chains. Chains return only through
   owner-approved rules.
4. **Only the asset and the supporting systems the platform sends are loaded** (current behaviour).
5. **`Threat_Actor.IsCapable` is ignored.** Every active actor is eligible.
6. ~~The relevance gate also picks the acting attacker (G117).~~ **Changed by the owner on 2026-10-10 after
   measurement M2** (the AI picked "Nation-state/APT" for 8 of 10 threats): the acting attacker is chosen by search
   ranking among the type's linked actors (G120).
8. **Every threat of each category is judged** (owner, 2026-10-10, after measurement M1: the top-10 shortlist missed
   224 relevant category judgements against 75 found). The run must also be fast: judge in small batches, many at
   once, paced by the AI slot limit (G121). The library has no IT/OT, sector or type description on its threats
   (checked in DevTest5), so no asset-type filter is possible without new library data.
9. **Strict library data** (owner, 2026-10-10): a threat with no category of its own is left out with a
   `library_data_invalid` note, never given its type's category (G119).
10. **No linked attacker → meaning-based search, then the AI** (owner, 2026-10-10). The search ranks only the
    attackers the library links to at least one threat type: today the 9 generic attacker types; none of the 40
    named groups (APT28, Sandworm, ...) is ever linked. The AI then picks one of the top 3 or says none fits. A
    named group is never chosen by word likeness (G122, spec v4.0 §1 "actor identity vs attribution").
7. **Configurable step tracing** (owner, 2026-10-10): `DEBUG_STEP_OUTPUT=true/false`. When true, every workflow step and
   significant function logs its redacted inputs, intermediate results, outputs, time taken and errors. When false, only
   the essential operational, security and audit logs remain. Secrets are never logged.

---

## Part 2: The build checklist

### S0: Save the plan where it can't be lost
- [x] Copy this file to `docs/BUILD_PLAN.md`. (done 2026-10-10)
- [x] Add memory file `build-plan-2026-10-10.md`: "follow docs/BUILD_PLAN.md step by step; current step S1". Add its
  line in `MEMORY.md`.
- **Exit:** both exist. Update the memory line at every later exit check.

### S0b: G118, configurable step tracing (`DEBUG_STEP_OUTPUT`)
- **Goal:** with `DEBUG_STEP_OUTPUT=true`, every workflow step logs `step.started` (redacted inputs),
  `step.finished` (redacted output, milliseconds) or `step.failed` (error type, redacted message, milliseconds). With
  `false` (the default), nothing extra is logged and the cost is one boolean check.
- **Changes:**
  - `core/config.py`: `debug_step_output: bool = Field(default=False, validation_alias="DEBUG_STEP_OUTPUT")`, plus
    `populate_by_name=True` so field names still work in code. This is the second unprefixed name the owner chose.
  - `core/redaction.py` (new): the secret-text patterns and `redact` move here from `engine/shared/prompt_redaction.py`
    (which imports them back), with the secret-field-name rule from `core/logging.py`, and `safe_preview(value)`.
    `safe_preview` gives a bounded, redacted picture of any value:
    - strings are redacted and clipped;
    - fields with secret names (`*_key`, `password`, `token`…) are masked;
    - lists become their length plus the first 3 items;
    - dataclasses and Pydantic models are previewed by their fields;
    - depth is limited, and any other object is shown by its type name.
  - `core/tracing.py` (new):
    - `set_step_tracing(enabled)`, called by `configure_logging`;
    - `traced_step(name, **inputs)`, a context manager whose `.record(**results)` logs intermediate results;
    - `@traced(name)`, a decorator logging a function's arguments and return value.
  - `core/constants`: `LogEvent.STEP_STARTED / STEP_FINISHED / STEP_FAILED`, and a `Tracing` class (preview limits).
  - Apply `@traced` / `traced_step` to every workflow step:
    - run start, context freeze;
    - landscape, search, each category check, each AI gate batch, gap-fill;
    - dedupe stages, actors, attacker check;
    - paths, ranking, plan;
    - AI chat / embedding / rerank calls;
    - every later step (writer, controls, review) as it is built.
  - `.env.example`, `.env`, `.env.uat`: `DEBUG_STEP_OUTPUT=false`. The config-sync test learns the unprefixed names.
- **Tests (`tests/test_step_tracing.py`):**
  - off → no step logs;
  - on → started and finished with milliseconds;
  - inputs redacted (key fields masked, passwords in text redacted, long text clipped, lists summarised);
  - failure → `step.failed`, and the error is still raised;
  - the decorator returns the function's own value.
- **Exit:** all checks pass. A dev planner run with `DEBUG_STEP_OUTPUT=true` shows each step with timings, and no
  secret appears in the log.

### Phase 1: fix the built threat finding (S1–S11)

#### S1: G106, the `TOTAL_SCENARIO_COUNT` setting
- **Goal:** the scenario count comes from `.env`, not code. 0 = every valid path; N = the top N.
- **Changes:**
  - `core/config.py`: `total_scenario_count: int = Field(default=0, ge=0, validation_alias="TOTAL_SCENARIO_COUNT")`.
    It is the only setting without the `CII_` prefix (spec §1); its comment says so.
  - `core/constants/runs.py`: delete `Generation.MAX_SCENARIOS`.
  - `engine/scenarios/attack_paths/path_selector.py`:
    - `AttackPathSelector(chat, target)`; `plan()` uses `self._target` for `select_up_to_target` and `"target"`;
    - `get_attack_path_selector()` passes `get_settings().total_scenario_count`.
  - `.env.example`, `.env` and `.env.uat`: the line `TOTAL_SCENARIO_COUNT=0` with a one-line comment. Edit in place;
    never print values.
  - `tests/test_config.py`: the env-sync test accepts `TOTAL_SCENARIO_COUNT` as the one unprefixed key.
- **Tests:**
  - `test_total_scenario_count_reads_the_unprefixed_name` (12 → 12);
  - `test_total_scenario_count_refuses_negative_decimal_and_text` (−1, 1.5, "abc" fail at load);
  - the target test in `tests/test_attack_paths.py` uses the selector's target.
- **Exit:** all checks pass. `grep MAX_SCENARIOS app tests` finds nothing.

#### S2: G108, safe gap-fill
- **Goal:** an AI proposal never reaches a scenario with a made-up type, a random attacker or curator-rejected wording.
- **Changes (`engine/scenarios/finding/ai_gap_fill.py`):**
  - Delete the attacker choice: `closest_actor`, the lowest-ID fallback (line 162) and the `actors` constructor
    argument. Delete `LibraryMatcher.closest_actor` (`library_match.py:31-33`) once a grep shows it unused. The AI's
    `attacker` field stays in the answer contract but is never read.
  - **Type below 75:** record `GapFillOutcome.UNTYPED` and `PlanMessage.GAP_FILL_UNTYPED` (naming the proposed threat
    and type), and return no threat.
  - **Before the gate:** if `name_match_key(proposal threat)` equals a pending threat row (`ThreatLibrary.pending`, kind
    threat) or a curator-rejected threat (`ThreatLibrary.curator_rejected`), record
    `GapFillOutcome.PREVIOUSLY_REJECTED` plus the rejection `CandidateRejection.AI_PREVIOUSLY_REJECTED`, and return no
    threat.
  - An accepted AI threat always carries the library's `type_id` and `type_name`, and **no actors** (S4 assigns them).
- **Also:**
  - `threats.py`: update the `GapFiller(...)` construction and pass the pending and rejected names.
  - `core/constants/planner.py`: the new members and messages.
- **Tests (`tests/test_threat_finding.py`):**
  - `test_an_untyped_gap_fill_proposal_becomes_a_note_not_a_threat`;
  - `test_a_gap_fill_proposal_matching_rejected_wording_is_refused`;
  - `test_gap_fill_never_picks_an_attacker`.
- **Exit:** all checks pass.

#### S3: G109, never merge two different threat types
- **Changes:**
  - `dedupe.py`:
    - `merge` rule b: fold an AI threat into its library twin only when `type_id` is equal; otherwise keep both and add
      `PlanMessage.TYPE_CONFLICT_KEPT_APART`;
    - `merge_reworded_threats`: compare an AI threat only with kept threats of the same `type_id`.
  - `same_attack.py` `_read_group`: a group whose members' `type_id` differ is a problem ("threats of different types
    are never the same attack"). Valid groups are kept.
- **Tests:**
  - `test_same_name_with_a_different_type_is_kept_apart_with_a_note`;
  - `test_same_attack_never_groups_two_types`;
  - `test_rewordings_fold_only_within_one_type`.
- **Exit:** all checks pass.

#### S4: G110, attackers chosen once, after duplicates are removed
- **Changes:**
  - Split `AttackerAssigner._planned`: a function `accepted_library_threat(category, threat, verdict)` builds the threat without
    actors. Put it in `attackers.py`, or a new small module if a size limit is hit.
  - `AttackerAssigner.assign_attackers(threats: list[PlannedThreat], ...)` adds the actors to the final threats:
    - a library threat uses `LibraryThreat.linked_actors`;
    - an AI threat uses its type's actors, from a `type_id → linked actors` map built once from the snapshot.
  - `threats.py` `_merge_and_assign_attackers` order: planned threats → `merge` → `merge_reworded_threats` → `SameAttackCheck.merge_same_attacks` →
    `AttackerAssigner.assign_attackers` → `AttackerFitCheck.check_attackers` → `_named_threat`.
  - `same_attack.py` `pick_surviving_threat` key: `(not from_library, tie_break)`. The attacker no longer counts.
  - `AttackerFitCheck`: check every `closest_attacker` threat with options, library or AI (drop `t.from_library`).
- **Tests:**
  - `test_attackers_are_ranked_only_for_threats_left_after_duplicates_are_removed`;
  - `test_the_survivor_of_a_same_attack_group_ignores_its_attacker`.
- **Exit:** all checks pass; the existing actor tests still pass.

#### S5: G117, the relevance gate picks the acting attacker
- **Changes:**
  - `prompts.py` `relevance_gate_prompt`: each verdict also returns `"attacker"`, the ONE listed attacker most likely to
    carry out the threat against this asset, or `null`. Bump `PLANNER_PROMPT_VERSION`.
  - `models/planner_replies.py`: `RelevanceVerdict.attacker: str | None = None`.
  - `models/threats.py`: `Verdict.attacker_id: int | None`.
  - `relevance.py` `parse_verdict`: gets the slot's attacker list (names → IDs) and keeps the pick only when it equals a
    listed name after `name_match_key`. A missing or wrong pick is **ignored**, never a re-ask, so it can never cost a
    category.
  - `attackers.py` `AttackerAssigner`: a valid pick in the threat's linked actors acts (goes first), and the ranking orders
    the rest as up to 3 backups. With no valid pick, the ranking decides.
- **Tests:**
  - `test_the_gate_pick_acts_and_the_ranking_orders_the_backups`;
  - `test_an_unlisted_gate_pick_is_ignored_without_a_re_ask`.
- **Exit:** all checks pass.

#### S6: G111, retry key fingerprint and strict body
- **Changes:**
  - `models/scenarios.py`: `StartRunRequest.model_config = ConfigDict(extra="forbid")`.
  - `services/scenarios/runs.py`:
    - `request_hash` = SHA-256 of `json.dumps(request.model_dump(mode="json"), sort_keys=True)`, stored by
      `new_run_record`;
    - `_replay` answers 409 `idempotency_key_conflict` when the stored hash differs. A record without a hash is
      compared on asset only.
- **Tests (`tests/test_runs.py`):**
  - `test_the_same_retry_key_with_other_systems_is_a_conflict`;
  - `test_an_unknown_body_field_is_refused`.
- **Exit:** all checks pass.

#### S7: G112, broken AI numbers are refused
- **Changes:**
  - `ai/embeddings.py` `_read_checked_vectors`: refuse a vector with a NaN or infinite value through a new
    `EmbeddingNotFinite(UnusableAiAnswer)` and an `ErrorMessage` entry; it is not retried.
  - `ai/rerank.py` `_read_checked_scores`: each `relevance_score` must be finite and within 0–1, else
    `IncompleteAiAnswer` (retried), with an `ErrorMessage` entry.
- **Tests (`tests/test_ai.py`):**
  - `test_an_embedding_with_a_nan_is_refused`;
  - `test_a_rerank_score_outside_0_to_1_is_refused`.
- **Exit:** all checks pass.

#### S8: G113, an honest finish
- **Changes:**
  - `core/constants/runs.py`: `RunActionOutcome.PARTIAL = "partial"`.
  - `worker/tasks/scenarios.py`: a plan with no selected path finishes with `PARTIAL` when `plan["not_assessed"]` is not
    empty, else `COMPLETE`.
  - `models/scenarios.py`: the status view shows it.
- **Test:** `test_a_run_with_a_category_not_assessed_ends_partial`.
- **Exit:** all checks pass.

#### S9: G114, one threat = one path (delete the AI grouping)
- **First:** grep `AttackPathGrouping`, `attack_path_prompt`, `AttackPathProposal`, `AiTask.ATTACK_PATHS`,
  `PlanMessage.GROUPING_NOT_MADE`, `.links` and `"links"` in `app/` and `tests/`.
- **Delete:**
  - `engine/scenarios/grouping.py`;
  - `prompts.attack_path_prompt`;
  - `planner_replies.AttackPathProposal`;
  - `AiTask.ATTACK_PATHS` and its temperature (`core/constants/ai.py:23,38`);
  - `PlanMessage.GROUPING_NOT_MADE`;
  - grouping-only `AnswerProblem` and `LogEvent` members;
  - `AttackPath.links` (`models/threats.py:154`) and the plan record's `"links"` (`paths.py:71`).
- **Keep:** `ThreatFinding.LINK_MAX_CHARS` (it clips the same-attack reason) and `RULE_LINKS` (the writer uses it; deleted in S18: the approved writer prompt's rule 4 replaces it).
- **`paths.py` `plan()`:** `paths = [AttackPath((threat,)) for threat in findings.threats]`. Bump
  `PLANNER_PROMPT_VERSION`.
- **Tests:** replace `test_valid_chains_are_kept_and_an_ungroupable_batch_stays_one_step_paths` with
  `test_every_threat_becomes_exactly_one_path`; keep the ranking, target, frozen-plan and refusal tests.
- **Exit:** all checks pass; the grep finds no grouping names.

#### S10: G116, stale text
- **Changes:**
  - `core/constants/planner.py:37`: the `ActorRole.ALTERNATE` comment becomes "the next linked actors, best fit first".
  - `.env.example:54` and `.env.uat:36`: delete "once the AI slot limiter is built".
  - `services/scenarios/context.py:66-68`: use `ThreatFinding.SYSTEM_ALIAS`.
- **Exit:** all checks pass.

#### S11: Phase 1 close-out
- [ ] `docs/BLUEPRINT.md` gap register: G106, G108–G114, G116, G117 (problem → fix → test), with G107 and G115 as
  "dropped (owner ruling)".
- [ ] `docs/IMPLEMENTATION_GUIDE.md`: the built table and the test count.
- **Exit:** all checks pass. Report the new test count.

### Measurements (S12–S13)

#### S12: Dev measurements on asset 1179 (`scratchpad/dev_plan_run.py 135 1179 1488,1489,1490`)
Scratchpad script only; no product code.
- **M1, shortlist recall:** after the normal check, run the gate on each category's unjudged threats and count the
  relevant ones the top-10 shortlist missed.
- **M2, attacker fit:** for 10 threats, list the gate's pick and the ranked linked actors.
- **M3, category fallback:** count library threats with no category link of their own.
- **M4, closest attacker (C2):** count threats whose type links no actor.
- **Also:** threats, paths (= threats), seconds and AI calls by task, against the last run (42 / 36 / 155 s).

#### S13: Report the measurements
A plain-English report with one recommendation each:
- **M1:** misses > 0 → propose adaptive paging.
- **M3:** a `library_data_invalid` decision.
- **M4:** a C2 decision.

Any change these lead to gets its own G-numbered step, inserted before S14.

#### S13a: G119, strict library data (owner ruling 9)
- `data_access/library.py` `_to_library_threat`: a threat with no category link is left out (not given its type's
  category); the loader counts such threats and the plan carries `PlanMessage.LIBRARY_DATA_INVALID`.
- **Test:** a threat without a category link is not planned, and the note names how many there are.

#### S13b: G120, the acting attacker by search ranking (owner ruling 6, undoing G117)
- Remove the gate's `attacker` field (prompt, `RelevanceVerdict`, `Verdict.attacker`,
  `PlannedThreat.suggested_attacker`) and the pick in `AttackerAssigner`. Bump `PLANNER_PROMPT_VERSION`.
- **Test:** the ranking alone orders the linked actors (the G117 tests are replaced).

#### S13c: G121, every threat judged, fast (owner ruling 8)
- `categories.py`: each category judges ALL its threats, shortlist first (search order), then the rest;
  `whole_category` is always true, and gap-fill runs only when none applies.
- `relevance.py`: batches hold at most `ThreatFinding.GATE_BATCH_MAX_ITEMS` threats (a shorter answer comes back
  faster) and run at once in a pool of `ThreatFinding.GATE_BATCHES_AT_ONCE` per category. The AI slot limit
  (`CII_MAX_CONCURRENT_AI_CALLS`) paces them across categories and runs.
- **Measure** the wall time on asset 1179 before and after; record both numbers.
- **Tests:** every category judges every threat; batches run concurrently and keep slot order in the result; a
  failed batch still makes the category not assessed.

#### S13d: G122, no linked attacker → search the vetted attackers, then the AI (owner ruling 10)
- `attackers.py` `AttackerAssigner`: for a threat whose type links no attacker, `find_actors` is limited to the
  attackers linked to any type (the curator-vetted pool); the AI check then picks among the top 3. If the library
  links no attacker at all, every actor is searched (noted).
- **Test:** an attacker never linked to any type (a named group) is never offered as a closest attacker.

### Phase 2: the writer prompts (S14)

#### S14: Update `docs/SCENARIO_PROMPTS_DRAFT.md`, then STOP for owner approval (gate)
- **One step:**
  - remove the "steps in order" rule, `leads_to_next` and `contributing_categories`;
  - `entry_point_options` = the threat's systems, or `[]` when it acts on the asset itself.
- **New rule:** write a possible attack ("could", "may"), never a confirmed incident.
- **Attacker rule (C9):** a type of attacker (for example "an organised criminal group"), never a named group that did
  or will attack.
- **Route:** set by code: `standalone`, or `unknown` when the scenario needs a system-to-system link the platform does
  not record.
- **Findings (C5):**
  - blocker = exact code faults only (an ID not in this run, another entity's data, an advisory number never
    supplied);
  - warning = the other code checks;
  - note = the AI plan check's words.
- **Plan check:** rules 1 and 4 adjusted for one-step paths.
- **Exit:** the owner approves the prompt text. **Nothing from S16 on starts before this.**

### Phase 3: record the rulings (S15)

#### S15: Decisions on record
- [ ] `docs/IMPLEMENTATION_GUIDE.md` §0.2: decisions #14–#19 (Part 1 rulings 1–6) plus a "Spec v4.0 errata" table
  (Appendix A and B with their rulings).
- [ ] `docs/BLUEPRINT.md`: the FR/BR rows touched by Part 1 (W1–W12 "copy v1 prompts" → the approved draft;
  alternates; IsCapable; systems; one-threat paths).
- [ ] `docs/HOW_SCENARIOS_ARE_GENERATED.md`: Part 3 of this document, kept in step with each phase.
- [ ] Memory: update `owner-decisions-2026-10-10.md` with rulings 3–6.
- **Exit:** a grep for "copy v1 prompts", "AI groups" and "IsCapable = 1" finds nothing stale.

### Phase 4: Step 12, the scenario writer (S16–S29), only after S14 is approved

#### S16: Constants and data shapes
- `core/constants/`:
  - `AiTask.WRITE_SCENARIO` and `AiTask.PLAN_CHECK` with temperatures (plan check 0.0; writer per the approved draft);
  - `FindingSeverity` = blocker / warning / note (replacing blocking/advisory; grep its users);
  - `ScenarioStatus` = written / failed / abandoned;
  - `Route` = standalone / unknown;
  - writer `LogEvent`s and `ErrorMessage`s;
  - `Generation.WRITER_BATCH = 6` (renaming `FIRST_BATCH`/`NEXT_BATCH`; grep users);
  - `Generation.MAX_PATH_ATTEMPTS = 5`.
- `models/` (in `models/writing.py` if `scenarios.py` would pass 300 lines):
  - `WriterBrief`;
  - `ScenarioDraft(title, statement, risk, assumptions, entry_point)`;
  - `Finding(code, severity, message)`;
  - `WrittenScenario` (the draft plus findings, notes, route and AI-call count);
  - the writer's Pydantic answer contract.
- **Exit:** all checks pass.

#### S17: `engine/scenarios/writing/brief_builder.py`
- `build_brief(plan, path, context, siblings)` returns a `WriterBrief`:
  - asset facts (`facts_safe_for_prompt`);
  - category;
  - type and threat (`threat_name_without_code`);
  - `why_it_applies` (the gate's reason);
  - the threat's systems by name, with facts;
  - the acting attacker;
  - `entry_point_options`;
  - `other_scenarios` (regenerate only).
- No database IDs; every text is redacted.
- **Tests:** only this path's systems; no IDs; entry options = the threat's systems or `[]`.

#### S18: `engine/scenarios/writing/writing_prompts.py`
- The approved system prompt and the brief user prompt, word for word from S14, with `WRITER_PROMPT_VERSION`.
- **Test:** the prompt carries the approved rules ("could/may", attacker as a type, unknown facts → assumptions).

#### S19: `engine/scenarios/writing/draft_cleanup.py`
- Remove framework codes (`TECHNIQUE_CODE`, `CAPEC-\d+`, CVE IDs never supplied, standard names) and asset, system and
  attacker names from the title.
- Turn "Because X, Y." into "Y, because X."; when that can't be done cleanly, use "This risk exists because …".
- Remove hashes and GUIDs.
- **Tests:** one per rule.

#### S20: `engine/scenarios/writing/exact_rules.py`
Exact checks, each returning a `Finding`:
- **blocker:** an ID not in this run; another entity's data; an advisory number never supplied;
- **warning:**
  - the asset not named in the statement or the risk;
  - the attacker type not named;
  - another library attacker named;
  - a system outside the brief named (whole word, case-aware);
  - an empty assumption.

**Tests:** pass and fail for each.

#### S21: `engine/scenarios/writing/ai_plan_check.py`
- One AI call at temperature 0 with the approved plan-check prompt. Answer `{consistent, problems}`, checked by a
  Pydantic contract, with one re-ask.
- An unusable answer → the note "plan check not made" (never a failure).
- **Tests:** consistent, problems, unusable.

#### S22: `engine/scenarios/writing/scenario_writer.py`, `ScenarioWriter.write_scenario(brief)`
1. Ask (`ask_for_checked_json`: fields present, not empty, entry point in the options; one re-ask).
2. Clean.
3. Rules plus the plan check.
4. If anything was found, ONE rewrite in the same conversation listing every problem, then clean, rules and plan check
   again.
5. Keep the draft with fewer problems (the rewrite on a tie).
6. Return a `WrittenScenario`.

It raises `UnreadableAiAnswer` after two unreadable answers, and `Unavailable` on an outage.

**Tests:** the happy path; a re-ask; a better rewrite kept; a better original kept; at most 4 AI calls plus re-asks.

#### S23: `data_access/scenarios.py`, writes
- **`insert_scenario`:**
  - `_id` = SHA-256(run + path_id + version); a duplicate key means already saved (no-op);
  - a unique index on `(session_id, title_key)` with the partial filter `{current: true}`;
  - a title clash → one retry with the threat-name qualifier.
- **`insert_failure`:** a failure card.
- **`count_scenarios`:** one aggregation for written / failed / abandoned / accepted / rejected / pending /
  `controls_waiting`.
- The index goes in `ensure_indexes`.
- **Tests:** a duplicate delivery saves once; a title clash gets the qualifier; counts by aggregation.

#### S24: Fenced path updates
- `plan.paths.$[p].served/attempts/abandoned/scenario_id`, filtered on the epoch and task ID → `LeaseLost` when not
  owned.
- **Test:** a stale epoch can't change a path.

#### S25: `worker/tasks/writing.py`, `tsg_write_scenarios`
1. `run_leased_job` → the context, plan and `job.batch`.
2. Up to 6 paths in parallel (`ThreadPoolExecutor(Generation.WRITER_BATCH)`, contextvars copied).
3. Each path as soon as it is done:
   - **written** → insert the scenario and mark the path served;
   - **`UnreadableAiAnswer`** → a failure card and attempts + 1; at 5 attempts, abandoned;
   - **`Unavailable`** → re-raised once the others finish (the job retries; saved paths are skipped).
4. After each save: recount, update the counts and plan note (fenced), `publish_session_status`.
5. Register in `TASK_MODULES`; remove `WRITE_SCENARIOS` from `NOT_BUILT_YET` (`tests/test_worker.py:380-384`).

#### S26: Continue and finish
- **More left:** after a batch, `hand_over(lease, WRITE_SCENARIOS, {"job.batch": next 6})` while selected paths remain
  unserved and not abandoned.
- **None left:** `status: done`, `active: false`; outcome `complete` when every path was written, `partial` when any
  failed or was abandoned, or `plan.not_assessed` is not empty.
- **Tests:** 14 paths → 3 batches by themselves; complete and partial finishes; a duplicate message does nothing.

#### S27: Metric
- `core/metrics.py`: `tsg_scenarios_total{outcome}` (written / failed / abandoned), on the Grafana dashboard. An alert
  only if the owner asks.
- **Test:** `tests/test_observability.py` sees it.

#### S28: Writer test suite T-WRT-01..22 (`tests/test_scenario_writing.py`, using `tests/fakes.py`)
The cases:
- the happy path;
- a re-ask;
- unreadable twice → a failure card;
- an entry point outside the options;
- each clean-up rule;
- each code rule and its severity;
- a blocker hidden and not counted;
- a plan-check note;
- one rewrite, keeping the better draft;
- a unique-title qualifier;
- a duplicate delivery;
- a stale epoch;
- an outage retry skips saved paths;
- 5 attempts → abandoned;
- the auto-continue;
- complete and partial finishes;
- counts by aggregation;
- a live update after each save;
- "could/may" and the attacker-type rule in the prompt;
- a system-to-system link claimed → warning.

**Exit:** all checks pass.

#### S29: Full dev run (gate: report and wait)
- Run the worker on asset 1179: plan plus every path written.
- **Report:**
  - minutes to the first 6 scenarios (target < 10);
  - total time;
  - AI calls per scenario;
  - failures;
  - 3 full example scenarios.
- **Exit:** the owner has seen it. Then update the guide, BLUEPRINT and memory.

### Phase 5: Step 13, controls (S30–S36)

#### S30: Write the detailed control steps first
Write them in this format into `docs/BUILD_PLAN.md`, following Part 3 Stage G, then build in order:
1. `search/snapshot.py` `find_controls(..., allowed=AssetType mask)`;
2. `engine/scenarios/control_mapper.py` `ControlMapper` (query, pool, top 40, rerank, keep ≥ 60, nearest fallback,
   de-duplicate, rank 1..n, raw and 0–100 scores);
3. `data_access` control writes (fenced, with a per-scenario control lease);
4. `worker/tasks/controls.py`: `tsg_map_controls`, queued per scenario at save, plus `tsg_retry_controls` on beat every
   30 min;
5. `controls_waiting` in the counts;
6. tests (scenario-only, risk-only and combined queries; the IT/OT pool; cutoff; nearest; no duplicates; unknown IDs
   refused; empty library → `control_library_empty`; no compatible control → `no_compatible_control`);
7. a dev run.

**Detailed control steps (S30, written 2026-10-10 before any control code).** They follow spec v4.0 §7.5 and Part 3
Stage G. Measured on the dev library first: 1,288 active controls, `AssetType` only `IT` (731) or `OT` (557); asset
1179 is OT, its systems OT, OT and IT. Rulings applied:
- **Never widen to incompatible controls** (spec §7.5.2; the plan the owner approved on 2026-10-10, test
  `no_compatible_control`). This replaces the 2026-10-08 "fall back to the whole library": a scenario with no
  compatible control gets no control and a clear reason, never an IT control for an OT-only scenario.
- **The pool follows the scenario, not only the asset:** the asset's type plus the types of the scenario's own
  systems (an OT asset's scenario on its IT system may get IT controls). `IT-OT` / `OT-IT` and a blank `AssetType`
  fit both.
- **No AI-written controls** (spec §7.5.6): only library rows, by search and the reranker. The optional "AI helps
  reformulate the query" fallback is not built (YAGNI: the reranker scores every candidate; add it only if
  measured recall is poor).
- "Preferred domain" in the ordering has no owner definition: not used (score, then id).

#### S31: The compatible pool and the control search
- **Goal:** a scenario's controls are searched only among controls that fit its asset and systems.
- **Files:** new `core/constants/controls.py` (`Controls` moved here from `library.py`: `MIN` 1, `SHORTLIST` 40, plus
  `QUERY_MAX_CHARS` 4,000, `MAX_ATTEMPTS` 5, `LEASE_SECONDS` 120, `RETRY_FAILED_AFTER_SECONDS` 1,800,
  `SWEEP_EVERY_SECONDS` 300, `RESEND_QUEUED_AFTER_SECONDS` 600; `ControlMatch` exact / nearest;
  `COMPATIBLE_ASSET_TYPES` IT → {IT, IT-OT, OT-IT}, OT → {OT, IT-OT, OT-IT}); `search/snapshot.py`.
- **Changes:** `compatible_asset_types(asset_type, system_codes)` = the union for every recognised code (IT, OT) among
  the asset's type and the scenario's systems' category codes; nothing recognised → empty (→ S32
  `no_compatible_control` with the reason "the asset and its systems record no IT/OT type").
  `find_controls(queries, top_k, allowed_types)` masks the rows before the top-k (as categories do for threats); a
  control with a blank `AssetType` always fits.
- **Tests:** OT asset + IT system → both; OT only → OT and the twins; a blank-typed control always fits; no
  recognised type → empty; the mask applies before the top-k.

#### S32: `engine/scenarios/control_mapper.py`, `ControlMapper.map_controls(scenario, context, snapshot)`
- **Goal:** one scenario's controls, from its scenario AND risk statement, by meaning.
- **Query** (fixed order, labelled, cut at 4,000 characters from the end, so the texts that matter most survive):
  category; threat type and name; acting attacker; title; scenario statement; risk statement; asset name and
  technology; the scenario's systems by name.
- **Steps:** the pool (S31) → library empty → `control_library_empty`; pool empty → `no_compatible_control` (both a
  `ControlsNotMapped(code, message)`, never a crash) → hybrid search in the pool, top 40 → ONE rerank call (the
  reranker already refuses a short answer or a score outside 0–1) → keep every control scoring ≥ the reranker
  profile's `control_cutoff` (60) as `exact`; none → the single best as `nearest` (a visible warning on the
  scenario's controls) → fold duplicates (same id, then the same normalised "name: description" text, IT/OT twins,
  keeping the higher score) → order by score, then id → ranks 1..n.
- **Result:** `MappedControl(control_id, code, name, domain, asset_type, rank, score, match)` (models), plus what made
  it: rerank and embedding models, the control library's stamp.
- **Tests:** the query holds both statements; the cut-off; the nearest fallback; twins folded; ranks contiguous; the
  two refusals; an outage raised (the job retries).

#### S33: Control writes, with a lease per scenario (`data_access/scenarios.py`, `data_access/sessions.py`)
- `claim_controls(session_id, task_id)`: ONE `find_one_and_update` takes one current written scenario of the run
  whose controls are `queued`, or `running` with an expired lease → `running`, `task_id`, `lease_until` (+120 s),
  `last_attempt_at`, `attempts + 1`. Two workers never take the same scenario.
- `finish_controls` / `give_back_controls` / `fail_controls`: fenced on `controls.task_id` and `running`. Given
  back → `queued` (`queued_at`), or `failed` once `attempts` reaches 5; failed with a code
  (`no_compatible_control`, `control_library_empty`) at once.
- `renew_controls_lease`, and the sweep's `requeue_stalled_controls(now)`: `queued` for over 600 s (message lost),
  `running` with an expired lease, `failed` for over 1,800 s → `queued` (attempts kept).
- **Counts written by two jobs:** `SessionRepository.write_counts(session_id, counts, computed_at)` writes only when
  `counts_at` is older (BLUEPRINT Rule S12), so an older count never overwrites a newer one. The write job (S25)
  moves its counts to this guarded write (its path state stays fenced).
- **Tests:** two claims, one scenario; an expired lease taken over; a stale task id cannot finish; 5 attempts →
  failed; the sweep re-queues each stalled kind once; an older count never wins.

#### S34: The jobs (`worker/tasks/controls.py`)
- `tsg_map_controls(record_id, epoch)` (queue `tsg_scenarios`; not leased on the run): loop claim → map (lease
  renewed every 30 s) → finish → counts → `session.updated`, until nothing is left. An outage gives the scenario
  back and retries the message after the back-off; `ControlsNotMapped` fails that scenario's controls with its code.
- The write job sends one `tsg_map_controls` after each batch's saves ("card first, controls later": reviewers see
  scenarios while controls are mapped).
- `tsg_retry_controls` on beat every 300 s (queue `tsg_maintenance`): the sweep, then one message per run found.
- Register both in `TASK_MODULES`, the beat schedule and the routes; remove them from `NOT_BUILT_YET`.
- **Tests:** saved scenarios get controls and `controls_waiting` reaches 0; an outage retries; a repeated message
  maps nothing twice; a failed scenario is re-queued by the sweep after 30 minutes; the run's status shows step
  `controls` only while controls wait.

#### S35: Dev run and docs
- Asset 1179: a new run, written and mapped; report per scenario: controls kept, nearest fallbacks, the seconds per
  scenario, AI calls (1 embedding + 1 rerank per scenario expected).
- BLUEPRINT C1-C8, Rules S10-S12 and the `controls` fields as built; HOW_SCENARIOS_ARE_GENERATED Stage G.

**S36 (gate):** report 3 scenarios with their controls.

### Phase 6: Step 14, review (S37–S43)

#### S37: Write the detailed review steps first
Same format, then build:
- **#4 accept and #5 reject:** a conditional update, mutually exclusive, 409 `generation_in_progress` while generating,
  idempotent, audited, live update.
- **#6 regenerate:** a new version of the same path through Stage F; the old one is kept with `current: false`.
- **#7 resume:** only selected paths left pending after an interruption; an atomic claim; 409 `nothing_left`.
- **#27 promote:** an accepted AI threat → `tsg_ResolveThreat` as pending; idempotent.
- **Tests:** races (double click, accept vs reject, resume vs worker), entity isolation, promotion idempotency.

**Detailed review steps (S37, written 2026-10-11 before any review code).** They follow spec v4.0 §6 (#4-#7, #27),
§6.1, §7.6 and BLUEPRINT M09 Rules S3-S7 and S13. Rulings applied (each one the simpler, safer reading where the
documents differ):
- **Decisions are final, except `replace_accepted`.** BLUEPRINT's state table (§12.2 "Version `decision`") allowed
  rejected → accepted and accepted → rejected, but Rules S4/S5 and the API table (§13 #4, #5) refuse both
  (`already_rejected`, `already_accepted`) and v1's un-accept route was not carried over: Rules S4/S5 win (G137 fixes
  the table). A reviewer who changes their mind regenerates the scenario and decides the new version.
- **Accept "all" is idempotent** (spec §6.1 #4: a repeat succeeds when the final state already holds): it takes every
  current written scenario not rejected; the ones already accepted are listed again, a path with another accepted
  version is skipped (`duplicate_version`, accept-all never replaces), and so is a scenario whose library threat was
  retired (`library_inactive`). 409 `nothing_to_accept` only when no such scenario exists. (Rule S4 step 2 read only
  pending ones, so a double click on "Accept all" answered 409 after a success.)
- **`library_inactive`** (Rule S4) uses the in-memory library, the same rule as G126 at write time: a library
  threat's id must be live or pending; an AI threat passes. The first decision in an API process loads the library
  once (then it refreshes in the background).
- **Regenerate does only its targets, then the run ends:** `complete` when every target got a new version,
  `partial` when any kept its old version (its `regenerate_error` says why). Open paths are resumed by #7, never as a
  side effect of a regenerate. Its 409 lists every id at fault under one reason, `scenarios_not_regenerable` (as
  accept's `scenarios_not_decidable`).
- **Run checks are reads; the writes carry the state filter.** Accept and reject read the run (Rule S3); next set
  and regenerate change the run in ONE conditional update on `{job.epoch, status done|failed, step scenarios}`, so
  of two clicks, or a click and a worker, exactly one wins.
- **Not built here:** 409 `manual_scenario` and the remediation read-only rule for a displaced accepted scenario
  arrive with hand-written runs and remediation (Step 16): neither exists yet.

#### S38: Constants, models and the plan-path rules shared by the API and the job
- **Goal:** the review vocabulary in one place; the "which paths are open" rules used by both the write job and #7.
- **Files:**
  - `core/constants/review.py` (new): `Review.MAX_IDS_PER_CALL` 50 (BR-SCN-02), `MAX_ID_CHARS` 64; `TargetProblem`
    (unknown, failure_scenario, already_rejected, already_accepted, duplicate_version, library_inactive,
    version_not_current, changed_concurrently); `PromotionOutcome` (inserted, existing, curator_rejected);
    `ReviewMessage`.
  - `constants/runs.py`: `ConflictReason` + nothing_to_accept, scenarios_not_decidable, scenarios_not_regenerable,
    duplicate_version, nothing_left, target_reached, scenarios_abandoned, asset_busy, scenario_not_accepted,
    nothing_to_promote. `constants/access.py`: `AuditAction` + scenario.accepted, scenario.rejected, run.next_set,
    run.regenerated, library.promoted; `AuditTarget.SCENARIO`.
  - `models/review.py` (new): `AcceptRequest`, `RejectRequest`, `RegenerateRequest` (extra fields refused; ids 1-50,
    each once, at most 64 characters), `TargetSkipped`, `AcceptResult`, `RejectResult`, `RunActionStarted`,
    `PromotionResult`.
  - `engine/scenarios/attack_paths/path_progress.py` (new, moved from `worker/plan_progress.py`): `is_still_to_write`, `next_paths_to_write`,
    `plan_counts`, plus `why_no_path_left(paths)` → scenarios_abandoned / target_reached / nothing_left.
  - `core/metrics.py`: `tsg_decisions_total{decision}`.
- **Tests:** a body with an unknown field, 51 ids or a repeated id → 422; `why_no_path_left` for each reason.

#### S39: #4 accept and #5 reject
- **Files:** `data_access/scenario_review.py` (new, `ScenarioReview`): `find_targets(session_id, ids)` (one `$in`
  read, blocked never found), `find_acceptable(session_id)` (accept-all), `find_accepted(session_id, path_ids,
  except_ids)`, `set_decision(ids, from_, to, stamp)` (one `update_many` filtered on the expected decision; False on
  a duplicate key or fewer modified: a race), `record_promotion` (S42). `services/scenarios/review.py` (new,
  `ReviewService.accept / reject`); `api/routers/review.py` (new).
- **Accept** (`POST /v1/sessions/{id}/accept`, `{scenario_ids: [..] | "all", replace_accepted: false}`):
  1. Rule S3: run queued or running → 409 `generation_in_progress`; failed in step threats → 409 `run_failed`.
  2. Targets: ids → per id `unknown` / `failure_scenario` / `already_rejected` / `duplicate_version` (two versions of
     one path) / `library_inactive`; any → 409 `scenarios_not_decidable` with `errors[{scenario_id, reason}]`,
     nothing written. "all" → as ruled above.
  3. A path with another accepted version: without `replace_accepted` → 409 `duplicate_version` (ids listed); with
     it → those versions back to pending first (one `update_many`), listed in `replaced`.
  4. One `update_many({_id: {$in}, decision: pending})` → accepted, `decided_by`, `decided_by_client`,
     `decided_at`. A race (duplicate key on `one accepted version per path`, or fewer modified) → one re-read: ids
     now accepted are listed, the rest skipped `changed_concurrently`.
  5. When anything changed: counts (Rule S12), `session.updated`, audit `scenario.accepted`,
     `tsg_decisions_total{accepted}`. A repeat changes nothing and writes no audit record.
  6. 200 `{accepted, replaced, skipped, controls_pending}`.
- **Reject** (`POST /v1/sessions/{id}/scenarios/reject`, `{scenario_ids}`): the same with `already_accepted`, no
  `duplicate_version` or library check; 200 `{rejected, skipped}`; audit `scenario.rejected`.
- **IO:** 1 run read + 1 targets read (+1 accepted-paths read) + 1 `update_many` (+1 for replaced) + counts + 1
  publish + 1 audit. No SQL call (the library is in memory).
- **Tests (T-SCN-13..19):** accept 2 → counts + one audit + live update; repeat → same answer, no second audit;
  each per-id reason; one accepted version per path and `replace_accepted`; an older version accepted; accept-all
  twice; accept vs reject at once → exactly one wins; generation in progress; another entity → 403;
  `decided_by_client` is the caller's key.

#### S40: #7 next set (resume interrupted work)
- **Files:** `data_access/run_actions.py` (new, `RunActionRecords`): `find_paths(session_id)` (`status, step,
  job.epoch, plan.paths`), `queue_again(session_id, entity_id, epoch, job, last_action)` (ONE conditional update on
  `{_id, entity_id, job.epoch, status done|failed, step scenarios}` → `status queued, active true`, a fresh `job`
  (task `tsg_write_scenarios`, epoch + 1, the batch) and `last_action {kind, outcome running}`; returns whether it
  matched, or `RunClash.ACTIVE_RUN` on the one-active-run index), `find_plan_threat` (S42).
  `services/scenarios/run_actions.py` (new, `RunActions.next_set`).
- **Steps** (`POST /v1/sessions/{id}/scenarios/next-set`, no body): Rule S3 → `next_paths_to_write(paths)` (selected, open,
  never-tried first, best rank first, 6) → none: 409 with `why_no_path_left` → `queue_again` → not matched: 409
  `generation_in_progress`; another run active on the asset: 409 `asset_busy` → `send_job` (a lost send is re-sent
  by the reaper) → publish → audit `run.next_set` → 202 `{epoch}`. The write job then continues by itself.
- **Tests (T-SCN-20..23):** a run failed mid-writing → 202, the batch, then the job writes the rest; twice → 202
  then 409; two at once → one 202; while running → 409; nothing open → each reason; asset busy.

#### S41: #6 regenerate (API + the write job)
- **API** (`POST /v1/sessions/{id}/regenerate/scenarios`, `{scenario_ids}`): Rule S3 → targets (`find_targets`): per
  id `unknown` / `version_not_current` / `failure_scenario` / `duplicate_version` → 409
  `scenarios_not_regenerable` → `queue_again` with `batch [{path_id, replaces: scenario_id}]`, kind `regenerate` →
  send, publish, audit `run.regenerated` → 202 `{epoch}`.
- **Job:** `write_batch` hands a batch with `replaces` to `Regenerator` (new `worker/tasks/regenerating.py`); the
  path's AI work moves from `BatchWriter` to a shared `PathWriter` + `write_at_once` (new `worker/path_writing.py`),
  so both write the same way. `data_access/scenario_versions.py` (new): `find_versions(session_id, path_ids)` (the
  paths' done versions: id, version, statement, superseded_by), `supersede(old, new)`, `note_failure(id, error)`.
  1. Per target: already superseded → done before (a retry); version n+1 already written → only supersede n (a
     crash between the two writes, R-8); else write it with `other_scenarios` = the statements of the path's
     versions (the approved rule 12: "meaningfully different").
  2. Written → saved as version n+1 (`uuid5(run:path:n+1)`, `replaces`, a unique title), then `superseded_by` on n,
     then the path's `served` (fenced, with counts and the note). An accepted n stays accepted; n+1 is pending.
  3. Failed (unreadable, unsupported) → `regenerate_error {code, message, at}` on n, no new version, path attempts
     unchanged. Blocked → kept hidden for audit (n+1, never served) and `regenerate_error scenario_blocked` on n.
  4. An outage → given back, the retry skips what was done; on the job's last try the remaining targets get
     `regenerate_error unavailable` and the run ends `partial`.
  5. End: one controls message when a version was written; `finish` with `complete` or `partial`.
- **Tests (T-SCN-24..27):** n+1 written, n superseded, accepted n stays accepted, the writer saw the siblings; a
  failed regenerate keeps n current with its error; a crash between the writes is healed; a failure card, an old
  version, two versions of one path → 409; two regenerates at once → one 202.

#### S42: #27 promote an accepted AI threat
- **Files:** `data_access/library.py` (`LibraryRepository.propose_threat` → `tsg_ResolveThreat`, Source `ai`),
  `models/library.py` (`ProposedThreat`), `services/scenarios/promotion.py` (new, `LibraryPromotion.promote`).
- **Steps** (`POST /v1/sessions/{id}/scenarios/{scenario_id}/promote-to-library`, no body): the run check (404/403)
  → the scenario in the run (404) → not accepted: 409 `scenario_not_accepted`; a library threat: 409
  `nothing_to_promote` → its plan threat (exact type and threat names, primary category) → in memory, by normalised
  name: curator-rejected → `curator_rejected` (never inserted); live or pending → `existing` → else
  `propose_threat(category, type, threat, "ai", X-User-Id, the scenario's actor ids)` → `inserted` / `existing` →
  `library_promotion {by, by_client, at, results}` set once (first call) → audit `library.promoted` once → 200
  `{scenario_id, results[{threat, threat_type, threat_type_id, threat_catalogue_id, outcome}]}`. SQL Server down →
  503 and nothing written to MongoDB.
- **Tests (T-SCN-28..30, T-LIB-07..09):** promote twice → `inserted` then `existing`, the row `IsActive = 0`, one
  audit; not accepted → 409; library threat → 409; curator-rejected wording → `curator_rejected` with no SQL call;
  another entity → 403.

#### S43: Module review, docs and a dev run, then report
- The owner's module review (logical gaps, IO, no god class/function/file, production-ready), each gap fixed at its
  cause with a test (G137+).
- BLUEPRINT Rules S3-S7 and S13 as built, the §13 API rows, the decision state table (G137); IMPLEMENTATION_GUIDE
  Step 14; HOW_SCENARIOS_ARE_GENERATED Stage H; RUNNING test count.
- Dev run (scratchpad, real stores, no UAT): on a written run of asset 1179, accept 3, reject 1, regenerate 1,
  promote an AI threat if the run has one, next set on an interrupted run; report the answers and timings.

### Phase 7: Step 16, remediation (S44–S56)

The owner chose remediation as the next module on 2026-10-11 ("focus on next module implementation"; the control
cut-off calibration stays open). It follows spec v4.0 §6.1 #11–#17, §7.7, §9 (#28) and BLUEPRINT M11 Rules R1–R10,
M05 L2–L3, §8.3 and §12.2. The owner's module rule applies after every step: cross-check for logical gaps, IO,
no god class/function/file, production-ready; every gap fixed at its cause with a test (G149+).

**Rulings applied (S44, 2026-10-11).**
- **One plan endpoint, two bodies.** #11 takes `{scenario_id, …register}` (a generated, accepted scenario) or
  `{manual_scenario {…}, …register}` (a hand-written one, `Idempotency-Key` required); exactly one of the two. The
  generated path is built first (S52); the hand-written path last (S55), since it needs the library references.
- **The plan prompt is v1's with four gaps fixed** (guide Step 16 said port `treatment_prompt`, v1
  prompts.py:1328-1438; the owner found gaps in it on 2026-10-11 and confirmed four: invented numbers, products and
  vendors; weak "nearest" controls recommended as firmly as exact ones; an interim action with no place in the
  answer; risk levels outside the four-word ladder). `docs/REMEDIATION_PROMPT_DRAFT.md`, **approved by the owner on
  2026-10-11**; the code holds it word for word (a test keeps them equal); `PLAN_PROMPT_VERSION` names it.
- **A broken AI answer is asked again once** (`ask_for_checked_json`, as every v2 AI answer), then the version fails
  `generation_failed`. BLUEPRINT R3 said "no re-ask, as v1": v1 forced the shape with strict structured output,
  v2 checks it in code, and one re-ask is the codebase's single rule for that.
- **The in-request control top-up keeps its 20-second answer without new AI options.** The mapping runs under the
  scenario's own control lease (Rule R1T) and the request waits at most `Remediation.TOP_UP_SECONDS`; past that it
  gives the lease back (the background job maps it) and answers 503 `controls_not_ready` with `Retry-After`. A late
  result is dropped by the lease fence. (BLUEPRINT R1T planned timeout/retry arguments on the AI calls; the fence
  makes them unnecessary.)
- **Decisions are fenced by a counter** (provisional rule 2 of 2026-10-09): every accept or reject filters on
  `decision_seq` and increments it, so two decisions at the same moment can never both apply to a stale read
  (`accepted_version` alone let two rejects of different versions both match).
- **Dates are `YYYY-MM-DD`** (provisional rule 5; spec §6.1 #15-17), computed by code, never by the AI.
- **The six provisional guide rules of 2026-10-09 re-checked: the owner keeps all six** (2026-10-11): rules 2
  (the decision counter) and 5 (`YYYY-MM-DD` dates) are built here; 1, 3 and 4 are already built; 6 waits for
  Step 15.

#### S44: Write the detailed remediation steps first, then the owner re-check
- This section; the tracker rows; the six provisional rules put to the owner with a recommendation.

#### S45: Constants and data shapes
- `core/constants/remediation.py` (new): `Remediation` (`TEXT_MAX_CHARS` 2,000, `MAX_CONTROL_REFS` 50,
  `MAX_ACTION_DAYS` 3,650, `STATEMENT_MAX_CHARS` 4,000, `NAME_MAX_CHARS` 200, `JUSTIFICATION_MAX_CHARS` 1,000,
  `COMMENT_MAX_CHARS` 2,000, `TOP_UP_SECONDS` 20, `TOP_UP_RETRY_AFTER_SECONDS` 30), `RiskLevel`, `YesNo`,
  `ControlCoverage`, `ControlType`, `ActionPriority` (v1's vocabularies), `PlanProgress` (failed, generating,
  awaiting_review, rejected, accepted), `RemediationMessage`, `PlanWarning` (every warning template), `PlanSource`.
  `ConflictReason` + plan_already_exists, not_complete, controls_not_ready, changed_concurrently, type_mismatch;
  `AuditAction` + plan.requested / completed / regenerated / accepted / rejected; `TaskName.WRITE_PLAN`;
  `Collection.REMEDIATIONS`; `Event.REMEDIATION_UPDATED`; `Realtime.REMEDIATION_CHANNEL`; `AiTask.REMEDIATION_PLAN`
  (temperature 0.0).
- `models/remediation_requests.py` (new): `RegisterData` (v1 `TreatmentPlanBody`'s fields: every one optional, `""`
  = not given, ratings as exact decimals ≥ 0 with ≤ 15 digits and ≤ 4 places, dates kept as the calendar date
  written, the window sent together with end ≥ start, ≤ 50 existing controls, unknown fields refused), `ControlRef`,
  `ManualScenario`, `PlanRequest` (exactly one of `scenario_id` / `manual_scenario`), `DecisionRequest`
  (`{version?, comment?}`), `RegenerateRequest` (`{}`).
- `models/remediation.py` (new): `PlanDraft` (+ `DraftControl`, `DraftAction`: the AI answer contract, R5),
  `RemediationStatus`, `RemediationResult`, `RemediationSummary`, `RemediationList`, `PlanRequested`.
- **Tests:** each register rule (blank = absent, decimals exact, a 16th digit refused, window pair, extra field),
  exactly one of the two bodies.

#### S46: Library references (`search/references.py`, M05 L2-L3)
- `resolve_control_refs(refs, controls, strict)`: id, then code (case-insensitive), then exact name; id and code
  naming two rows → 422; strict (a hand-written scenario's controls): unknown or repeated → 422 listing them;
  tolerant (the register's existing controls): unresolved kept as text, repeats collapsed, first kept.
- `resolve_threat_identity(category, type, threat, library)`: id wins, both given must agree; live, then pending, then
  curator-rejected, by normalised name; a known threat under another type → 422 `type_mismatch` naming the library's
  type; the category one the library files the threat under, else the type's, else none. Outcome `active | pending
  | curator_rejected | missing`. In memory: 0 round trips.
- **Tests:** each order and refusal; tolerant vs strict; every identity outcome.

#### S47: The scheduler (`engine/remediation/scheduler.py`, `schedule_checks.py`; port of v1 `treatment_schedule.py`)
- Durations to whole days 1–3,650 (each repair warned); `depends_on` to earlier actions only, by position (forward,
  self, unknown or a repeated id dropped, one warning per distinct reference; a repeated `action_id` belongs to its
  first holder); offsets `start = max(finish of prerequisites)`; the critical path walked back from the last finish;
  inclusive dates from the window's start, clamped past the calendar's end with a warning; no window → null dates
  and one warning. Consistency warnings: ids not A1..An, out of start order, an urgent action waiting on a less
  urgent one, the plan past the window, `action_plan` stating another day count, a recommended control no action
  implements, an action naming a control outside the plan.
- **Tests:** the owner-approved golden example (A1 14, A2 10, A3 21 after A1, A4 5 after A2 and A3 → 40 days, ends
  2026-11-09), every repair, a repeated id, no window, a half window, the calendar clamp.

#### S48: The snapshot (`engine/remediation/snapshot.py`, Rule R4)
- Fixed key order: `asset, asset_context, supporting_systems, threat {category, type, name, actors}, scenario {title,
  statement, risk_statement, supporting_systems_involved, route_status}, existing_controls {library_mapped [...],
  library_mapped_count, register_controls, register_matched_count, applied_to_all_subsystems, justification},
  risk_assessment {ratings, risk_level, division, assessment_window {start, end, total_days (inclusive)}},
  treatment_strategy "Mitigate", register {risk_identification_date, risk_owner, division} (never sent to the AI),
  warnings`. Library details from the in-memory control library; `mapping_relevance` = the rerank score;
  `covered_by_register` = a register reference resolved to the same control.
- Free text through ONE door: redacted, cut at 2,000 characters + " [truncated]". The register's three advisories
  (final ≠ likelihood × impact at final's own scale; no level and no final rating: not risk-calibrated; the window
  already over).
- **Tests:** the key order, a register control covering a mapped one, the advisories, the cut, no id in the AI view.

#### S49: The planner (`engine/remediation/prompts.py`, `planner.py`, Rules R5-R6)
- The prompt (the owner-approved text, docs/REMEDIATION_PROMPT_DRAFT.md), the AI view of the snapshot (`register`
  and `warnings` left out, database keys removed, `control_id` among them).
- `RemediationPlanner.plan(snapshot)`: one `AiTask.REMEDIATION_PLAN` call through `ask_for_checked_json` with the
  `PlanDraft` contract (one re-ask), then `finish`: strategy "Mitigate"; recommended controls outside
  `library_mapped` dropped (one warning each) and the kept ones stamped with library id, canonical code and domain;
  controls the register already covers dropped; no controls table or no action → `invalid_plan`; Critical/High risk
  with no Critical/High item → warning; "covered" with no library control → warning; the register echoes copied in;
  then the scheduler.
- **Tests:** a clean draft, each drop, `invalid_plan`, the urgency warning, an unusable answer → `generation_failed`.

#### S50: Data access (`data_access/remediations.py`, `remediation_versions.py`)
- `RemediationRepository`: indexes (unique `scenario_id`; `{entity_id, X, created_at -1}` for each list filter; the
  reaper's), `insert` (duplicate `scenario_id` → `PlanExists`), `find_status`, `find_by_scenario`, `find_snapshot`
  (one version's snapshot alone), `list_for_entity` (one index scan + one count).
- `RemediationVersions`: `append_version` (R8: one conditional write on epoch + status; the latest status and error
  copied into its version item), `decide` (R9: filter on `decision_seq`).
- **Tests:** a duplicate request, the version append guard, a stale decision refused.

#### S51: The control top-up (Rule R1T)
- `ControlLeases.claim_scenario(scenario_id, task_id)`: one scenario's controls claimed for the API (queued, failed,
  expired, done with no item); a live worker lease → none. `services/remediation/controls_top_up.py`: map under the
  lease with `TOP_UP_SECONDS`; success → the fenced finish; anything else → given back (`queued` for a generated
  scenario, `failed` for a hand-written one) and 503 `controls_not_ready`, `Retry-After` 30.
- **Tests:** mapped in the request; a worker holding the lease → 503 at once; past the deadline → 503 and the late
  result dropped; an empty mapping → 503.

#### S52: First plan for a generated scenario (#11, #15, `tsg_write_plan`)
- `PlanRequestService.request` (R1): the scenario (404 / 403 / 409 `scenario_not_accepted`), one plan per scenario
  (409 `plan_already_exists`), the top-up when needed, the register's controls resolved (tolerant), snapshot
  version 1, one insert, `send_job`, audit `plan.requested` (risk owner masked), publish; 202.
- `worker/tasks/remediation.py` `tsg_write_plan` (R3): leased on `tsg_remediations` (epoch = version), the version's
  snapshot, `draft` + `finish` + schedule, one fenced write (`versions.$[v]`, top-level `status done`, `risk_level`),
  publish, audit `plan.completed`, `tsg_plans_total{outcome}`. `JOB_COLLECTIONS` gains `tsg_remediations` →
  `publish_remediation_status`; its indexes at worker start; the reaper covers it.
- `RemediationQueries.status` (#15, R10).
- **Tests:** request → job → done (fake chat), every refusal, a duplicate request at once, a job failure's code.

#### S53: Reading plans (#16, #17) and live updates (#28)
- #16 result: the shown version (accepted, else the newest done), its plan, schedule and warnings, the scenario
  summary, the register echo; `include_history` adds every version (never a snapshot). #17 list: entity from the
  header, filters (`session_id`, `scenario_id`, `status`, `decision`, `risk_level`), newest first, paged; each filter
  + sort one index scan. #28 `GET /v1/remediation/{id}/events`: the SSE stream of `remediation.updated` (the same
  hub and rules as #8).
- **Tests:** the shown-version rule, history without snapshots, each filter, another entity, the stream's first event.

#### S54: Regenerate (#14) and decisions (#12, #13)
- R8: the scenario still accepted (409), the latest version done or failed (409 `generation_in_progress`), the
  top-up if the scenario has no control, a new snapshot (the register half copied, the rest rebuilt; a warning per
  control no longer mapped), one conditional append; send, audit, publish; 202 `{version}`.
- R9: the default version = the newest done; missing → 404 `version_not_found`; not done → 409 `not_complete`;
  scenario no longer accepted → 409; accept moves `accepted_version` (another accepted version back to pending);
  reject clears it when it was this one; the record's decision derived; one update fenced on `decision_seq`, one
  re-read and retry, then 409 `changed_concurrently`; a repeat changes nothing and audits nothing.
- **Tests:** v1 → v2, accept v1 then v2 (v1 back to pending), reject, two decisions at once, a read-only plan.

#### S55: A plan for a hand-written scenario (#11 `manual_scenario`, Rule R2)
- `Idempotency-Key` required; the key space shared with runs (a generated run's key or another asset's → 409); a
  replay → 200 with the stored ids; asset checks and the frozen context (`tsg_GetAssetContext`); the threat identity
  (S46; a new wording → `propose_threat(source="manual")`, pending; curator-rejected → saved without a library id);
  the acting attacker and up to 3 alternates ranked among the type's linked attackers (none linked → the closest,
  flagged); controls given → resolved strictly, else the top-up; the manual run and its scenario saved under ids
  derived from the key (upserts: a retry lands on the same documents); then R1's steps.
- **Tests:** replay, key conflicts, a new threat proposed pending, a curator-rejected wording, strict control refs,
  no linked attacker, the top-up.

#### S56: Module review, docs and a dev run, then report
- The owner's module review across S45-S55 (an independent reviewer + own cross-check), each gap fixed at its cause
  with a test; BLUEPRINT M11 and §12.2/§13.3 as built; IMPLEMENTATION_GUIDE Step 16; RUNNING.
- Dev run (scratchpad, real stores and AI, no UAT): a plan for an accepted scenario of asset 1179 (with and without a
  window), regenerate, accept v1 then v2; report the plans, timings, AI calls and warnings.

### Later (not in this plan)
- Threat intelligence (ATT&CK and CAPEC first).
- An owner-approved chain-rule catalogue.
- Admin APIs (Step 17).
- Docker, CI and UAT (Steps 19–20).
- Benchmark, calibration and load testing (Step 21).

---

## Part 3: How a scenario is generated, step by step

Marks: ✅ works today · 🔧 changed in Phase 1 (G-number) · 🆕 built in Phases 4–6.

**Example used throughout:**
- **Asset:** "Substation Control Centre": OT, Energy sector, sub-sector Electricity transmission, critical service
  "Substation Control".
- **Systems sent:** SCADA server (ID 1488), RTU (1489), Historian (1490).
- **`TOTAL_SCENARIO_COUNT`:** 0.

**Tools used throughout:**

| Tool or library | Used for |
|---|---|
| FastAPI + Pydantic | The API and request checking |
| pyodbc + SQLAlchemy pool | Calling the SQL Server stored procedures |
| pymongo (MongoDB) | Runs, plans, scenarios, stored vectors, AI-call records, audit |
| Redis + Celery | Job queues, worker leases, the limit on AI calls at once, live updates |
| numpy | The keyword search (BM25) and the meaning search (vector maths), written in our own code |
| LiteLLM | The chat, embedding and reranker models through the proxy |
| sentence-transformers `CrossEncoder` | A local reranker on the laptop only |

### Stage A: Starting a run (API, answers in under a second)

**A1. The request arrives ✅**
- **What happens:** the platform's backend (never a browser) sends:
  ```
  POST /v1/sessions
  X-API-Key, X-User-Id, X-Entity-Id: 135, X-Tenant-Id, Idempotency-Key: abc-1 (optional)
  {"asset_id": 1179, "supporting_system_ids": [1488, 1489, 1490], "service_id": null, "sector_id": null, "subsector_id": null}
  ```
- **Code:** `app/main.py`, `app/api/middleware.py`. Every request gets a **request ID**, which appears in every log
  line. The body is counted as it arrives; over 2 MB it is stopped with 413 before anything else runs.

**A2. Who is calling ✅**
- **Code:** `get_authenticated_principal` (`api/dependencies.py`). All four identity headers are required (401
  otherwise).
- **The key:** it is hashed with SHA-256 and looked up in `tsg_api_clients`. Only hashes are stored. Lookups are
  cached; a revoked key stops working within 60 s.
- **Result:** a `Principal` (entity 135, tenant, user, the calling system's `client_id`).

**A3. Is the body valid ✅🔧G111**
- **Code:** Pydantic `StartRunRequest` (`models/scenarios.py`): IDs are whole numbers, at least one system, no repeats.
  🔧 An unknown field (for example `"asset_idd"`) → 422.
- **Retry key:** `Idempotency-Key` is at most 200 characters.

**A4. Is it a repeat ✅🔧G111**
- **Code:** `RunService._replay` (`services/scenarios/runs.py`). The same key and the same request return the **same
  run** with 200, and no second run is created.
- 🔧 A SHA-256 fingerprint of the request is stored. The same key with a different body (for example other systems)
  → 409 instead of the old run.

**A5. Read the asset's facts ✅**
- **Code:** `AssetContextRepository.read` → stored procedure `tsg_GetAssetContext` through pyodbc (connection pool, 30 s
  limit). The app may only run procedures, never read tables.
- **It returns 6 result sets:**
  1. the asset, only if entity 135 owns it;
  2. **only the 3 systems sent**, if linked to the asset;
  3. services;
  4. sector and sub-sector;
  5. option names;
  6. the entity's technology.

**A6. Check and freeze the facts ✅**
- **Code:** `freeze_context` (`services/scenarios/context.py`).
- **Checks:**
  - asset not owned → 403 `asset_not_owned`;
  - a system not linked → 403 `system_not_linked`;
  - unknown service or sector → 404;
  - sub-sector not under the sector → 422.
- **Decoding:**
  - coded fields become words: `technology_used = "[6, 9]"` → `["WinCC", "Windows Server"]`, and `managed_by = 3` →
    `"Vendor"`;
  - a blank stays **unknown**, never "no";
  - "1900-01-01" as the DR test date = never tested → empty.
- **Labels:** SCADA server = SYS1, RTU = SYS2, Historian = SYS3, in the order sent.
- **Missing facts:** the facts no system records (for example `dr_drill_frequency`), kept for the reviewer.
- **Result:** `FrozenContext` (asset, asset context, critical service, sector, sub-sector, systems, missing facts).

**A7. Save the run ✅**
- **Code:** `new_run_record` + `SessionRepository.insert_run`. One insert into `tsg_sessions`: `status: queued`,
  `step: threats`, `active: true`, all counts 0, the frozen context, and
  `job = {task: tsg_find_threats, epoch: 1, attempts: 0, due_at: now}`.
- **Two unique indexes guard it:**
  - one **active run per entity + asset**: a second start → 409 `active_session_exists`, with the running ID;
  - one **run per entity + retry key**: two identical starts at once → one creates, the other replays.

**A8. Send the job and answer ✅**
- **Code:** `RunService._announce`.
  - `send_job` puts a Celery message on the Redis queue `tsg_threats`. It carries only the task name, run ID and epoch,
    never the data.
  - A metric is counted, and an audit record is saved (`tsg_audit`, 365 days).
- **Answer:** `202 {"session_id": "…", "status": "queued", …}`.
- **Failed send:** the run is already saved, so the **reaper** (every 60 s) re-sends a job still queued after 120 s when
  its queue is empty.
- **Used by:** every later step reads the run record; status #2 and live updates #8 show it.

### Stage B: A worker takes the job

**B1. Receive ✅** A Celery worker (thread pool; one message at a time; acknowledged after finishing) runs task
`find_threats` (`worker/tasks/scenarios.py`) → `run_leased_job` (`worker/jobs.py`).

**B2. Claim (lease) ✅**
- **Code:** `JobLease.claim` (`data_access/job_records.py`): ONE conditional update. It succeeds only if the run is
  queued, the epoch is 1, the task is `tsg_find_threats` and the job is due. It sets `status: running`, the lease end
  (now + 120 s) and attempts + 1.
- **Duplicates:** a duplicate message finds the job taken and does nothing (`Ignore`).
- **Renewal:** a background thread renews the lease every 30 s, for at most 1 hour.
- **Crash:** if the worker dies, the lease runs out and the reaper re-queues the job.
- **Fenced writes:** every later write saves only if this worker still holds the lease, so a stale worker can never
  overwrite newer work (`LeaseLost`).

**B3. Tell watchers ✅** `publish_session_status` sends a Redis pub/sub message; each #8 stream re-reads the status
from MongoDB.

**B4. Load the frozen facts ✅** `plan_run` → `find_context` → `FrozenContext.from_record`. Exactly the A6 facts are
used; SQL is not asked again.

### Stage C: Finding the threats (`ThreatFinder.find_threats`, `engine/scenarios/finding/threat_finder.py`)

**C1. One library snapshot ✅**
- **The library in memory** (`search/library_cache.py`):
  - loaded once per process through `tsg_GetThreatLibrary` and `tsg_GetControlLibrary`;
  - a background thread compares the `tsg_GetLibraryStamp` fingerprints (one per table) every 60 s and reloads on a
    change;
  - during an SQL outage, the last good copy keeps serving.
- **What it holds** (`data_access/library.py`):
  - active threats, each with its type, its STRIDE categories (a threat with no category link borrows its type's; M3)
    and its type's linked attackers;
  - **all active attackers** (`IsCapable` ignored);
  - pending rows and curator-rejected threats.
- **The search snapshot** (`search/service.py`, `search/snapshot.py`): 4 hybrid indexes.
  - **Searchable texts:** threats "Type: Threat" (for example "Malware: Unauthorised firmware update"), controls
    "Name: Description", attackers by name, types by name.
  - **Vectors:** looked up in `tsg_embeddings` by model + corpus + SHA-256 of the text; only new texts go to the
    embedding model, in batches.
  - **Rebuilding:** a changed library builds a new snapshot in the background while the old one serves.
- **Result:** `snapshot = self._search.snapshot()`. One object serves every search of this run, so a library edit
  mid-run can't mix versions.

**C2. No attackers at all? ✅** `PlanRefused(actor_library_empty)`: the job fails, is not retried, and no AI money is
spent.

**C3. The fact sheet ✅**
- **Code:** `describe_asset_for_ai` (`asset_landscape.py`).
- **Budget:** the chat model takes 60,000 characters, so the fact sheet may use **30,000**. The asset part takes at most
  a quarter, with sector, sub-sector, critical service and priority first, so a long description is what gets cut.
- **Cleaning** (`facts_safe_for_prompt` in `shared/prompt_redaction.py`):
  - database keys removed;
  - empty values and placeholders ("N/A", "none", "TBD") dropped;
  - passwords, keys, JWTs, emails and internal host names → `[REDACTED]` (regular expressions).
- **Systems:** each line is `SYS1 "SCADA server": {facts as JSON}`, with the name quoted so it can never act as an
  instruction. The systems share what the asset leaves equally (about 7,000 each for 3).
- **Too long:** facts over a share are cut with "…" and a note.
- **Refusal:** a share under **150** → `plan_refused`.
- **Example:**
  ```text
  ASSET: {"asset":"Substation Control Centre","asset_context":{"sector":"Energy","sub_sector":"Electricity transmission","critical_service":["Substation Control"],"asset_priority":"High",...}}
  SYS1 "SCADA server": {"asset_type":"OT","technology_used":["WinCC","Windows Server"],"vendor_name":"Siemens","managed_by":"Vendor","hosting_location":"On-premises"}
  SYS2 "RTU": {...}
  SYS3 "Historian": {...}
  ```
- **Result:** a `Landscape` (text, SYS1 → 1488, SYS1 → "SCADA server", the sector line).

**C4. The library by category ✅** For each of the 6 STRIDE categories, the library threats filed under it. A category
with no threats is not searched.

**C5. The search questions ✅**
- **Code:** `library_search_queries` (`asset_landscape.py`). Per category, one question per system plus one for the asset.
- **Each question:** category + definition + sector line + that part's **text facts** (no numbers, yes/no fields or
  dates), cut at 1,500 characters. 6 × 4 = **24 questions**. Example (Tampering, SYS1):
  ```
  Tampering. Unauthorised modification of data, configuration or control logic. Energy Electricity
  transmission Substation Control SCADA server OT WinCC Windows Server Siemens Vendor On-premises
  ```

**C6. One search for all 24 questions ✅**
- **Code:** `snapshot.find_threats` → `HybridIndex.search` (`search/indexes.py`).
- **Question vectors:** all 24 go to the embedding model in **one** LiteLLM call. Each comes back as a list of numbers
  (3,072 for text-embedding-3-large), and is cached 14 days in `tsg_query_vectors` (only a hash of the text is stored).
- **Then, for each question, in memory:**
  1. **Keyword score (BM25):**
     - the question is split into words (punctuation removed, lower case);
     - each word found in a threat adds `IDF × count × 2.5 / (count + 1.5 × (0.25 + 0.75 × length ÷ average length))`,
       where `IDF = ln(1 + (N − n + 0.5)/(n + 0.5))`, N = threats and n = threats containing the word;
     - **rare words weigh more:** "firmware" in 12 of 1,800 threats → IDF ≈ 4.97 → it adds about 5.9; "unauthorised"
       in 150 → about 2.9;
     - **short threats are favoured a little:** "Malware: Unauthorised firmware update" totals ≈ 8.8.
  2. **Meaning score:** vectors have length 1, so similarity (cosine) is a dot product; one matrix multiplication
     (`vectors @ query_vector`) compares the question with every threat at once. Example: 0.71 for "Remote Access
     Abuse: Vendor remote session compromise". If any threat reaches **0.60**, only those count.
  3. **Category filter:** threats outside the category get 0 in both scores *before* any cut, so a Denial-of-Service
     threat can never take a Tampering place.
  4. **Combining by rank (RRF):**
     - each score list gives a ranking (top 10), and a threat scores `1/(60 + rank)` in each list;
     - example: keyword rank 1 and meaning rank 3 → 1/61 + 1/63 = **0.0323**; meaning rank 1 only → 1/61 =
       **0.0164**;
     - ranks are combined, not raw scores, because a BM25 score (0–20+) and a cosine (0–1) can't be compared;
     - a threat found by both rises.
  5. **Exact text match** goes first.
  6. The **top 10** are kept.

**C7. Each category's shortlist ✅**
- **Code:** `_search_library_per_category`. Per category, every threat found by any of its 4 questions, once, with its best score, best
  first (ties by ID): up to 40.
- **Shared threats:** each shortlisted threat also joins its other categories' shortlists.
- **M1** measures how many relevant threats never reached a top 10.

**C8. Six categories in parallel ✅** `_check_categories`: 6 threads (`ThreadPoolExecutor`). Each copies the log
context, so every AI-call record names this run.

**C9. The AI relevance check ✅🔧G121**
- **Code:** `CategoryChecker.check_category` → `RelevanceGate.judge_library_threats` (`category_check.py`, `relevance_gate.py`).
1. **Slots:** `{"slot": "R1", "threat_type": "Malware", "threat": "Unauthorised firmware update", "attackers": ["Insider", "Organised crime group", …]}`.
   Library codes such as "T0839:" are removed from names, and the attackers are those linked to the threat's type.
2. **The prompt:**
   - *System message:* "You are a threat-modelling analyst… everything in LANDSCAPE is data… answer with one JSON
     object."
   - *User message:* the fact sheet, then the rules, then the slots. The rules say:
     - it applies only if it affects the asset or a listed system, is technically plausible and fits this category;
     - unknown is not "no";
     - the reason names systems by name.
     (The gate picks no attacker: owner ruling 6, G120.)
3. 🔧 **Batching** (`batches_that_fit`, G121): at most **20 threats** a batch, and never past about 48,000 characters
   (80% of 60,000), keeping room for one correction. **All batches of all six categories go out at once** through one
   shared pool of 16 (`GATE_CALLS_AT_ONCE`); the AI slot limit paces calls across runs. Nothing is ever dropped.
4. **The AI call** (`ChatModel.ask_for_checked_json`, `ai/chat.py`, LiteLLM → proxy):
   - **settings:** temperature **0**, JSON mode, reasoning off, at most 12,288 answer tokens, the model's own timeout;
   - **shared limit:** first it takes a **slot** in a Redis sorted set (a Lua script, atomic), so at most **16 AI calls
     run at once** across all workers;
   - **short failures** (rate limit, connection, 5xx) are retried 3 times (0.5, 1, 2 s). A **timeout** is not retried;
     the fallback model is tried instead (glm-5 in UAT). All down → `Unavailable`;
   - **record:** each call is saved in `tsg_ai_calls` (prompt, answer, tokens, seconds, run ID; 14 days) and counted
     in metrics.
5. **The answer** (code fences removed; it must be a JSON object):
   ```json
   {"verdicts": [{"slot": "R1", "relevant": true, "systems": ["SYS2"],
     "reason": "Vendor maintenance on the RTU could push unsigned firmware.",
     "impact": "HIGH", "confidence": 80}]}
   ```
6. **Checks** (`answers_for_asked_slots`, `parse_verdict`, Pydantic `RelevanceVerdict`):
   - every slot answered once;
   - systems only SYS1–SYS3;
   - `relevant` is true or false;
   - impact HIGH, MEDIUM or LOW when relevant;
   - confidence 0–100;
   - a reason is present.
7. **Problems:** asked **once more in the same conversation**, with the list (up to 20 problems of 200 characters). A
   cut-off answer → the batch is **halved** and each half asked separately.
8. **Result:** a `Verdict` (relevant, system IDs such as SYS2 → 1489, reason ≤ 500 characters, impact HIGH = 3 /
   MEDIUM = 2 / LOW = 1, confidence). Rejections are recorded with their reason; every judged ID is counted.

**C10. Every threat of the category is judged 🔧G121** (owner ruling 8)
- **Code:** `CategoryChecker._check_once`. All threats of the category go through C9 in one go, the shortlisted ones
  first (search order), so the likeliest are in the first batches; `whole_category` is always true.
- **Why:** on asset 1179 the top-10 shortlist missed 224 relevant judgements (measurement M1).
- **Speed:** the whole asset (159 threats) is planned in about 78 s, against about 290 s judging one batch after
  another.

**C11. One AI-proposed threat (gap-fill) ✅🔧G108**
- **When:** only if C10 also found nothing **and** every threat of the category was judged (`judged_ids` = all IDs).
  Otherwise the note "gap-fill not asked".
- **Code:** `GapFiller.propose_ai_threat` (`ai_gap_fill.py`).
1. **The ask:** the fact sheet + category + the library threats judged not to apply ("never propose these again") + the
   rules. Answer: `{"applies": true, "threat_type": "…", "threat": "…", "attacker": "…", "systems": ["SYS2"], "reason": "…"}`,
   or `{"applies": false, "reason": "…"}`.
2. **Checks:** required fields, real labels, at most 3,500 characters. One re-ask; the whole ask at most twice.
   Failing → the category gap is "not assessed".
3. **Already in the library?** (`LibraryMatcher.closest_threat`) A hybrid search gives the 10 closest library threats
   in this category. The **reranker** (a cross-encoder through LiteLLM; `CrossEncoder` on the laptop) reads the
   proposal and each candidate together and scores 0–100. **75 or more** → redundant, dropped.
4. 🔧 **Rejected before?** Its normalised name equals a pending or curator-rejected name → dropped.
5. **Does it apply?** It goes through C9 as slot R1; rejected → dropped, with the reason.
6. **Type:** `closest_type` searches the type names used in this category, plus the reranker. 75 or more → the
   library's type. 🔧 Below → a **note for the curator**, not a threat.
7. 🔧 **No attacker is picked here.** The "lowest-ID attacker" fallback is deleted, and the AI's attacker text is never
   used.
8. **Result:** an AI threat with key `ai:<normalised name>`, marked `ai_generated`.

**C12. When a category fails ✅**
- **Unreadable answers:** the category is tried once more from the start. If it fails again, it is **not assessed**
  (the shortlist is recorded as "not judged", and no gap-fill runs).
- **AI service down** (`Unavailable`): the whole job is given back and retried after 15, 30, 60, then 120 s, up to 5
  attempts.

### Stage D: Cleaning the threat list (`_merge_and_assign_attackers`, 🔧G110 new order)

**D1. One list** Every accepted library threat and AI threat becomes a `PlannedThreat` (key, IDs, type, name,
categories, systems, impact, confidence, reason). 🔧 No attackers yet.

**D2. Same threat twice, or same name ✅🔧G109**
- **Code:** `merge_same_threats` (`duplicate_merge.py`).
  - **Same key** (for example `lib:297`, found under Tampering and Elevation of Privilege): ONE threat, with categories
    and systems combined and the higher impact and confidence kept.
  - **Same name:** an AI threat whose normalised name equals a library threat's folds into it. 🔧 Only with the **same
    type**; otherwise both are kept, with a note.

**D3. Reworded AI threats ✅🔧G109**
- **Code:** `merge_reworded_threats`. All names are embedded in **one call**, with the asset name removed so "… of Substation
  Control Centre" doesn't make names alike.
- An AI threat at cosine **≥ 0.98** to an earlier kept threat (🔧 of the same type) is a rewording, so it is folded.

**D4. Same attack, different words ✅🔧G109**
- **Code:** `SameAttackCheck.merge_same_attacks` (`same_attack_check.py`).
1. **Who is asked:** only threats sharing a system (the asset counts as one), slotted THR1… and grouped so neighbours
   share a batch.
2. **The AI:** "same action, same systems, same effect? A threat that leads to another is different; if in doubt, keep
   separate." Answer: `{"same": [{"threats": ["THR2", "THR5"], "reason": "…"}]}`.
3. **Code checks:** at least 2 known slots, no slot reused, a reason, they share a system, 🔧 the same type.
4. **Which one is kept** (`pick_surviving_threat`): library over AI, then the lowest library ID. 🔧 The attacker no longer counts.
5. **Check fails:** nothing is folded; a note.
- **Example:** "Backup and recovery compromise" + "Backup destruction or recovery sabotage" on the Historian: vectors
  give only 0.717, but the AI says same attack, so one is kept.

**D5. Pick the attackers 🔧G110 🔧G120 🔧G122**
- **Code:** `AttackerAssigner.assign_attackers` (`attacker_assignment.py`), now after D2–D4.
1. **Search text:** one per threat, `"Remote Access Abuse: Vendor remote session compromise. <reason> Energy Electricity transmission Substation Control"`,
   all embedded in **one call**.
2. **Candidates:** only the attackers **linked to the threat's type**, ranked by hybrid search (keyword + meaning by
   rank; no floor; every candidate considered).
3. 🔧 **Acting:** the top-ranked (owner ruling 6, G120).
4. **Backups:** the next **3**. A linked attacker the search couldn't score is added at the end, never dropped.
5. 🔧 **Type with no linked attacker** (owner ruling 10, G122):
   - The meaning-based search ranks only the attackers the library links to some type (today the 9 generic attacker
     types, never one of the 40 named groups).
   - The nearest 3 become options, and the first acts.
   - The threat is flagged **closest**, and D6 lets the AI choose among the 3.
6. **Embeddings down:** library order, marked not ranked; if a threat has no linked attacker, the job retries instead.

**D6. Check "closest" attackers ✅** `AttackerFitCheck.check_attackers`: the AI picks the ONE listed option that could most
plausibly do it, or null; code accepts only names from that threat's list. Outcomes: `fits` / `chosen` / `none_fits` /
`not_checked`, each noted.

**D7. Labels back to names ✅** `replace_codes_with_names`: every "SYS2" in reasons and notes becomes "RTU".

**D8. Result ✅** `ThreatFindings`: the final threats; each category's record (shortlisted, judged, whole category,
relevant count, gap-fill outcome, rejections with reasons); every merge with its reason; all notes; the fact sheet; the
library fingerprint.

### Stage E: The plan (`AttackPathSelector.build_plan`, `paths.py`)

**E1. One threat = one path 🔧G114** Each threat is one path; the AI no longer joins threats (`grouping.py` deleted).
The path ID is the first 16 characters of SHA-256 of the threat key (`lib:297` → `a3f9…`), so the same threat always
gets the same ID. Categories, systems, impact and confidence come from the threat.

**E2. Rank ✅**
- **Code:** `rank_paths` (`path_ranking.py`), a pure function: the same paths always give the same order.
- **Pass 1 (category coverage):** in STRIDE order, for each uncovered category, the strongest path in it (main
  category, then higher impact, then higher confidence).
- **Pass 2 (system coverage, greedy):** repeatedly, the path adding the most systems not yet covered, until none adds
  anything.
- **Pass 3:** the rest, by impact, then confidence.
- **Ties:** library before AI, lowest library ID, then path ID.
- Each path is labelled `category_coverage`, `path_coverage` or `risk_significance`.

**E3. Count 🔧G106** `select_up_to_target` with `TOTAL_SCENARIO_COUNT` (validated at start-up as a whole number ≥ 0):
- 0 → all selected;
- 12 → the top 12 selected, the rest kept with `unselected_reason: target_reached`;
- never padded.

**E4. The plan ✅**
- **Contents:**
  - prompt version;
  - every threat;
  - every path (`path_id`, rank, choice, `served: null`, `attempts: 0`, `abandoned: false`, `steps: [key]`, category,
    categories, systems, impact, confidence, selected);
  - target;
  - notes;
  - `not_assessed`, `no_valid_threat`;
  - category records;
  - merges.
- **Added by the worker:** `frozen_at` and `made_with` (chat models, embedding model, reranker, library fingerprint).

**E5. Save and hand over, in one fenced write ✅🔧G113**
- **Code:** `plan_run` → `hand_over` (`JobLease.queue_next`). One update, accepted only if this worker still owns the
  job, saves:
  - the plan;
  - `plan_note` ("planned 42, written 0, remaining 42");
  - `step: scenarios`;
  - counts and timings;
  - the next job: `task: tsg_write_scenarios`, `status: queued`, the **first 6 path IDs** in `job.batch`.

  Then a message goes on the `tsg_scenarios` queue and watchers are told.
- **No path:** done in the same write; 🔧 outcome `partial` if a category was not assessed, else `complete`.

### Stage F: Writing the scenarios 🆕 Phase 4 (prompts approved in S14)

**F1. The writer job starts:** task `tsg_write_scenarios` (`worker/tasks/writing.py`) claims the job like B2 (same run,
same epoch, task must match) and reads the frozen facts, the plan and the batch.

**F2. Six at a time:** the 6 paths are written in **parallel threads**, under the same 16-call AI limit.

**F3. The brief (code, no AI):** `brief_builder.py`.
- the asset (name, type, description, critical service, sector, priority; recorded facts only, cleaned as C3);
- category;
- threat and type (no library codes);
- **why it applies** (the C9 reason);
- the threat's systems by **name**, with facts;
- the acting attacker;
- `entry_point_options` (the threat's systems, or empty when it acts on the asset itself);
- `other_scenarios` (only when regenerating).

**F4. The writer AI:** `ScenarioWriter` (`scenario_writer.py`) → `ask_for_checked_json`, with the approved system prompt. Its
rules include:
- one attack, one main impact;
- use only the brief; unknown facts go into assumptions;
- name only the brief's systems; never claim two systems are connected;
- **"could / may", never a confirmed attack**;
- the attacker as a **type of attacker** (for example "an organised criminal group"), never a real named group;
- the risk statement leads with the consequence, never "Because";
- no names or framework codes in the title;
- no exploit steps;
- plain English.

The answer is `{scenario_title, scenario_statement, risk_statement, assumptions, entry_point}`. Code checks the fields
are present and not empty, and the entry point is one of the options; one re-ask; still wrong → a failure card (F10).

**F5. Clean (code):** `draft_cleanup.py`, with regular expressions:
- framework codes (`T1542`, `CAPEC-123`) and names out of the title;
- "Because X, Y." → "Y, because X.";
- codes and hashes out of the text.

**F6. Code checks:** `exact_rules.py`. Each failure is a **finding** with a severity:
- **blocker**, exact faults only (an ID not in this run, another entity's data, an advisory number never supplied): the
  draft is saved hidden, and is never counted or served;
- **warning** (the asset or attacker type not named; another library attacker named; a system outside the brief
  named): shown on the scenario.

**F7. AI meaning check:** `ai_plan_check.py`, at temperature 0. "Same threat? same attacker? no extra system? no
system-to-system link? impact fits the category? risk follows from it? nothing invented?" →
`{consistent, problems}`. Its words are **notes**.

**F8. One rewrite at most:** if F6 or F7 found anything, ONE rewrite in the same conversation listing every problem,
then F5–F7 again. The draft with **fewer problems** is kept (the rewrite on a tie). At most 4 AI calls per scenario,
plus re-asks.

**F9. Save it at once (fenced):** `data_access/scenarios.py`.
- **ID:** fixed (SHA-256 of run + path + version), so a twice-delivered message saves once.
- **Unique titles:** enforced by a database index; a clash gets the threat name as a qualifier (for example "Loss of
  control integrity (firmware update)").
- **Contents:** run, entity, path ID, version, `current: true`, title, scenario, risk, assumptions, entry point,
  `route` (`standalone`, or `unknown` when it relies on an unrecorded link), threat/type/attacker references, findings,
  notes, decision `pending`, controls `queued`.
- **Then:**
  - the run's path is marked served (fenced);
  - counts are recalculated by one aggregation (never +1 counters);
  - the counts and plan note are saved;
  - watchers are told.
- **Example:**
  - **Title:** "Loss of control integrity"
  - **Scenario:** "An organised criminal group could use a vendor maintenance session to push unauthorised firmware to
    the RTU. The RTU may accept it as genuine, and its breaker and setpoint commands could no longer be trusted."
  - **Risk:** "Loss of trusted control logic in the RTU could force manual operation and interrupt the Substation
    Control service."
  - **Assumptions:** "Assumes vendor sessions can update RTU firmware; not recorded in the platform."
  - **Entry point:** RTU.

**F10. Failures:**
- **AI down:** the job is given back and retried after 15, 30, 60, then 120 s; paths already saved are skipped.
- **Unreadable twice:** a visible **failure card**, and the path's attempts + 1.
- **5 attempts:** the path is **abandoned** and never served again.

**F11. Continue and finish the set:** after each batch, the task takes the **next 6** unwritten paths of the set a
person asked for (the first set, INITIAL_SET_SIZE, or a next set, NEXT_SET_SIZE: owner 2026-10-11, G196) and hands over
to itself in one fenced write. When none of the set is left: `status: done`, `active: false` (the asset is free for a
new run); the rest waits for a next-set call. The outcome is `complete` when every path of the set was written,
`partial` if one of them failed or was abandoned, or a category was not assessed.

### Stage G: Controls 🆕 Phase 5

1. **Start:** each saved scenario queues its own `tsg_map_controls` job on `tsg_scenarios`, so review never waits for
   controls.
2. **Search text:** title + scenario + **risk statement** + threat type and name + attacker + asset name and type +
   system names, cut at 4,000 characters.
3. **Allowed pool:** controls whose `AssetType` fits the asset. An OT asset gets OT, IT-OT and OT-IT; an IT asset gets
   IT, IT-OT and OT-IT. It is a filter on the control search, applied before the top-k (like categories in C6).
4. **Search:** the same hybrid search → **40** candidates ("ControlName: Description").
5. **Reranker:** the 40 (query, control) pairs are scored 0–100. Code checks one score per candidate, each a valid
   number; raw and 0–100 scores are both stored.
6. **Choose:** keep **every** control scoring **60 or more** (the model profile's cutoff); if none passes, keep the
   single best as `nearest`, with a warning.
7. **Clean-up:** de-duplicate (same ID, then the same text in an IT and an OT twin, keeping the higher score), rank
   1, 2, 3…, save under the scenario; `controls_waiting` in the counts.
8. **Failures:**
   - retried with back-off, plus a sweep every 30 minutes;
   - an empty library → `control_library_empty`;
   - no compatible control → `no_compatible_control`.

**Example:** "Firmware integrity verification" (87), "Vendor remote-access approval" (74), "Change control for RTU
logic" (66).

### Stage H: Using the results

| What | API | What it does |
|---|---|---|
| Progress | #2 `GET /v1/sessions/{id}` | One indexed read: status, step, counts, plan note, last action ✅ |
| Live progress | #8 `GET /v1/sessions/{id}/events` | The current status first, then an update after every save (Redis pub/sub; the status is re-read from MongoDB) ✅ |
| A run's scenarios | #3 `GET …/results` | `tsg_scenarios` filtered by run and entity, paged ✅ |
| One scenario | #10 | The scenario with its controls ✅ |
| The entity's scenarios | #9 | Paged, entity-filtered ✅ |
| Accept / reject | #4 / #5 | 🆕 Phase 6: one conditional update, audited, live update |
| Regenerate | #6 | 🆕 Phase 6: a new version for the same path (back to Stage F); the old one is kept |
| Resume interrupted work | #7 | 🆕 Phase 6: only selected paths left pending |
| Send an accepted AI threat to the library | #27 | 🆕 Phase 6: written as **pending** through `tsg_ResolveThreat`; a curator approves it |

**One line:** frozen facts → fact sheet → 24 searches (keyword + meaning, combined by rank) → AI judges in batches (and
picks the attacker) → whole category if empty → one careful AI proposal → duplicates removed → attackers ranked → one
threat per path, ranked and counted → written 6 at a time with checks → controls by search + reranker → review.

---

## Part 4: Glossary

| Term | Meaning |
|---|---|
| Run / session | One request to generate scenarios for one asset (a `tsg_sessions` document) |
| Frozen context | The asset and system facts saved at the start; never re-read during the run |
| Fact sheet / landscape | The text block the AI reads: the asset plus each system's facts |
| SYS1, SYS2 | Short labels the AI uses for systems; code turns them back into IDs and names |
| STRIDE | The 6 threat categories: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege |
| BM25 | Keyword scoring: rare words count more, short texts are favoured a little |
| Embedding / vector | A list of numbers representing meaning; similar meaning → similar numbers |
| Cosine | Similarity of two vectors, 0–1 (1 = the same meaning) |
| RRF | Reciprocal Rank Fusion: combines two rankings by adding 1/(60 + rank) |
| Reranker | A model that reads a query and a candidate together and scores the match 0–100 |
| Relevance gate | The AI check "does this threat apply to this asset?" |
| Gap-fill | One AI-proposed threat, only when the whole library category had nothing relevant |
| Lease | A worker's time-limited claim on a job (120 s, renewed every 30 s) |
| Epoch | The run's job generation number; old messages with an older epoch are ignored |
| Fenced write | A save that succeeds only if this worker still owns the job |
| Reaper | A task every 60 s that re-queues lost jobs and re-sends unsent ones |
| AI slot | One of at most 16 AI calls allowed at once across all workers (Redis) |
| Blocker / warning / note | Finding severities: a blocker hides the scenario; a warning is shown; a note is information |
| Partial | The run finished, but some work could not be done (a category not assessed, a path failed or abandoned) |

---

## Appendix: Gap analysis, spec v4.0 vs the codebase (2026-10-10)

Legend: ✅ matches · ⚠️ partial · ❌ missing · ⛔ conflicts with a recorded owner decision or with the spec itself.

### A. Conflicts with the owner's recorded decisions (each ruled in Part 1)
| # | Topic | Spec says | Recorded decision / code | Ruling |
|---|---|---|---|---|
| C1 | Alternate attackers | Name cosine ≥ 0.80 **and** calibrated fit (§7.2.5, §8.1 step 6) | Next 3 linked actors (`attackers.py:109-116`); 0 of 34 pairs reached 0.80 | Owner's rule |
| C2 | Attacker from another type | Forbidden without an approved association (§7.2.2 step 8.4) | Linked, else closest (`attackers.py:96-103`) | Owner's rule; M4 measures it |
| C3 | Tenant filter | Entity **and** tenant on every query (§4.4, §5.1, §13) | Entity only | Owner's rule |
| C4 | Writer requirements/outputs | Required (§7.4.2) | Removed | Owner's rule |
| C5 | Blocking findings | blocker/warning/note; quarantine (§7.4.7) | Nothing blocks | Spec, for exact code faults only |
| C6 | Multi-step paths | Only source-validated or approved rules (§1, §7.3.1) | LLM grouping | One threat = one path (S9) |
| C7 | When threat intelligence is built | Before Steps 10–13 (§7.2.6) | Guide Step 15 | After Steps 12–14 |
| C8 | Systems analysed | All linked (Build Steps 2.3, 5.1) | Only the systems sent | Only the systems sent |
| C9 | Naming the attacker | A named group only with evidence (§1, §7.2.1) | Draft: name it | Spec: a type of attacker only |
| C10 | Monitoring pages | Private or formally risk-accepted (§13) | Public | Owner's rule; risk acceptance at go-live |
| C11 | AI timeout | 4 attempts (§1, §11) | Not retried in the call | Owner's rule |
| C12 | Worker → services | Allowed (§2.2) | Guard forbids it | Owner's rule |

### B. Places where the spec contradicts itself (ruled in Part 1)
1. **Run states:** §8.2.3 vs §10.2 → §10.2.
2. **Collections:** §4.2 vs §8.2.2 (`tsg_runs`, `tsg_run_locks`, `tsg_paths`, `tsg_outbox`…) → §4.2.
3. **Systems:** §6.1 (a caller list) vs Build Steps 2.3/5.1 (all linked) → the caller's list.
4. **Alternates:** §7.2.2 step 8.3 vs §7.2.5/§8.1 → the owner's rule.
5. **Type corpus:** §8.1 step 6.2 (none) vs §7.2.2 step 6.2 (type match at 75) → it stays.
6. **Writer fields:** §7.4.2 vs Build Step 25 → none.
7. **File layout:** §2.2 vs §8.2–8.6 → §2.2.
8. **Other documents:** §0 (standalone) vs §8.2/§8.8 references to other documents → ignored.

### C. Gaps found, and the step that closes each
| Area | Gap | Closed by |
|---|---|---|
| Config | `TOTAL_SCENARIO_COUNT` is a code constant | S1 |
| Gap-fill | Untyped proposals become threats; lowest-ID attacker; rejected wording not checked | S2 |
| Dedupe | Different types can merge | S3 |
| Actors | Chosen before dedupe; survivor chosen by attacker | S4 |
| Actors | Acting attacker picked by name similarity only | S5 |
| API | Unknown fields ignored; same key + different body replays | S6 |
| AI | No finite check on embeddings; no range check on rerank scores | S7 |
| Run status | "Done" hides not-assessed categories | S8, S26 |
| Paths | The AI guesses chains | S9 |
| Text | Stale comments; unused constant | S10 |
| Search depth | Misses outside the top 10 unmeasured | S12 (M1) |
| Library data | A threat with no category borrows its type's | S12 (M3) |
| Writer, controls, review | Not built | Phases 4–6 |
| Threat intel, calibration, remediation, admin APIs, Docker/CI/UAT, benchmark | Not built | Later |
| Already matching ✅ | Layer guards; 8 SQL procedures with execute-only grants; Mongo indexes and TTLs; identity headers; 403/404; problem body; 413; 503 with Retry-After; frozen context; one library snapshot per run; "Type: Threat" search text; 6 categories; BM25 + vector + RRF; category filter before the top-k; relevance gate with re-ask and batch halving; whole-category scan before gap-fill; deterministic ranking; never padded; zero paths → done; plan frozen with model and library stamps; leases, reaper, 15/30/60/120 s retries; SSE #8; 20 alerts | — |

### D. Deferred (YAGNI until its data exists)
- **Threat intelligence:** OTX is legally blocked for commercial use, and KEV/NVD/EPSS need product versions the asset
  data lacks. Start with ATT&CK and CAPEC when it is needed.
- **Transition graph:** empty without approved rules, so one-step paths. Chains return through an owner-approved rule
  catalogue.
- **Calibration** (actor fit, reranker) needs a labelled test set (Step 21). Raw rerank scores are stored from Phase 5.
- **Adaptive paging:** only if M1 shows misses.
- **Outbox, run locks, two state machines:** the reaper is the spec's own allowed alternative.

### E. Which is better, part by part
| # | Part | Better | Why |
|---|---|---|---|
| 1 | Systems analysed | Current (ruling) | The platform decides the scope; shorter prompts |
| 2 | Unknown facts | Current, for now | No CMDB/topology source exists |
| 3 | Threat search text | Equal | Both "Type: Threat" |
| 4 | Library data checks | Spec | Bad data becomes visible (M3 first) |
| 5 | Relevance gate | Equal | Same design; current adds batch halving and a re-ask |
| 6 | Search depth | Current, for now | Paging costs AI calls; measure first (M1) |
| 7 | Gap-fill | Spec | No untyped threats or random attackers (S2) |
| 8 | Threat intel | Spec in principle | Not buildable with today's data or legal status |
| 9 | Duplicate removal | Spec | No cross-type merges; attackers after (S3, S4) |
| 10 | Attacker choice | Mixed | No false attribution (S14); gate pick (S5); keep the ranking; ignore `IsCapable` |
| 11 | Multi-step attacks | Spec (ruling) | No guessed chains; fewer AI calls (S9) |
| 12 | Ranking and count | Spec for the count; current for ranking | Configurable count (S1); evidence tiers need intel |
| 13 | Scenario writer | Combine | The short brief plus could/may and no false attribution |
| 14 | Controls | Spec | Build as written (Phase 5) |
| 15 | Job handling | Current | Leases and the reaper recover faster; the spec allows it |
| 16 | Honesty fields | Spec | `partial`, not a hidden gap (S8, S26) |

### F. Which workflow is best today: the hybrid this plan builds
| Measure | Spec, full | Current (before) | Hybrid (this plan) |
|---|---|---|---|
| Truthful claims | High | Medium | High for the data available |
| Coverage | Highest, once intel exists | The caller's systems | The caller's systems (ruling) |
| AI calls per run | Most | Medium | Fewest |
| Same input → same plan | High | Lower | High |
| Buildable now | No | Yes | Yes |
| Time to scenarios | Months | Weeks | Weeks |
