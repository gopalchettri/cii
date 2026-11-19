# Status

| Phase | State |
|---|---|
| Discovery | Complete (16 Nov 2026): three read-only explorers; findings in `specs/2026-11-16-simplify-codebase-design.md` |
| 0 Brainstorming | Complete: owner chose order (outside app, then app code, then runtime), inner workings may change, API frozen, notes in `.10x/` |
| 1 Strategy | Complete |
| 2 Design | ADR-001, ADR-002 Accepted; ADR-003 Proposed; ADR-004 FastAPI layout, ADR-005 ATT&CK only, ADR-006 ack at start: Accepted; spec 2026-11-16-under-20k-design.md |
| 3 Planning | Complete: tasks below |
| 4 Implementation | In progress |
| 5 Verification | Pending |
| 6 Delivery | Pending |

## Tasks
- [x] A1 remove clean stale worktrees (local); 34 kept for the owner (18 with changes, 16 unmerged)
- [x] A2 delete finished scripts, root clutter (not yet test-run: owner said do not run the code)
- [x] A3 configmap from files (ADR-001): kustomize render byte-identical, test_deploy 35 passed
- [x] A4 tests that pin doc wording (rules.test.yml exp_annotations kept: promtool needs them)
- [x] A5 outdated docs (flow doc 4,367 -> 548, handbook 1,003 -> 515, guide 1,399 -> 1,045, runbook and old SDD deleted)
- [x] Wave 1 (16 Nov 19:14-20:05): six areas rewritten in parallel worktrees, merged: 34,572 -> 29,818; suite green except the old layer rules
- [x] Wave 2 (20:35-21:10): small cuts and merge fixes (about -400)
- [x] Wave 3 (16 Nov): seven features in parallel worktrees (library, admin, jobs, AI, mapper, intel, remediation, scenarios), merged; container rebuilt; 29,454 -> 28,931
- [x] Style pass: 120-column lines, no magic trailing commas, no docstrings on private helpers: 28,931 -> 27,314; OpenAPI byte-identical
- [x] Merge review of wave 3 (8 reviewers, 2 skeptics per finding): 3 confirmed, fixed
- [x] Wave 4 (16-17 Nov, 7 lanes): skipped A/B cuts; 27,314 -> 26,236; per-lane review + fixes; merge review: nothing confirmed
- [x] Import cycles removed (every app module imports on its own); docs synced to the FastAPI layout
- [x] Full suite 17 Nov 00:35: 2,675 passed, 4 skipped, 0 failed (six sorted shards); OpenAPI byte-identical; mypy, ruff clean
- [x] Old layers gone (17 Nov 01:00): services/ -> domain/scenario/runs.py and domain/intel/admin.py; data_access/ -> crud/audit.py, crud/embeddings.py, crud/library.py; models/ -> schemas/library.py, schemas/curation.py, schemas/scenario_internal.py, schemas/intel_records.py; 10 unused names deleted; suite 2,674 passed; OpenAPI identical
- [x] container.py out (17 Nov): getters next to their classes; suite 2,676 passed on 6 parallel workers (pytest-xdist)
- [x] scenario-simple (ADR-007): waves 0-3 done 17 Nov; suite 2,957 passed (8 failures from the parallel create-session work or known); tracked app/ 26,188 -> 25,587 lines on disk, which also holds the other session's edits to tracked files
- [ ] scenario-simple: live end-to-end run (intel on and off); enums.json re-pin by the create-session session
- [ ] 48 dead enum members pinned in tests/contract/enums.json (mostly the removed KEV/EPSS/NVD/ICS sources): owner's OK to re-pin
- [ ] Under 20,000: cross-area cuts (container, crud classes, enums, scenario worker, intel dataclasses, pacer) about -2,800; C cuts only on the owner's yes
- [ ] Feature steps 1-11 (spec 2026-11-16-under-20k-design.md): library, admin, jobs, AI usage, mapper, intel, remediation, scenarios, platform close-out, style pass, approved C cuts
- [ ] D ADR-003 proposal, QA and security reviews, PR

## create-session-attack (ADR-008, ADR-009, spec 2026-11-17-create-session-attack-design.md)
Phases 0-3 complete (owner approved the plan 17 Nov 2026); 4 Implementation built, reviewed and fixed; 5 Verification in progress (the live create-session run and the lead's final suite run are open). Nothing is committed.
- [x] Foundation (17 Nov): constants (`core/constants/attack.py` and additions), `CII_ANSWER_TOKENS_LINK_CONTROLS` / `_PICK_CONTROLS`, request and response shapes, `crud/attack.py` (tsg_attack, tsg_control_links), prompts `[scenario.attack]` `[controls.links]` `[controls.picks]`, `app/tsg_prompt.txt` deleted, removed-feed enum members deleted (4 `IntelKind`, 3 `EvidenceFact`, 2 `EvidenceDecision`, 1 `EvidenceReason`); 43 new tests pass (`tests/test_attack_repository.py`, `tests/test_create_session_foundation.py`)
- [x] Ingestion: ATT&CK graph in the import (format 9), revoke hook (built; the lead reports round 1 reviewed and fixed)
- [x] Linking: `tsg_link_mitigations`, three control-links routes (built; the lead reports round 1 reviewed and fixed)
- [x] Schedule: routes, `find_next_run`, `claim_due_run`, 60-second beat check (built; the lead reports round 1 reviewed and fixed)
- [x] Admin UI at `/ui/` (built; the lead reports round 1 reviewed and fixed; 9 pages)
- [x] Start route, write branch (`AttackBatchWriter`), controls branch (built 17 Nov; round 2 reviewed by 4 reviewers and fixed: 26 run findings, 23 with a test, and 5 controls findings)
- [x] One test per existing API on a new session (`tests/test_create_session_flow.py`); Swagger text; AI usage dashboard rows
- [x] Docs (17 Nov): README, `readme_to_run_uat.txt`, `docs/API_CONSUMER_GUIDE.md` (3.1b, 7.4, 7.5, known limits), `docs/TSG_END_TO_END_FLOW.md` (3.1), `docs/SOLUTION_DESIGN.md` (F16, F17, D82), `docs/API_DEVELOPER_HANDBOOK.md`, `deploy/DEPLOYMENT_GUIDE.md`, `deploy/configmap.yaml` (the two answer-token settings); role notes for sde, qa, security, devops, sre, dba
- [x] Security review (17 Nov): 5 findings. 4 fixed, each with a regression test proven to fail without the fix: a linking run deleted stored links (the deletion is gone); `[scenario.attack]` had no "this is data" line; the AI's prose was saved unchecked (now cleaned and safety-checked as the library writer's); the graph had no cut-short guard. The fifth is the owner's decision (handoff.md, 7)
- [x] Verify round (17 Nov): 17 verified findings in the run and controls code; 12 fixed with a regression test each (both majors: an ATT&CK ID confirmed with another entry's name; a plan job mapping an attack scenario by the search), 5 left for the owner (handoff.md, 1-6)
- [x] Ingestion fixes (17 Nov): the first import starts at beat's first check (was the second); dead download code removed; the Swagger text of group 4 names the schedule, the control links and `/ui/`
- [x] Mutation checks: round 1 (ingestion, links, schedule, UI) 162 mutants in its final pass, 6 survived (23 over both passes, 20 tests added); round 2 (start, writer, controls) 116 mutants, 10 survived, 10 tests added; every survivor is killed by its test now. No survivor showed a wrong rule
- [x] Suite triage (17 Nov 10:35-10:48, before the verify round's fixes): whole suite 3,017 passed forward and 3,018 reversed; the only failures were the 7 pin tests, `.env.uat`'s `CII_NVD_API_KEY` line and, forward, one lint failure of a file being edited at that minute; two test-order leaks fixed at the root. The whole suite was not run again since
- [x] Live on the laptop (the live lane's report, 17 Nov): the import (both sources, ATT&CK release 20.1: 23,269 documents in `tsg_attack`, recounted against MITRE's files), the schedule (one import per due slot, none while disabled) and the linking (93 mitigations judged in 93 chat calls and 93 rerank calls, 8.9 min; a second run: no AI call)
- [x] Docs and SDD re-checked against the final code (17 Nov 11:50): SDD 5.4 (one sentence), the consumer guide, the flow doc, D82, the run guide, the deployment guide, these notes
- [x] Group 4 withdraw and approve routes removed (owner, 17 Nov; D83 in `docs/SOLUTION_DESIGN.md`; in the tree: `app/api/routes/intel.py` holds the ten routes): `POST /v1/tsg/intel/sources/{source}/revoke` and `.../approve` go, with the ingestion task's revoke hook, the per-source `approved` flag and the UI's Withdraw and Approve buttons; ten group 4 routes stay (59 operations, 61 before). Docs, the SDD (3.4, two sentences) and these notes are written for the state after it; the code change is made in a copy and applied by the lead: not verified by the docs lane
- [ ] Pins: `tests/contract/*.json` were written at 11:18-11:34 on 17 Nov, after the last fixer finished (`enums.json` holds `NO_FURTHER_RISK`, `NOT_OFFERED`, `NOT_PREPARED`); the pin tests and the whole suite were not run after that by the docs lane: not verified
- [x] Live end-to-end run (17 Nov, the live lane's report): 10 `POST /v1/create_session` runs (IT, OT, mixed; counts 15, 7 and 0) and 1 `/v1/sessions` run; all 91 stored cards checked against `tsg_attack` and the library; every review API answered; `scripts/e2e_all_api.py` 61 of 61 operations, 0 failures
- [x] After the live run (17 Nov; ADR-009, D84, D85): names settled by code, re-ask only for a scenario that would be lost, risks listed in every writing call until the count, a campaign's use counts as documented, the removed feeds' data deleted at import, the echo check flags only text said to an AI, a runaway cut-off answer asked again at the same room. Owner decisions recorded in `decisions/product-manager/create-session-attack.md`
- [x] Live run on the code of D84 and D85 (17-18 Nov): IT 15 of 15 and OT 15 of 15 scenarios, 0 content problems, 59 of 59 operations; whole suite 3,237 passed in both orders (1 known failure: `.env.uat`'s `CII_NVD_API_KEY` line)
- [x] 18 Nov: the answer reader takes a name written as text ("T0836: Modify Parameter"); a stronger English-only line in `[scenario.attack]`; scenario writing at temperature 0.6 (D86: stray Chinese words 0 in 192 answers, measured against today's setting at the same time)
- [ ] Owner decisions: the points still open in handoff.md

## mitre-pipeline (ADR-010, plan `understand-the-e2e-runner-py-and-lucky-flurry.md`)
Phases 0-3 complete (owner approved the plan 19 Nov 2026); 4 Implementation in progress on branch `mitre-scenario-pipeline`. Nothing is committed.
- [x] 0 ADR-010 and the architect, staff-engineer and engineering-manager notes
- [x] 1 `app/mitre_prompts.toml` (POC version 22: actors, plan, writer text and repair) and `MITRE_PROMPTS`
- [x] 2 Constants: `core/constants/mitre.py`, `RunPipeline.MITRE`, `TaskName.WRITE_MITRE_SCENARIOS`, two STIX collections, three `AiTask`s, `PromptVersion.MITRE_WRITER`, `LogEvent` members, two `AiApi`s; enums, celery and openapi pins re-written
- [x] 3 Settings: `MitreScenarioSettings`, three answer rooms, the env files and the configmap, conftest, test_config
- [x] 4 `crud/mitre/mitre_stix.py`, its indexes (outside the switch) and the indexes pin
- [ ] 5 Ingestion, always on
- [ ] 6 MITRE index; 7-9 engine; 10 schemas; 11 session; 12 worker task
- [ ] 13 Routes, runs.py guard, dashboard JSON and the two test lists (until then `tests/test_ai_usage_dashboard.py` fails on the two new `AiApi` members)
- [ ] 14 Dev timing run on real Kimi
