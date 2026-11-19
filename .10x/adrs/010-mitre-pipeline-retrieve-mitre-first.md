# ADR-010: A separate MITRE run that retrieves MITRE data first, then lets the AI select, plan and write

**Status:** Accepted (owner, 19 Nov 2026: the plan `understand-the-e2e-runner-py-and-lucky-flurry.md`)
**Date:** 2026-11-19
**Feature:** mitre-pipeline
**Author:** 10x-Team (Architect + Staff Engineer + Engineering Manager)
**Supersedes:** for the new `pipeline: "mitre"` run only, ADR-008's "Retrieve ATT&CK first ... Why Not" row and its
"one AI call per set writes the scenarios" decision, and ADR-009's name settling and risk listing. The attack run
(`POST /v1/create_session`, ADR-008, ADR-009) and the library run (`POST /v1/sessions`) are not changed.

## Context
The POC at `POC/mitre-tsg-poc` (prompts version 22) gives verified, MITRE-grounded scenarios in about 75 s for 5:
the AI selects actors from all 240 MITRE actors, plans paths over all 810 techniques and the 18 ICS asset types,
writes one scenario per path in parallel, and code checks every ID against the MITRE STIX data. The owner wants
this engine in CII, without over-engineering, as the replacement path for scenario generation. ADR-008 rejected
"retrieve ATT&CK first" because the AI's own correlation was lost; the POC keeps it (the AI selects and plans from
the whole MITRE text, not from a search), so that reason no longer holds.

## Decision
- A new run `POST /v1/mitre_create_session` (asset IDs, `Idempotency-Key`; 202 with a status URL), polled at
  `GET /v1/mitre_sessions/{id}` and continued with `POST /v1/mitre_sessions/{id}/next-set`. Stored in the shared
  `tsg_sessions` / `tsg_scenarios` with `pipeline: "mitre"`; set by set (`INITIAL_SET_SIZE`, then `NEXT_SET_SIZE`).
- One Celery task `tsg_write_mitre_scenarios` (queue `tsg_scenarios`) through `run_leased_job`: the first set
  selects actors and plans paths once, every set writes the next paths in parallel (`MITRE_PARALLEL_WRITERS`).
- The MITRE import always runs, whatever `EXTERNAL_INTELLIGENCE_ENABLED` says: it also stores the full Enterprise and
  ICS STIX objects in `tsg_mitre_enterprise_stix` and `tsg_mitre_ics_stix` (one version each, never wiped by an
  empty import). Evidence use stays behind the switch.
- Controls come from the CII control library: the cards carry `content.attack` in the shape the existing controls
  job reads, and `tsg_map_controls` picks them from the mitigations' `tsg_control_links`.
- Prompts in `app/mitre_prompts.toml` (version 22, `PromptVersion.MITRE_WRITER`); every size is a required setting
  (`MitreScenarioSettings`, three `CII_ANSWER_TOKENS_MITRE_*` rooms), with no value in code.
- Code in `app/domain/scenario/mitre_scenario/` (two files: `mitre_engine.py`, `mitre_session.py`), plus
  `crud/mitre`, `schemas/mitre`, `search/mitre`, `worker/scenario/mitre`. The shared regenerate and next-set refuse a
  mitre run (409) through a 2-line guard in `runs._queue_write_job`; nothing else in the other pipelines changes.

## Alternatives Considered
| Alternative | Pros | Cons | Why Not |
|---|---|---|---|
| A third branch inside the attack run's files | one start route | ties two engines together; every attack file edited | owner: a separate pipeline, other pipelines unchanged |
| Keep the attack run's "AI writes first, MongoDB confirms" | already built | 63 of 247 names had wrong IDs (ADR-009); no actor selection from all actors | the POC's verified output is the target |
| Read MITRE STIX from the attack graph `tsg_attack` | no new collections | it keeps no procedures, ICS asset types, campaigns' dates or sectors | the engine needs the full STIX fields |
| Raise the shared `CII_AI_CALL_TOKENS_LIMIT` | one limit | changes the other pipelines' batching | two MITRE call limits of their own |
| Word export, new admin endpoints | POC parity | more code to own | not asked for |

## Consequences
- Positive: every group, technique and asset type shown is checked by ID; about 1-2 minutes for a first set; the
  library and attack runs are untouched; controls come from the CII library.
- Negative: two more collections (about 30k documents); an in-memory MITRE index per scenarios worker (about 94 MB);
  `import app.core.constants` now needs the three answer-room lines in the environment.
- Risks: the 1-2 minute target under CII's limiter (it reserves the full answer room and re-asks once) needs a dev
  timing run (task 14); the call limits are estimates (chars/3 versus the POC's tokenizer) until measured.

## Dependencies
- ADR-004 (FastAPI layout), ADR-005 (ATT&CK only), ADR-007 (scenario plain functions), ADR-008, ADR-009.
