# sde: create-session-attack (17 Nov 2026)

Built (all in the working tree, nothing committed):
- Start: `POST /v1/create_session` (`app/api/routes/scenarios.py`, summary "1b") calls
  `runs.create_attack_scenario_session`; it and `create_threat_scenario_session` share `_start_run`. The record carries
  `pipeline: "attack"`, step `scenarios`, a starting plan of empty slots (`attack.build_starting_plan`) and the job
  `tsg_write_scenarios`. `request_hash` is prefixed with the pipeline, so one Idempotency-Key never replays the other
  start route's run (409 `idempotency_key_conflict`). 409 `intel_no_data` when `tsg_attack` is empty or lacks a
  source the asset needs; next set and regenerate make the same check.
- Prompt: `app/domain/scenario/attack_prompt.py`, text and pieces in `app/prompts.toml` `[scenario.attack]`; built per
  request (only the facts present are named; Enterprise, ICS or both by asset type). `app/tsg_prompt.txt` is gone.
- Write and confirm: `app/domain/scenario/attack.py` and `app/worker/scenario/attack_job.py` (`AttackPathWriter`,
  `AttackBatchWriter`, reached by one branch in `write_job.write_scenario_batch`). One checked call a set
  (`AiTask.WRITE_SCENARIO`, `reuse_earlier_answer=True`); three `tsg_attack` lookups an answer (`find_objects`, `find_uses`,
  `find_mitigations`; `find_uses` makes two queries, the group's links and those of its attributed campaigns), three
  more for a re-asked set; only a slot that would be lost is re-asked, alone, and it alone takes the re-ask's answer
  (`_merge_reasked_set`); an unconfirmed extra technique or mitigation is dropped with no re-ask; every writing call lists
  further risks while the plan holds fewer than the count (`is_listing_risks`, `plan.risks_complete`); the count rule is
  `extend_attack_plan`, written with the plan in one fenced write. An ID given with another entry's exact name takes that
  entry; a spelling variant of the ID's own entry takes the ID's (`_find_named_object`; ADR-009, D85). The AI's prose is
  cleaned (`write.remove_ids_and_links`: technique, CVE and advisory numbers, links; `[n]` markers) and checked with
  the library writer's own functions (`write.find_not_english_problems` in the one re-ask,
  `write.apply_safety_checks` on the draft: a finding saves the card blocked and gives the path up).
- Controls: `app/domain/scenario/attack_controls.py`, reached from `controls_job.py` by `is_attack_scenario`. One
  `find_links` read, one embedding call and one `AiTask.PICK_CONTROLS` call a set of up to 6; the search
  (`map_controls`) is the fallback for an answer that cannot be read and for a scenario left out twice. A plan job
  that maps an attack scenario's controls itself (`worker/remediation.py` `_map`) picks them the same way. Stored
  technique states: `matched`, `no_known_defence`, `not_prepared`, `no_library_control`, `type_mismatch`,
  `not_offered`, `not_picked` (in no response).
- Ingestion: the ATT&CK reader keeps the graph (`AttackReading.FORMAT` "9"); `crud/attack.py` stores it; linking in
  `domain/intel/control_links.py` and `worker/control_links.py` (task `tsg_link_mitigations`, maintenance queue);
  schedule in `domain/intel/schedule.py`; five new intel routes (schedule GET/PUT, control-links GET, prepare, job).
  D83 (17 Nov): the source revoke and approve routes are removed; group 4 has ten routes, numbered 1 to 10 in
  Swagger (the schedule 6 and 7, the control links 8 to 10).
- Admin UI: `app/api/ui.py` mounts `app/ui` at `/ui` (9 page modules, no build step).
- Settings: `CII_ANSWER_TOKENS_LINK_CONTROLS` 2048, `CII_ANSWER_TOKENS_PICK_CONTROLS` 3072 (every `.env` example and
  `deploy/configmap.yaml`).

Tests (functions counted in the files on 17 Nov at 11:45, parametrised cases not counted; not run by the docs lane):
`test_attack_writer.py` 54, `test_control_links.py` 41, `test_attack_controls.py` 38, `test_import_schedule.py` 29,
`test_attack_repository.py` 22, `test_admin_ui.py` 17, `test_attack_prompt.py` 15, `test_create_session_foundation.py`
13, `test_create_session_start.py` 11, `test_attack_graph_store.py` 12, `test_create_session_flow.py` 2. Last area
runs reported by the fixers: scenario area 577 passed, 0 failed (11:35); ingestion area 1,029 passed, 1 failed (a
lint finding in another lane's file, fixed since).

Deviations from the plan: no `CreateSessionRequest` (the body is `StartRunRequest`); `data_handled` is a fact of
`tsg_GetAssetContext`, not a request field; the control-links job kind is a constant with its own
`ControlLinksJobOut`; every confirmed technique is cited (a second wording, `AttackMessage.IS_TECHNIQUE`, when ATT&CK
records no use by the group); a first-set slot the AI finds no risk for is left out (`NO_FURTHER_RISK`), not given up.

Not done or not verified: a pin-test and whole-suite run after the last fixes (the lead's); a live end-to-end
`POST /v1/create_session` run with a real AI; the prompt's wording is not A/B-measured; a remediation plan on an
attack scenario is tested at the plan job (`tests/test_attack_controls.py`, three tests), not in the flow test.
Left as they are, for the owner (handoff.md): the sentence in
`given_up_paths[].reason`; a plan on a scenario with no picked control; sentences cut at "e.g."; an asset with no
IT/OT type. Known cost: a delivery tried again after the plan write pays a second write call.
