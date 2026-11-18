# qa: create-session-attack (17 Nov 2026)

- Flow test (`tests/test_create_session_flow.py`): a run started by `POST /v1/create_session` on the SQL test database,
  every queued message delivered to the real Celery tasks against the test MongoDB, a fake chat model answering. It
  drives status, results, one scenario, the entity's scenarios, plan-trace, accept, regenerate (version 2), reject,
  next set until 409 `target_reached` (count 4) or `nothing_left` (count 0), promote-to-library, cancel and delete.
  Each set cost one write call, one pick call and one `tsg_map_controls` message.
- Reported by the build agents (their own runs, slot gw6): writer 25 passed, controls 28, prompt 23, start 18,
  foundation 25, repository 18, flow 3; last combined run 44 files, 841 passed, 6 failed: 5 contract pins (expected
  until the lead rewrites them) and `test_controls_fixes.py::test_a_delivery_with_nothing_left_to_map_reads_no_context`,
  a test-order leak from `test_run_actions.py:194` and `test_d51_idempotency.py` (not this feature).
- Mutation checks reported: writer 13 of 13 killed; controls picker 31 of 32 (the survivor changes no stored record);
  joining changes 8 of 8.
- Round-2 review (4 reviewers) found, and the code now has a fix for: a re-ask replacing the whole first answer
  (`_merge_reasked_set`); the shortlist ignoring the mitigations ATT&CK records for a technique (`_list_mitigations`);
  the data check not asking for the asset's own matrix (`has_data(sources)`); a split first call losing the listed
  risks (the prompt is built per part); an ATT&CK ID with another entry's name (`AttackMessage.NAME_MISMATCH`); a
  first-set slot with no risk counted as given up (`NO_FURTHER_RISK`); a state that said "not picked" for controls
  never offered (`TechniqueControlState.NOT_OFFERED`). The fixers report 26 run findings (23 fixed with a test, 26 of
  26 mutants killed) and 5 controls findings (all fixed).
- Security review (5 findings): 4 fixed, each with a test proven to fail when the defect is put back:
  `test_a_source_withdrawn_and_imported_again_costs_no_rerank_and_no_chat_call` (no link is deleted; it used the
  withdraw route, so the D83 lane rewrites it by another real path or deletes it: its report says which),
  `test_the_prompt_says_its_input_blocks_are_data_and_never_instructions`,
  `test_public_numbers_links_and_markers_in_the_ais_prose_are_never_saved_and_code_still_cites` and
  `test_prose_a_writer_safety_check_faults_is_kept_hidden_and_given_up_as_the_writer_does` (the AI's prose),
  `test_a_fetch_that_lost_most_of_its_links_or_its_objects_fails_and_keeps_the_stored_graph`. The fifth (the switch
  does not stop a create-session run) is not changed: the owner's decision.
- Verify round (one lane on the run code, one on the controls code): 17 verified findings, 12 fixed with a regression
  test each, 5 left for the owner (handoff.md, 1-6). Its area run: 577 passed, 0 failed, twice (11:35).
- Mutation round 2 (start, writer, controls): 116 mutants, 106 killed, 10 survived; 10 tests added, each kills its
  mutant. Round 1 (ingestion, links, schedule, UI): 162 mutants in the final pass, 6 survived; 20 tests added over
  both passes. No survivor showed a wrong rule.
- Suite triage (10:35-10:48, before the verify round's fixes): whole suite in one process 3,017 passed forward and
  3,018 reversed; failing: the 7 pin tests, `.env.uat`'s `CII_NVD_API_KEY` line, and once a lint failure of a file
  being edited. Two test-order leaks fixed at the root. ruff and mypy (the repo's configuration) clean at 10:35.
- The first import at beat's first check: fixed (`read_schedule(now)`), with
  `test_beats_first_check_on_a_database_with_no_schedule_imports_on_a_clock_that_moves`; the live lane saw the
  schedule created and claimed in one check (03:52:03 UTC).
- Docs lane run (slot gw4) after adding the two settings to `deploy/configmap.yaml`: `test_deploy.py`,
  `test_deploy_rollback_and_routes.py`, `test_config.py`, `test_ai_rate_limited_wait.py`, `test_observability.py`: 131
  passed, 1 failed (`test_config.py::test_env_files_match_settings[.env.uat]`: the owner's local `.env.uat` still has
  a `CII_NVD_API_KEY` line the app no longer reads; known, not from this feature).

Verified live by the live lane on the laptop (its report, not re-run here): the import of both sources, the schedule
and the linking with a real AI (93 mitigations: 93 chat and 93 rerank calls; a second run none).
Not verified: a live `POST /v1/create_session` run with a real AI (a live-run agent was at work when this was
written); a browser run of `/ui/`; the whole suite and the pin tests after the verify round's fixes; SSE events on
an attack run; a remediation plan on an attack scenario through the API (the plan job is unit-tested);
`scripts/e2e_all_api.py`'s three new steps against a live stack (dry run only).

D83 (17 Nov, the owner): the withdraw and approve routes are removed. The docs lane changed docs only and ran no
test. Expected from the code lane: the tests of the two routes deleted, one test that both paths answer 404 and are
absent from the OpenAPI, `scripts/e2e_all_api.py` without its "Intel source" step, and an OpenAPI diff showing
every remaining path and schema unchanged. The pin tests fail until the lead re-writes `tests/contract/*`.
