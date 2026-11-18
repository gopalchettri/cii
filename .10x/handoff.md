# Handoff

Branch `tsg_simplify_codebase_2026-11-16_16-25` (stacked on `tsg_remediation_servicemapper_concurrent_user_16Nov2026`); all
work is uncommitted in the working tree (owner: never commit without asking).
Current plan: `specs/2026-11-16-under-20k-design.md`, one feature at a time (order in `decisions/engineering-manager/fastapi-restructure.md`).
Area plans and reviews (cuts with ids and classes): the session scratchpad `areas/*.json`, summarised in the spec.
Hard limits: contract pins unchanged (except ADR-005's IntelSource enum), prompts byte-identical, stored fields and
names unchanged, Celery task names unchanged, SQL Server for stored procedures only.

## scenario-simple (17 Nov 2026)
Plan: `specs/2026-11-17-scenario-simple-design.md` (ADR-007). Lane change lists: `specs/2026-11-17-scenario-lanes.json`.
Baseline hashes: `reviews/2026-11-17-baseline.sha256`; OpenAPI sha256 6d5148ce54752c62b1aa0d131c2632b7402aa2b549c1428495b3998ded186d04.
Tests: `.venv/Scripts/python.exe -m pytest tests -q -n 6` (MongoDB must be running). Nothing is committed.

## create-session-attack (17 Nov 2026)
Plan: `specs/2026-11-17-create-session-attack-design.md` (ADR-008; the owner's plan file calls it ADR-007, a number
scenario-simple took). Additive: `/v1/sessions` stays as it is, and so does `tests/contract/ui_api_frozen.json` but for
four description texts (`PUT /v1/tsg/intel/switch`, `POST /v1/tsg/intel/refresh`, `IntelRefreshBody`, the admin jobs
cancel route), which the lead reports the owner approved: no path, parameter, body or response differs.
Done (17 Nov): everything in the plan is built; review rounds 1 and 2, a security review and a verify round are
fixed, each fix with a regression test (see `status.md`). The live run is done (10 runs, 17 Nov); its findings
are fixed (ADR-009, D84, D85). Next: a live run on that code, the lead's final suite and pin run, then the
owner's decisions still open below.
Runs in the same checkout as scenario-simple. Its additions change these pins until the lead re-writes them at the
end (`tests/test_outside_contract.py`): `enums.json` (new members; removed-feed members gone), `celery.json`
(`tsg_link_mitigations`), `indexes.json` (`tsg_attack`), `tsg_names.json` (`tsg:control_links:lock`), `openapi.json`
(new schemas). `app/prompts.toml` gains three sections; no existing prompt changed, `version` stays 2.
The pin files were written at 11:18-11:34 on 17 Nov, after the last fixer finished; not verified by a pin-test run
since. Nothing waits on another part: `tsg_link_mitigations` exists and the AI usage dashboard names the new call and
the two control activities.
Group 4 routes removed (owner, 17 Nov; D83 in `docs/SOLUTION_DESIGN.md`): `POST /v1/tsg/intel/sources/{source}/revoke`
and `.../approve` go, with the per-source `approved` flag, the purge of a withdrawn source and the UI's Withdraw and
Approve buttons. The other ten group 4 routes keep their OpenAPI (Swagger numbers them 1 to 10). The code change is
made in a copy and applied by the lead; the docs and the SDD already describe the state after it. The pin tests
(`tests/test_outside_contract.py`, `tests/test_ai_usage_no_api_change.py`) fail until the lead re-writes
`tests/contract/*`. ADR-005 says every admin route stays: it is not edited, D83 records the change.
Open for the owner (each is a choice, none blocks the live run):
1. Settled (owner, 17 Nov; ADR-009): an ATT&CK ID given with another entry's exact name takes that entry, and a
   spelling variant of the ID's own entry ("Multifactor Authentication") takes the ID's; no re-ask for either.
2. Settled (owner, 17 Nov: no change): a run whose first write call is unusable for good holds no scenario; only
   a new start helps.
3. `GET plan-trace`: `writing.given_up_paths[].reason` holds a sentence on these runs, a code on `/v1/sessions` runs.
4. A plan on a scenario with no picked control has no library-mapped control, and each such plan request pays one
   pick call.
5. A scenario's sentences are cut at every full stop and space ("e.g. "), so a picked control's reason can be a
   fragment.
6. Settled by the owner's asset-type decision (17 Nov): "Every asset will have asset type. it will either IT or OT
   or IT\OT both i.e., hybrid". The code still treats an asset with no type as both matrices.
7. Settled (owner, 17 Nov: keeps working): the intelligence switch (env or runtime) does not stop `POST /v1/create_session`, its next set or its regenerate:
   they run from the stored graph, and only missing data refuses them (409 `intel_no_data`).
8. Closed by D83 (17 Nov): a source can no longer be withdrawn, so no route says a source's data is deleted. Control
   links are still never deleted.
9. On these scenarios `evidence[].modified` and `fetched_at` are null: `tsg_attack` keeps neither.
10. A group or mitigation number ("G0034", "M0932") the AI writes in its prose is not removed; technique, CVE and
    advisory numbers and links are.
11. By hand: the line `CII_NVD_API_KEY` in `.env.uat` and `deploy/secrets.yaml` (it fails
    `test_env_files_match_settings[.env.uat]`). The removed feeds' records: settled (owner, 17 Nov), the app
    deletes them at the start of every import (`crud.intel.delete_removed_sources`).
12. The SDD's version history table has no new row for these changes.
Known and not fixed (defects or costs, reported by their lanes):
- A write delivery tried again after the plan write pays a second write call (its prompt differs, so the earlier
  answer is not reused).
- `tests/goldens/scenario/controls_cards.json` and `controls_cases.json` show unstaged changes dated 06:05 on 17 Nov,
  before the fixers' work; for the lead to check against "goldens stay byte-identical".
Waves 0-3 done and gated (17 Nov). The scenario files now belong to the create-session session ("Threat scenario generation API"), which also does the single contract re-pin. Left: live end-to-end run; nothing committed.
