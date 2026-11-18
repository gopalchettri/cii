# sde: scenario-simple (17 Nov 2026)

Built (waves 0-3, all gated with the whole suite on 6 workers):
- Scenario service, intel admin service, evidence finder/at-write, source refresher, work control, asset lookup,
  control mapper: classes that only held dependencies are now plain functions reached through module attributes.
- worker/scenario: path_writing.py merged into write_job.py (5 files -> 4). app/domain/library/ and
  app/core/callables.py deleted.
- Never-read stored fields no longer written: missing_facts, counts.replaced, plan-trace turns/groups ({} in the API),
  plan prompt_version, library_stamp, controls.warning/shortfall/left_out_over_max, 6 unread made_with keys.
- Removed-source leftovers (KEV/EPSS/NVD/ICS advisories): quarantine rows, paged-feed fields, generic source helpers,
  Applicability enum, EvidenceRole.DIRECT, IntelState.QUARANTINED.
- origin_of_its_jobs finds the principal by type (any argument order).

Deviations: W6 guards removed (a hand-broken plan now ends with an internal_error card, not invalid_plan; the planner
never builds one). RejectedRecord keeps 4 fields (a source test asserts raw_hash). Two tests added: a control score at the
threshold, and evidence facts built only for kept records (both caught surviving mutants).
Not done: the live end-to-end run (plan gate 7); tests/contract/enums.json re-pin (handed to the create-session session).
