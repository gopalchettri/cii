# qa: scenario-simple (17 Nov 2026)

- Final suite: 2,957 passed, 8 failed; all 8 belong to the parallel create-session work or the known local .env.uat line.
- Goldens: regenerated only for the approved removed keys (path-by-path diff checked); prompt text and contract pins
  unchanged; OpenAPI identical apart from the other session's additions.
- Mutation checks: origin_of_its_jobs (args[0] mutant caught), pick_controls_to_keep (>= to > caught after adding a
  boundary test), evidence fact building (caught after restoring a lost test).
- Reviews: wave 1 one weakened assertion (restored); wave 2 early review one blocker (principal lookup, fixed); waves 2-3
  one lost test (restored). Open: live end-to-end run not yet done.
