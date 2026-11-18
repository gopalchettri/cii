# SDE: FastAPI restructure (16 Nov 2026)

What was built, in parallel waves of one engineer per area, each in its own worktree, merged by 3-way patch:

| Step | app/ lines |
|---|---|
| Start | 34,572 |
| Wave 1 (six areas into routes, schemas, crud, domain) | 29,805 |
| Wave 2 (small cuts, merge fixes) | 29,454 |
| Wave 3 (seven features: service classes and container getters out) | 28,931 |
| Style pass (120 columns, no magic trailing commas, no docstrings on private helpers) | 27,314 |
| Wave 4 (seven lanes, with review fixes) | 26,236 |

Also built: acks at start (ADR-006, `task_acks_late=False`, the reaper is the only recovery); intel sources ATT&CK
Enterprise and ICS only (ADR-005).

Merge-review fixes (16 Nov, 8 reviewers, two skeptics per finding): a cut-off comment in `crud/scenarios.py`; the
remediation chat-test fake now writes through the real call-record path; the library check logs a SQL Server outage
as one `dependency.unavailable` warning again (test pins the log levels; mutation-checked); the unused
`RerankModel.preload()` deleted; import cycles removed (`outage_reason` and `job_error_of` moved to
`core/exceptions.py`, so domain code no longer imports `worker/jobs.py`; the container binds the scenario service by module).

Accepted risks (listed, not fixed):
- AI-usage replay (USG-ROLLUP): if a spilled-row replay's add-up fails part way, the scheduled add-up does not go back
  to those hours by itself; the tool shows the error and `roll-up <since>` re-adds them.
- The laptop's local reranker is no longer preloaded at worker start: the first rerank pays the cold load (dev only).

Not done (need cross-area work, after wave 4): delete the DI container (P1), crud class shells as functions (P2),
inline log-event and message enums (P3, P5), the scenario worker rewrite (W1a) if the lane did not land it, the AI
pacer rewrite (LIM-PACER).
