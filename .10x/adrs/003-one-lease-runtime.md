# ADR-003: One lease runtime

**Status:** Proposed (awaiting the owner)
**Date:** 2026-11-16
**Feature:** simplify-codebase
**Author:** 10x-Team (Architect + Staff Engineer)

## Context
Four runtimes do the same claim, renew and take-over job: jobs plus the reaper (`app/worker/jobs.py`), controls
deliveries (`app/worker/scenario/controls_job.py`), admin-job heartbeats, and feed refresh claims. Each has its own
fields, timers and tests.

## Decision (proposed)
One lease helper (claim with fencing, renew thread, hand-back, expiry for the reaper) used by all four, keeping every
status field the API shows (`controls_delivery.retry`, `counts.controls_*`, the admin-job fields).

## Alternatives Considered
| Alternative | Pros | Cons | Why Not |
|---|---|---|---|
| Keep four runtimes | No risk now | Four ways to get leases wrong | The largest accidental complexity |
| Merge only the timers | Small | Leaves four claim paths | Half a fix |

## Consequences
### Positive
- One lease model to test and reason about.
### Negative
- A large change to job code that runs every request.
### Risks
- A status field the UI reads changes shape: the frozen contract and the e2e run must stay identical.

## Dependencies
- The owner's approval of this ADR before any code.
