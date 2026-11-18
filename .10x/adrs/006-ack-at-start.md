# ADR-006: Jobs are acknowledged when they start; the reaper alone recovers them

**Status:** Accepted (owner, 16 Nov 2026: "this 70min is correct approach? i find it flawed ... fix this issue as well")
**Date:** 2026-11-16
**Feature:** simplify-codebase
**Author:** 10x-Team (Architect + Staff Engineer)

## Context
With `task_acks_late=True`, a killed pod's message came back from Redis after the 4,200 s visibility timeout (70 min),
long after the reaper had already re-sent the job (about 2 min); the claim then dropped the copy. Two recovery paths,
one useless.

## Decision
`task_acks_late=False`: a message is acknowledged when its job starts (Celery `on_accepted`). The reaper, from MongoDB's
job record, is the only recovery path. The visibility timeout now covers only messages held before they start (a
retry's countdown) and stays above the longest retry wait.

## Alternatives Considered
| Alternative | Pros | Cons | Why Not |
|---|---|---|---|
| Keep acks_late, shorter visibility timeout | Faster broker redelivery | Re-sends running jobs | Duplicates during long jobs |
| Celery retries only, no reaper | Less code | 70 min recovery | The flaw itself |

## Consequences
- Positive: one recovery rule, no 70-minute ghost copies, fewer duplicates.
- Risks: a message accepted and the pod killed before the claim: the job stays queued; the reaper's lost-message rule
  re-sends it (at once if the queue is empty, else after 15 min). Pinned by `test_a_killed_pod_s_job_comes_back_through_the_reaper_only`.
