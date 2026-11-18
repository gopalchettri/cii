# ADR-002: One AI limit path

**Status:** Accepted
**Date:** 2026-11-16
**Feature:** simplify-codebase
**Author:** 10x-Team (Architect + Staff Engineer)

## Context
An AI call passes: the request-rate pacer's pre-slot wait (`wait_for_send_time`), an AI slot (Redis, cross-pod),
the pacer's turn (`wait_for_turn`), a retry wrapper around a second retry loop, and, for evidence, a per-process
rerank gate. The limiters fail open on a Redis error at cap 0 and keep unreleased-slot bookkeeping; the API process
has its own wait policy; the dev laptop's local reranker has a turn scheduler.

## Decision
Keep the essential limits (the shared slot caps, the token and request pacer with its give-back and 429 pause, the
429 retries, the owner-pinned adaptive cut and rerank gate). Remove: the pre-slot pacer wait (the turn already
respects the pause), the fail-open and unreleased-slot bookkeeping (a Redis error is `Unavailable`, as for every
capped pool), the API-vs-worker wait split, the double retry wrapper, the give-back's line-id fencing, the local
reranker's turn scheduler (one lock), the rerank gate's unused timed refusal.

## Alternatives Considered
| Alternative | Pros | Cons | Why Not |
|---|---|---|---|
| Keep everything | No risk | The owner's complaint stands | |
| Also drop the adaptive cut and the rerank gate | Fewer parts | Owner-pinned settings | The owner keeps them |

## Consequences
### Positive
- One path per call, easier to reason about when the gateway is full.
### Negative
- During a 429 pause, waiting calls hold their slot (the slot gauge may read higher).
### Risks
- A Redis outage at cap 0 now stops AI calls instead of running them unlimited (production caps are all above 0).

## Dependencies
- The owner's AI settings stay as they are.
