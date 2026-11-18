# ADR-009: The attack run's re-ask and risk listing, and the removed feeds' data deleted

**Status:** Accepted (owner, 17 Nov 2026: "do not make the solution overly complex and over engineered")
**Date:** 2026-11-17
**Feature:** create-session-attack
**Author:** 10x-Team (Architect + Product Manager)
**Supersedes:** in ADR-008, "code confirms every name against it, re-asks once, and drops what is still
unconfirmed" and the risk "A set's other risks must fit in the first answer"; in ADR-005, "Old records of removed
sources stay in MongoDB, never read" and "every admin route ... stay" (the withdraw and approve routes are gone, D83).

## Context
Ten live `POST /v1/create_session` runs (17 Nov): 63 of the first 247 names came with another entry's ATT&CK ID, and
the re-ask mostly made the AI keep the wrong ID; 11 of 15 write calls were re-asked; the first answer alone listed 7
to 10 risks where 15 were wanted. The removed feeds' records still sat in MongoDB, and no one deploying TSG has
database access.

## Decision
- Code settles a name: an ID given with another entry's exact name or alias takes the entry of that name; a spelling
  variant of the ID's own entry takes that entry; a name that is no one entry's is not trusted.
- An unconfirmed extra technique or mitigation is dropped with no re-ask. Only a scenario that would be lost is asked
  again, once and alone; every other slot keeps its first answer.
- Every writing call lists further risks, each with its group and one technique, while the plan holds fewer than
  `TOTAL_SCENARIO_COUNT` (0: always). An unconfirmed one is not planned; once a call lists no confirmed risk, no later
  call asks. Nothing is padded.
- Each import first deletes the records and status documents of the four removed feeds, named in
  `REMOVED_INTEL_SOURCES` (`cisa_kev`, `first_epss`, `nist_nvd`, `cisa_ics_advisories`); nothing else.

## Alternatives Considered
| Alternative | Pros | Cons | Why Not |
|---|---|---|---|
| Keep re-asking every unconfirmed name | the AI may fix a name | 19-22 s and about 3,000 tokens a re-ask, mostly for a name code can settle | owner: not over engineered |
| A separate AI call that only lists risks | one long list at once | one more call a run | listing in the writing call costs none |
| Delete every source the code does not know | no list to keep | an older pod during a roll-out deletes a newer source's data | named feeds only |

## Consequences
- Positive: fewer re-asks; a run can reach its count across sets; no manual database step for the old feeds.
- Negative: a call that lists only unconfirmed risks ends the asking for the run.
- Risks: a wrong name that is exactly another entry's name shows that entry (code cannot tell what the AI meant).

## Dependencies
- ADR-005, ADR-008; D83, D85 in `docs/SOLUTION_DESIGN.md`.
