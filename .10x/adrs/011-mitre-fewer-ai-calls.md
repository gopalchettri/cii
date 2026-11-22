# ADR-011: A MITRE run makes only the AI calls a set needs

**Status:** Accepted (owner, 22 Nov 2026: the plan `understand-the-e2e-runner-py-and-lucky-flurry.md`)
**Date:** 2026-11-22
**Feature:** mitre-pipeline
**Author:** 10x-Team (Architect + Staff Engineer)
**Extends:** ADR-010 (nothing in it is superseded)

## Context
Owner session f7acd30b (asset 1166) took 109.8 s in "threats", and a create used 8 to 9 Kimi calls against a
budget of 10-12 for a whole session. The calls were traced in `tsg_ai_usage` and `tsg_ai_call_texts`:
- **Actor selection:** one call over every MITRE actor profile listed about 130 actors. It ran past its answer
  room, was cut off after about 45 s and was asked again.
- **The planner's further round:** it ran at the end of the first set whenever fewer than NEXT_SET_SIZE paths
  were left. That is 2 calls and about 32k tokens for a set the user may never ask for.
- **Writer re-asks:** every set re-asked the writer for one scenario. Most re-asks were for something code can
  remove: a technique the plan lacks (15 of 60), or a group that is not a candidate or is not documented (5 of 60).

## Decision
1. **Actor profiles in two slices, asked in parallel.** `MITRE_ACTOR_SLICE_TOKENS_LIMIT=34000` and
   `CII_ANSWER_TOKENS_MITRE_ACTOR_SELECTION=8192`; the longest answer seen for half the profiles is about 6.1k.
2. **The further round only when a set needs it.** A set asks for the round first when it has fewer open paths
   than it writes. A set that leaves no open path asks at its end, so the board never reads "complete" while
   the planner may find more.
3. **Writer answers repaired by removing.** An unplanned technique, or a group that is not a documented
   candidate, is left out and the scenario is kept. Only the first MITRE_GROUPS_PER_SCENARIO groups are kept.
   Code only removes, so every fact left is still MITRE's. The writer is still asked again when:
   - fewer than ATTACK_PATH_TECHNIQUES' minimum techniques are left;
   - no group is left;
   - the text names what was left out (its MITRE ID or name);
   - any other check fails (threat type, word limits, systems, invented IDs).

4. **A smaller writer input, still MITRE's words.** Each technique description is cut to its opening sentences
   within `WRITER_TECHNIQUE_DESCRIPTION_CHARACTERS=400` (the full text averaged 1,240 characters; the 3 procedures
   per technique stay). The actor selection's unchecked AI `reason` no longer reaches the writer.

## Alternatives Considered
| Alternative | Pros | Cons | Why Not |
|---|---|---|---|
| A bigger actor answer room, one call | 1 call | Still cut off at 9,000; 50 s | Tried live: failed |
| Tell Kimi in the prompt to list fewer actors | No code | Ignored (134 listed) | Tried live: failed |
| 7 small actor slices | 32 s | 7 calls | Over the call budget (owner) |
| No further round (MITRE_PLANNER_MAX_FURTHER_ROUNDS=0) | 6 calls, simplest | A session ends at the first plan's paths | Owner kept "all paths" |
| Looser word slack, to cut word-limit re-asks | Fewer re-asks | Longer titles | Owner chose removing only |

## Consequences
- **Positive:** a create is 6 Kimi calls (4 when the actor answers are reused within 24h), threats take about
  37 s and a run about 85 s. A whole session of about 17 scenarios is about 13 calls.
- **Negative:** the set that runs short of paths waits about 14 s more for the planner.
- **Risk:** one create sends about 92k tokens within about a minute, against the dev quota of 100k tokens a
  minute. Two creates started at once get 429s, which the request-rate limit retries. Production needs about
  200k tokens a minute for two at once (an owner decision).
