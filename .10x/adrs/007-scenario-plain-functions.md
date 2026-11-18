# ADR-007: Scenario module as plain functions, no behaviour change

**Status:** Accepted
**Date:** 2026-11-17
**Feature:** scenario-simple
**Author:** 10x-Team (Architect + Staff Engineer)

## Context
`app/` is 26,188 lines; the owner calls it over-engineered and asked to simplify the scenario module first. A 223-agent
audit (`reviews/2026-11-17-scenario-audit.json`) found the scenario code (about 10,600 lines with evidence) is mostly real
rules and safeguards; the accidental part is dependency-holder classes, data passed through several shapes, removed-source
leftovers and never-read stored fields.

## Decision
The safe plan (`specs/2026-11-17-scenario-simple-design.md`): `ThreatScenarioService`, `ExternalIntelligenceService` and the
other dependency-holder classes become plain functions that call module-level getters; tests patch module attributes with
`monkeypatch`. Internal shapes that only pass data on become dicts. Never-read stored fields stop being written. Evidence
code keeps only MITRE ATT&CK Enterprise and ICS; dead enum values of removed sources go and `enums.json` is re-pinned.
Every rule, retry and safeguard stays. The two scenario repository classes stay classes (about 150 edits for 0-9 lines).

## Alternatives Considered
| Alternative | Pros | Cons | Why Not |
|---|---|---|---|
| Fold control matching into the write job | about -250 more lines, one job system fewer | loses per-card controls status and the 30-minute auto-retry | owner declined |
| Remove AI re-ask/rewrite, text shaping, spare paths | about -450 more lines | more failed cards, fewer scenarios, rougher prompts | owner declined |
| Rebuild scenario generation to a line budget | biggest reduction | biggest risk, needs a feature-by-feature design round | owner chose the safe plan |

## Consequences
### Positive
- One way to reach a dependency (import the getter); fewer hops from route to store; about -880 lines.
### Negative
- About 9,000 test lines change how they reach the code; module-attribute patching needs callers to go through the module.
### Risks
- A fake not seen because code imported the name directly: callers use `module.fn`; gates run the whole suite per wave.
- A golden regeneration hiding a prompt change: one agent regenerates, a diff check allows only the named removed keys.

## Dependencies
- ADR-004 (FastAPI layout), ADR-005 (ATT&CK only). Remediation and the service mapper follow in later rounds.
