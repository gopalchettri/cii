# ADR-005: External intelligence reads MITRE ATT&CK Enterprise and ICS only

**Status:** Accepted (owner, 16 Nov 2026: "keep only mitre enterprise and ics rest remove")
**Date:** 2026-11-16
**Feature:** simplify-codebase
**Author:** 10x-Team (Architect + Staff Engineer)

## Context
Evidence came from six sources (CISA KEV, FIRST EPSS, MITRE ATT&CK Enterprise and ICS, CISA ICS advisories, NIST NVD):
five formats, a paced NVD API with a key, CVE product linking and corpus joins, about 2,000 lines.

## Decision
Keep the two ATT&CK STIX bundles, downloaded from exactly:
`https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json` and
`.../ics-attack/ics-attack.json`, held in one `DATASETS` dict keyed `mitre_attack_enterprise`, `mitre_attack_ics`.
Delete the other four sources, their settings (`CII_NVD_API_KEY`), joins, product linking and fact sentences.
The `IntelSource` enum on the admin intel routes shrinks to the two values (the only API change; admin routes only).
Old records of removed sources stay in MongoDB, never read. Sanitising, download caps, the host allow-list, the switch,
every admin route and `intel_no_data` stay.

## Alternatives Considered
| Alternative | Pros | Cons | Why Not |
|---|---|---|---|
| Keep all six | Richest evidence | ~2,000 more lines, an API key, pacing | Owner chose ATT&CK only |
| Keep KEV as well | CVE exploitation facts | Product linking and joins stay | Owner chose ATT&CK only |

## Consequences
- Positive: one STIX parser, no paced API, no key; the first import is two downloads.
- Negative: scenarios no longer cite CVEs, EPSS likelihood or NVD severity/versions.
- Risks: an admin refresh queued with a removed source fails to parse; none are queued in normal use.
