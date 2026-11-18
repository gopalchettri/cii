# ADR-008: A run the AI writes first, confirmed against MITRE ATT&CK in MongoDB

**Status:** Accepted
**Date:** 2026-11-17
**Feature:** create-session-attack
**Author:** 10x-Team (Architect + Product Manager)

The approved plan calls this ADR-007; that number was taken the same day by `007-scenario-plain-functions.md`.

## Context
`POST /v1/sessions` finds threats in the SQL threat library, then writes scenarios. The owner wants a second way to
start a run: the asset facts go to the AI with the owner's prompt, and the AI names the attack group, techniques and
mitigations from its own MITRE ATT&CK knowledge. An AI can name things that do not exist, so nothing it names may be
shown unchecked. The import already downloads ATT&CK Enterprise and ICS but keeps only techniques.

## Decision
`POST /v1/create_session` (the payload and the `RunBoard` answer of `/v1/sessions`; `data_handled` is a fact the
stored procedure `tsg_GetAssetContext` returns, not a request field) starts a run with
`pipeline: "attack"`. One AI call per set writes the scenarios with their group, techniques and mitigations. The
import also stores the ATT&CK graph (objects and relationships) in `tsg_attack`; code confirms every name against
it, re-asks once, and drops what is still unconfirmed. Controls come from the library only: each mitigation is
linked to library controls in the background (`tsg_link_mitigations`, stored in `tsg_control_links`), and one AI
call per written set picks controls per sentence from a shortlist named by labels (C1, C2 ...). The run reuses the
existing tasks, lease, retry, cancel and review code, one branch each. The import runs on a schedule an admin saves.

## Alternatives Considered
| Alternative | Pros | Cons | Why Not |
|---|---|---|---|
| Retrieve ATT&CK first, then let the AI write from what was found | nothing unconfirmed is ever written | a search per asset, a longer prompt, and the AI's own correlation of sector and group is lost | the owner asked for the AI's knowledge first, MongoDB as the check |
| A separate AI call that only lists the risks | a steadier count at `TOTAL_SCENARIO_COUNT=0` | one more call per run | the owner chose one call |
| Show unconfirmed names with a warning | fewer dropped scenarios | invented groups or techniques reach a reviewer | never shown unconfirmed |
| Map controls with the existing search alone | no new task or collection | controls unrelated to the scenario's mitigations | linking gives controls that do what the mitigation says |
| A new queue and pod for the linking | isolated from imports | one more Deployment to size and watch | about 100 calls once per MITRE load fit the maintenance queue |
| Add the new job kind to `AdminJobKind` | one enum for every admin job | changes `AdminJobOut`, a frozen response shape | the kind is a constant of its own, with its own `ControlLinksJobOut` |

## Consequences
### Positive
- 6 AI calls for 15 scenarios with controls; every group, technique and mitigation shown exists in MITRE's data.
- Evidence is MITRE's own record that the group uses the technique, with its citations.
- No new queue, pod or review code; `/v1/sessions` and every existing shape are untouched.
### Negative
- A run can end below the asked count once the re-ask and the spares are used.
- Two more collections and one more background task to watch.
### Risks
- The AI's ATT&CK knowledge is older than the data: newer groups are not used until the model knows them.
- A set's other risks must fit in the first answer beside the written scenarios.
- Before the first linking ends, controls come from the search by meaning alone.

## Dependencies
- ADR-004 (FastAPI layout), ADR-005 (ATT&CK only). The frozen API contract (`tests/contract/ui_api_frozen.json`).
