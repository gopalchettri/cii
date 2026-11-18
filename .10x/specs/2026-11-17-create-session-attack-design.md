# Plan: `POST /v1/create_session` — the AI writes the scenarios, MITRE ATT&CK in MongoDB confirms them

Approved by the owner on 17 Nov 2026. Full plan: `~/.claude/plans/create-a-new-api-wiggly-minsky.md`. ADR-008.

## The ask

A second way to start a run, beside `POST /v1/sessions`. The asset facts and the owner's prompt go to the AI. In one
call the AI uses its own knowledge of MITRE ATT&CK (Enterprise for IT, ICS for OT) to write the scenarios and, for
each, the attack group, the techniques and the mitigations. The MITRE data saved in MongoDB then checks all three.
The mitigations' prepared links give the controls, always from the existing controls library.

## The owner's decisions

- Same payload and response as `/v1/sessions`. `data_handled` is not a request field: the stored procedure
  `tsg_GetAssetContext` returns it as an asset fact, and both routes' prompts show it.
- One AI call writes a set with its groups, techniques and mitigations. No separate call that only lists risks.
- What MongoDB does not confirm is dropped. A scenario with no confirmed group or technique gets one re-ask, then is
  not returned; a spare risk takes its place.
- `TOTAL_SCENARIO_COUNT`, `INITIAL_SET_SIZE` and `NEXT_SET_SIZE` apply as for `/v1/sessions`. Never padded.
- Controls: each mitigation is linked to library controls in the background (AI-judged, stored); then one AI call
  per written set picks controls per sentence. Only library controls are shown; no control id reaches the AI.
- Only MITRE ATT&CK Enterprise and ICS. The import runs on a schedule an admin saves (on/off, daily or weekly, day,
  time, timezone), no longer every hour. Default: weekly, Sunday 02:00 UTC.
- An admin web UI at `/ui/` for ingestion, schedule, control links, jobs, keys, curation, AI usage and system state.
- Every API under "5. runs" and "6. review" works on a session made this way.
- `/v1/sessions` and every existing path, payload and response stay unchanged. Additive only.

## Worked example

OT asset "SCADA historian", sector Energy, 2 supporting systems; the stored procedure returns its data handled:
"Grid telemetry and operator commands". Settings: `TOTAL_SCENARIO_COUNT=15`, `INITIAL_SET_SIZE=6`, `NEXT_SET_SIZE=6`.

| Step | What happens | AI calls |
|---|---|---|
| Before any user | Import saves groups, techniques, mitigations and their links in `tsg_attack`. Linking saves, per mitigation, the library controls that do what it says in `tsg_control_links` (M0932 -> controls 412, 87, 530). | about 100, once per MITRE load |
| 0 | The API checks the caller and payload, reads names from SQL Server, saves the session, queues the job, answers 202 with the status board. | 0 |
| 1 | The worker asks the AI for the first 6 scenarios and the other risks it sees: 6 written + 11 listed = 17 found. 15 wanted, so 15 are the run's scenarios and 2 are spares. | 1 |
| 2 | Code looks up every group, technique and mitigation named (3 lookups, at most 4 database queries). "T9999 is not in MITRE ATT&CK ICS" is sent back once; still unconfirmed, the scenario is dropped and a spare takes its place. | 0, or 1 re-ask |
| 3 | Per scenario, a shortlist of 12 library controls (linked ones first, then nearest by meaning). One AI call picks which control reduces which sentence, and how (prevent, detect, contain, recover). Code checks each pick. | 1 |
| After | Next set repeats 1 to 3 for 6 more, then the last 3. Regenerate, accept, reject, promote, cancel, delete as today. | 2 per set |

All 15 scenarios: 3 calls to write + 3 to pick controls = 6, plus a re-ask only where MITRE lacks a name.

## Where it runs

- Steps 1 and 2: the existing task `tsg_write_scenarios`, one branch on `pipeline == "attack"`.
- Step 3: the existing task `tsg_map_controls`, the same branch.
- Linking: one new task `tsg_link_mitigations` on the maintenance queue (no new queue or pod), one at a time (Redis
  lock), queued after an import that changed the graph and by `POST /v1/tsg/intel/control-links/prepare`.
- Schedule: one document (`_id: "schedule"`) in `tsg_external_feed_status`; beat checks every 60 seconds; one
  compare-and-set claim, so two ticks or two beat pods start one import.

## Parts and order

| Part | Holds |
|---|---|
| Foundation | constants, two answer-room settings, request and response shapes, `AttackRepository` and `ControlLinkRepository`, the three prompts, this state |
| Ingestion | ATT&CK graph in the import (format 9), revoke hook |
| Linking | `tsg_link_mitigations`, the three control-links routes |
| Schedule | `GET`/`PUT /v1/tsg/intel/schedule`, `find_next_run`, `claim_due_run`, the 60-second beat check |
| Admin UI | `/ui/` static mount with security headers, nine pages |
| Start | route, `create_attack_scenario_session`, the starting plan |
| Write | prompt, answer reader, ATT&CK check, re-ask, count rule, cards, `AttackBatchWriter` |
| Controls | shortlist, pick call, pick checks, fallback to the search |
| Close-out | one test per existing API on a new session, pins, Swagger text, dashboard, README, end-to-end run |

## Known limits (deliberate)

1. A run can give fewer scenarios than asked once the re-ask and the spares are used.
2. With `TOTAL_SCENARIO_COUNT=0` the AI decides how many risks exist, in its first answer.
3. The AI's MITRE knowledge can be older than MongoDB's: a newer group is not used until the model knows it.
4. A scenario can end with few or no controls: picks are never padded.
5. A picked control shows as an `exact` match (a new value would change a response the UI reads).
6. The schedule is daily or weekly at one time of day; "Import now" covers the rest.
7. The admin UI has no login of its own: it uses what each route uses today.
8. The results do not say which API made a scenario; the session stores `pipeline: "attack"`.

## Verification

`ruff`, `mypy`, the whole suite in parallel shards; mutation checks on the count rule, the ATT&CK check and the pick
checks; then a live end-to-end run (import, linking twice, one IT and one OT session at count 15 and 0, every
existing API on them, the schedule two minutes ahead, the UI in a browser). Every bug found gets a root-cause fix,
a regression test and a re-run of the step that found it.
