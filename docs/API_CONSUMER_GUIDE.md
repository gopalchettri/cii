# TSG API consumer guide: threat scenarios, remediation and service mapper

Covers 18 endpoints. Source of truth: `app/api/routers/scenario.py`, `app/api/routers/remediation.py`, `app/api/routers/service_mapper.py`, `app/models/**`.

## 1. Basics

**Base URL:** `https://<tsg-host>` (paths below start with `/v1`; no extra prefix).

### Headers

| Header | Required | Value |
| --- | --- | --- |
| `X-API-Key` | yes | API key (`ciip_...`) |
| `X-User-Id` | yes | user id, 1-256 chars (blank = missing; longer → 422) |
| `X-Entity-Id` | yes | integer 1..2147483647; not an integer, 0, negative or larger → 422 |
| `X-Tenant-Id` | yes | tenant id, 1-256 chars (blank = missing; longer → 422) |
| `Content-Type` | POST with body | `application/json` |
| `Idempotency-Key` | see below | up to 200 chars |
| `X-Request-Id` | no | your trace id; kept if it matches `[A-Za-z0-9._-]{1,64}`, else replaced. Always echoed on the response. |

Any of the four identity headers missing → `401`. Unknown or revoked key → `401`. A `401` carries `WWW-Authenticate: ApiKey realm="tsg", header="X-API-Key"`.

Every run, scenario, plan and mapping belongs to the entity in `X-Entity-Id`. Unknown id → `404`; another entity's → `403`.

### Idempotency-Key

| Endpoint | Behaviour |
| --- | --- |
| `POST /v1/sessions` | optional. Same key + same body → `200` with the same run. Same key, other body → `409 idempotency_key_conflict`. |
| `POST /v1/remediation`, `is_manual=true` | **required** (else `422`). Same key + same body → `200`, `replayed: true`. Same key, other body → `409 idempotency_key_conflict`. If that plan failed for an outage (`error.code` `unavailable`), the same key and body write its latest version again: `202`, `replayed: true`, `status: queued` (it can then also answer `409 run_being_deleted` or `control_library_empty`). |
| `POST /v1/remediation`, `is_manual=false` | accepted but ignored. A repeat → `409 plan_already_exists`. |
| `POST /v1/service-mapper` | optional. Same key + same body → `200` with the same `mapping_id`; when that key's generation is still the mapping's latest and failed for an outage (`error.code` `unavailable`), `202` with a new try (the next `generation`). Same key, other body → `409` (no `reason`). |

Keys are one namespace per entity across `POST /v1/sessions` and manual `POST /v1/remediation`: a key used on one → `409 idempotency_key_conflict` on the other. `POST /v1/service-mapper` keys are a namespace of their own. Use a fresh key (e.g. a UUID) per new request.

### Error body

Every error is `application/problem+json` (RFC 9457):

| Field | Type | Meaning |
| --- | --- | --- |
| `type` | string | always `about:blank` |
| `title` | string | HTTP status phrase |
| `status` | int | HTTP status |
| `detail` | string | human message |
| `code` | string | `validation_error`, `unauthorized`, `forbidden`, `not_found`, `conflict`, `unavailable`, `internal_error`, `setup_error` |
| `request_id` | string | same as `X-Request-Id` header |
| `reason` | string, optional | the rule that refused it (mostly on 409). Stable: branch on this. |
| `errors` | array, optional | 422: `[{field, message}]`. Review 409s: `[{scenario_id, reason}]`. |
| `details` | object, optional | facts you can act on, e.g. `active_session_id`, `remediation_id`, `system_ids` |

```json
{
  "type": "about:blank",
  "title": "Conflict",
  "status": 409,
  "detail": "Asset 1166 already has an active run.",
  "code": "conflict",
  "request_id": "3f9a0c2e5b7d4a1e8c6f0b2d4e6a8c0e",
  "reason": "active_session_exists",
  "details": { "active_session_id": "938cc176aede40daa154f7c572cd2494" }
}
```

422 `errors[].field` is the location joined by dots: `body.scenario_ids`, `body.manual_scenario.threat_name`, `header.X-Entity-Id`, `header.Idempotency-Key`. A rule on the whole body (e.g. mixing manual and generated fields) has field `body`; its message starts with `Value error, `.

### Status codes

| Code | When |
| --- | --- |
| 200 | read; review; accept; relationship decisions; idempotent replay |
| 202 | work queued (start run, regenerate, next set, request plan, regenerate plan, create mapping) |
| 401 | identity headers missing, bad key |
| 403 | another entity's record, asset or system not yours |
| 404 | unknown id |
| 409 | state conflict: see `reason` |
| 413 | body larger than `CII_MAX_REQUEST_MB` (default 2 MB); `code` is `validation_error` |
| 422 | invalid body, query, header or path |
| 500 | unexpected (`internal_error`) or server misconfigured (`setup_error`); quote `request_id` |
| 503 | a store or the AI is down; header `Retry-After: 5`. Retry. |

### Validation rules that apply everywhere

- Unknown body fields → `422` (`Extra inputs are not permitted`). Every request body model uses `extra="forbid"`.
- Ids in a path (`session_id`, `scenario_id`, `mapping_id`): at most 64 chars.
- Paging (only `GET .../results` here): `offset` default 0, 0..2147483647; `limit` default 50, 1..500. Use `total` to page.

## 2. Flow

```
POST /v1/sessions ─► 202 {session_id}
        │
        ├─► GET /v1/sessions/{sid}            (poll)   ┐ until progress.overall =
        └─► GET /v1/sessions/{sid}/events     (SSE)    ┘ awaiting_review | awaiting_next_set | complete | error | cancelled
        │
GET /v1/sessions/{sid}/results ─► scenarios[] (take scenario_id from here)
        │   ── the three calls below need session_status != active, else 409 generation_in_progress ──
        ├─► POST .../accept                     (accept ids or "all"; 200)
        ├─► POST .../regenerate/scenarios       (202; run is active again → back to poll/SSE)
        └─► POST .../scenarios/next-set         (202; run is active again → back to poll/SSE;
        │                                         allowed with scenarios still undecided)
        │
POST /v1/remediation {session_id, scenario_id} ─► 202 {remediation_id, session_id, scenario_id}
        │   needs: scenario accepted (controls may still be mapping: the plan job waits/maps them)
        ├─► GET .../treatment-plan/status        (poll)  ┐ until latest_version = the version you started
        └─► GET .../treatment-plan/events        (SSE)   ┘ and latest_status = done | failed | cancelled
        │
GET .../treatment-plan ─► plan (null until a version is done)
        │   ── both calls below need the scenario still accepted, else 409 scenario_not_accepted ──
        ├─► POST .../treatment-plan/review       {"decision": "accepted"}  (needs a done version, else 409 not_complete)
        └─► POST .../treatment-plan/regenerate   {}  (202; needs latest not queued/running → back to status/SSE)
```

`...` = `/v1/sessions/{session_id}/scenarios/{scenario_id}`. Accept starts no work. Regenerate and next-set do: until that job finishes (`session_status` back to `completed`), accept, regenerate and next-set all get `409 generation_in_progress`.

Service mapper (section 5), on its own:

```
POST /v1/service-mapper ─► 202 {mapping_id, status: "queued", generation: 1}
        │
        ├─► GET /v1/service-mapper/{id}/status   (poll)  ┐ until progress.overall =
        └─► GET /v1/service-mapper/{id}/events   (SSE)   ┘ done | failed | cancelled
        │
GET /v1/service-mapper/{id} ─► upstream_services[], downstream_services[] (take dependency_id from here)
        │
POST /v1/service-mapper/{id}/dependencies/decision {"accept": [...], "reject": [...]} ─► 200 (+ failed[])
```

## 3. Threat Scenario endpoints

### 3.1 `POST /v1/sessions`

Start a run for one asset. Returns `202` with the run's status.

Headers: identity headers, `Content-Type`, optional `Idempotency-Key`.

**Body** (`StartRunRequest`)

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `asset_id` | int 1..2147483647 | yes | asset owned by your entity |
| `supporting_system_id` | int or int[] | yes | one id or a list; at least one, no repeats. `supporting_system_ids` is also accepted. |
| `service_id` | int | no | service |
| `sector_id` | int | no | sector; must be the parent of `subsector_id` if both sent |
| `subsector_id` | int | no | sub-sector |

```json
{ "asset_id": 1166, "supporting_system_id": [1448, 1451] }
```

**Response** `202` (`200` on replay): `RunBoard`

| Field | Type | Meaning |
| --- | --- | --- |
| `session_id` | string | keep it |
| `entity_id` | int | |
| `asset_id` | int | |
| `asset_name` | string or null | |
| `user_id` | string or null | run owner |
| `session_status` | string | `active`, `completed`, `failed`, `cancelled` |
| `progress.threats` / `.scenarios` / `.controls` | string | `PENDING`, `RUNNING`, `COMPLETE`, `ERROR`, `CANCELLED` |
| `progress.overall` | string | what to do now: `pending`, `in_progress` (wait), `awaiting_review`, `awaiting_next_set`, `complete`, `error`, `cancelled` |
| `progress.timings.threats` / `.scenarios` / `.controls` | number or null | seconds, once the stage is complete |
| `progress.error_message` | object | `{}` when fine, else `{stage: why}` |
| `progress.error_reason` | string or null | AI outage that failed the run: `ai_down`, `ai_unreachable`, `ai_busy`, `ai_timed_out` |
| `progress.retrying` | object or null | waiting after an outage: `stage`, `reason`, `message`, `attempt`, `max_attempts`, `retry_at` |
| `progress.last_next_set` | object or null | `{outcome, requested, delivered}` |
| `progress.last_regen` | object or null | `{outcome, requested, replaced}` |
| `progress.scenario_count.total` | int or null | attack paths planned (null until threats found) |
| `progress.scenario_count.served` | int | scenarios written |
| `progress.scenario_count.remaining` | int or null | paths still to write |
| `progress.scenario_count.complete` | bool | nothing left to write |
| `progress.scenario_count.pending_review` / `.accepted` / `.rejected` | int | review counts |
| `updated_at` | datetime | |

`outcome` values: `running`, `complete`, `partial`, `failed`, `cancelled`.

A set can be `complete` with `delivered` below `requested`: a path an outage stopped keeps its `failed` card, and `progress.scenario_count.remaining` counts it, so the next set writes it again, up to 5 tries.

```json
{
  "session_id": "938cc176aede40daa154f7c572cd2494",
  "entity_id": 125,
  "asset_id": 1166,
  "asset_name": "Traffic Control Platform",
  "user_id": "jane.doe@example.com",
  "session_status": "active",
  "progress": {
    "threats": "PENDING", "scenarios": "PENDING", "controls": "PENDING",
    "overall": "pending",
    "timings": { "threats": null, "scenarios": null, "controls": null },
    "error_message": {},
    "error_reason": null,
    "retrying": null,
    "last_next_set": null,
    "last_regen": null,
    "scenario_count": {
      "total": null, "served": 0, "remaining": null, "complete": false,
      "pending_review": 0, "accepted": 0, "rejected": 0
    }
  },
  "updated_at": "2026-10-23T09:14:02.511000Z"
}
```

**Errors**

| Status | Reason | Fix |
| --- | --- | --- |
| 422 | — | fix `errors[]`: no systems, repeated system, id out of range, unknown field, sector not parent of sub-sector |
| 422 | `required_facts_missing` | a required asset/system property is not recorded; fix master data |
| 403 | `asset_not_owned` | use an asset of your entity |
| 403 | `system_not_linked` | `details.system_ids` are not linked to the asset |
| 404 | — | `service_id` / `sector_id` / `subsector_id` unknown |
| 409 | `active_session_exists` | the asset already has a run: use `details.active_session_id` |
| 409 | `idempotency_key_conflict` | key reused for another body, used by a manual plan request, or its run was deleted: use a new key |
| 409 | `intel_no_data` | external intelligence is on but empty; admin must import first |

### 3.2 `GET /v1/sessions/{session_id}`

The run's status. Poll this (or use SSE).

Headers: identity headers.

| Path param | Type | Meaning |
| --- | --- | --- |
| `session_id` | string ≤ 64 | from 3.1 |

**Response** `200`: `RunBoard` (same as 3.1).

**Errors**

| Status | Reason | Fix |
| --- | --- | --- |
| 404 | — | unknown session |
| 403 | — | another entity's session |

Note: scenarios are written first, controls after. A run whose scenarios are written reads `session_status: completed` with `progress.controls: RUNNING` while controls are mapped; `overall` is then already `awaiting_review` (or `awaiting_next_set`) when there is something to decide, else `in_progress`. You may accept and request plans then (see `controls_pending`, 3.5).

`overall` meanings: `awaiting_review` = some written scenario is still pending; `awaiting_next_set` = all written ones decided and paths remain; `complete` = nothing left to write or decide.

### 3.3 `GET /v1/sessions/{session_id}/events` (SSE)

Live status of the run. `text/event-stream`.

Headers: identity headers (see "SSE auth" below).

| Path param | Type | Meaning |
| --- | --- | --- |
| `session_id` | string ≤ 64 | |

**Events**

| `event:` | `data:` (JSON) | When |
| --- | --- | --- |
| `session.updated` | the `RunBoard` of 3.2 | once on connect, then on every change (identical bodies are not resent) |
| `session.deleted` | `{"session_id": "..."}` | once, when the run is deleted; then the stream closes |

- Each `session.updated` carries `retry: 3000` (reconnect after 3 s).
- When idle 15 s the server sends a comment line `: ping`.
- The server re-reads the status at least every 30 s.
- The stream does **not** end when the run completes. It ends when you close it, when the run is deleted, or when the API key is revoked (closes with no event).

**Errors** (normal HTTP responses, before the stream starts)

| Status | Reason | Fix |
| --- | --- | --- |
| 401 | — | send identity headers |
| 404 | — | unknown session |
| 403 | — | another entity's session |

**SSE auth.** The code reads auth **only from headers** (`X-API-Key`, `X-User-Id`, `X-Entity-Id`, `X-Tenant-Id`). No query parameter, no cookie. Browser `EventSource` cannot set headers, so it gets `401`. Use a `fetch`-based SSE reader (section 5) or a backend proxy that adds the headers.

### 3.4 `GET /v1/sessions/{session_id}/results`

The run's written scenarios, paged.

Headers: identity headers.

| Param | In | Type | Default | Meaning |
| --- | --- | --- | --- | --- |
| `session_id` | path | string ≤ 64 | | |
| `include_replaced` | query | bool | `false` | add older versions under each scenario's `replaced_scenarios` |
| `offset` | query | int ≥ 0 | 0 | |
| `limit` | query | int 1..500 | 50 | |

**Response** `200`: `RunResults`

| Field | Type | Meaning |
| --- | --- | --- |
| `session_id`, `entity_id`, `asset_id`, `asset_name`, `user_id` | | as in `RunBoard` |
| `progress` | object | as `RunBoard.progress` |
| `scenarios` | ScenarioView[] | current versions, in plan order: the newest of each path, plus any older version already accepted/rejected (so a regenerated accepted scenario shows both) |
| `total` | int | all matches, for paging |

**ScenarioView** (one item of `scenarios`)

| Field | Type | Meaning |
| --- | --- | --- |
| `scenario_id` | string | id to accept / regenerate / plan |
| `scenario` | object or null | null on a failure card |
| `scenario.threat_category` | string or null | |
| `scenario.contributing_categories` | string[] | |
| `scenario.threat_type` / `.threat_name` | string or null | |
| `scenario.supporting_systems_involved[]` | object[] | `supporting_system_id`, `supporting_system`, `is_entry_point`, `justification`, `is_applicable` |
| `scenario.scenario_title` | string or null | |
| `scenario.scenario_statement` | string or null | the scenario statement only (no "Why this threat applies") |
| `scenario.risk_statement` | string or null | |
| `scenario.assumptions` | string[] | each "assumes ... - not recorded in the platform"; [] when none |
| `scenario.route_status` | string or null | `STANDALONE` or `ASSUMED` |
| `scenario.also_applies` | string[] | other threats of the same kind on the same system |
| `threat.threat_id` | string or null | `lib:<id>` or `ai:<name>` |
| `threat.threat_category` / `.threat_category_id` | | |
| `threat.threat_type` / `.threat_type_id` / `.threat_name` | | |
| `threat.library_threat_type` / `.library_threat_name` | string or null | null if not in library |
| `threat.grounding_status` | string or null | `verified`, `unverified` |
| `threat.threat_catalogue_id` | int or null | |
| `threat.is_threat_type_ai_generated` | bool | |
| `threat.is_threat_ai_generated` | bool or null | |
| `threat.grounding_score` / `.score` | number or null | 0-100 |
| `threat.scope_rank` | int or null | 1 = most relevant |
| `actors[]` | object[] | `actor_id`, `actor_name`, `role`, `closest_match`, `selection`, `selection_reason` |
| `controls[]` | object[] | `control_id`, `control_code`, `itot`, `domain`, `control_name`, `control_description`, `map_rank`, `score`, `mapping_relevance`, `match_type` (`EXACT`/`NEAREST`/`GIVEN`), `match_reason`, `tier` |
| `accepted` | bool | |
| `replaces_accepted_version` | string or null | another accepted version of this path; accepting this one needs `replace_accepted` |
| `accepted_by` / `accepted_at` / `rejected_by` / `rejected_at` | | |
| `validation_status` | string | `ok`, `warning` |
| `validation_errors` | string[] | warnings; on a failure card, its reason |
| `validation_notes` | string[] | info only |
| `generation_epoch` | int or null | |
| `scenario_number` / `version` | int | version: 1, +1 per regenerate |
| `gen_started_at` / `gen_finished_at` / `gen_seconds` | | |
| `scenario_source` | string | `generated`, `manual` |
| `library` | object or null | hand-written only: `threat{name,status}`, `threat_type{name,status}`, `message` |
| `controls_unavailable` / `controls_mapped` / `controls_mapping_exhausted` | bool | `controls_mapping_exhausted`: background mapping failed. The sweep tries it again after 30 minutes while it has tries left, never after 5. Not a blocker: a plan request (4.1) or a plan regenerate (4.5) maps it again at once |
| `controls_mapping_exhaustion_reason` | string or null | |
| `replaced_scenarios` | ScenarioView[] | only with `include_replaced=true`, newest first |
| `scope` | object or null | `scope_key`, `scope_type` (`ASSET`/`SYSTEM`/`COMBINATION`), `supporting_system_ids`, `evidence` (always `[]`, kept for the response shape) |
| `actor` | string or null | acting attacker's name |
| `threat_source` / `threat_type_source` | string or null | `LIBRARY`, `AI_PROPOSED` |
| `review_flags` | string[] | `AI_PROPOSED_TYPE`, `AI_PROPOSED_THREAT`, `ASSUMED_ROUTE`, `VALIDATION_EXCEPTION`, `PLAN_CHECK`, `NEAREST_CONTROL`, `CONTROL_LIBRARY_GAP` |
| `control_match_status` | string or null | `EXACT`, `NEAREST_ONLY`, `CONTROL_LIBRARY_GAP`, `PENDING` |
| `session_id` | string | |
| `status` | string | `done`, `failed` (a failure card). After an outage (`failure.code` `unavailable`) the next set writes its path again, up to 5 tries. An AI outage's card (`failure.reason` set) can also be regenerated (3.6), even after 5 tries. Any other failed card's path is given up. Only `done` can be accepted or planned. |
| `failure` | object or null | failure card reason: `{code, message}`, plus `reason` (`ai_busy`, `ai_down`, `ai_unreachable`, `ai_timed_out`) when the AI did not answer. `code` `near_duplicate`: an outage's card whose path was then given up because it repeats another scenario of the session; the message names that scenario |
| `regenerate_error` | object or null | why the last regenerate kept this version |
| `created_at` | datetime | |
| `controls_status` | string or null | `queued`, `running`, `done`, `failed`, `cancelled` |
| `controls_error` | object or null | `{code, message, ...}` |
| `replaced_by` | string or null | newer version id |
| `evidence_mode` | string or null | |
| `evidence[]` | object[] | `n`, `ref`, `kind`, `source`, `title`, `url`, `facts`, `applicability`, `published`, `modified`, `fetched_at`, `searched_at`, `role`, `supports`, `mitigations` |
| `evidence_search` | object or null | |

```json
{
  "session_id": "938cc176aede40daa154f7c572cd2494",
  "entity_id": 125, "asset_id": 1166, "asset_name": "Traffic Control Platform",
  "user_id": "jane.doe@example.com",
  "progress": { "overall": "awaiting_review", "...": "as RunBoard.progress" },
  "scenarios": [
    {
      "scenario_id": "0c5dc06d-267d-5bb3-b9d3-1e027e1828e3",
      "scenario": {
        "threat_category": "Denial of Service",
        "contributing_categories": [],
        "threat_type": "Malware/Ransomware",
        "threat_name": "Ransomware with data theft extortion",
        "supporting_systems_involved": [
          { "supporting_system_id": 1448, "supporting_system": "SCADA Server", "is_entry_point": true,
            "justification": "Reachable from the corporate network.", "is_applicable": true },
          { "supporting_system_id": 1451, "supporting_system": "Historian", "is_entry_point": false,
            "justification": "Stores the data that is exfiltrated.", "is_applicable": true }
        ],
        "scenario_title": "Ransomware halts signal control",
        "scenario_statement": "An affiliate group phishes an operator ...",
        "risk_statement": "Signal control is lost for days ...",
        "assumptions": [],
        "route_status": "STANDALONE",
        "also_applies": []
      },
      "threat": { "threat_id": "lib:812", "threat_type": "Malware/Ransomware", "grounding_status": "verified", "...": "..." },
      "actors": [ { "actor_id": 31, "actor_name": "Ransomware affiliate", "role": "acting", "closest_match": false } ],
      "controls": [
        { "control_id": 446, "control_code": "CID-0446", "itot": "IT\\OT", "domain": "Backup",
          "control_name": "Offline backups", "control_description": "...", "map_rank": 1,
          "score": 81.2, "mapping_relevance": 81.2, "match_type": "EXACT", "match_reason": "...", "tier": "strong" }
      ],
      "accepted": false,
      "validation_status": "ok",
      "version": 1,
      "status": "done",
      "controls_status": "done",
      "...": "other ScenarioView fields"
    }
  ],
  "total": 6
}
```

**Errors**

| Status | Reason | Fix |
| --- | --- | --- |
| 404 / 403 | — | as 3.2 |
| 422 | — | `offset` / `limit` out of range |

### 3.5 `POST /v1/sessions/{session_id}/accept`

Accept scenarios. Only an accepted scenario can get a remediation plan.

When: any time `session_status` is not `active` (no job queued/running). It does not wait for every path to be written: accept the set you have, then call next-set (3.7) for more, in either order.

Headers: identity headers, `Content-Type`.

| Path param | Type |
| --- | --- |
| `session_id` | string ≤ 64 |

**Body** (`AcceptRequest`), the TSG v1 format:

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `mode` | `all` / `subset` / `none` | yes (v1 body) | `all`: accept every scenario; `subset`: accept `scenario_ids`; `none`: accept nothing |
| `scenario_ids` | string[] (1-50, unique, each ≤ 64) | with `subset` only | what to accept; left out with `all` and `none` |
| `replace_accepted` | bool | no (default `false`) | with `subset`: let a newer version replace an already accepted version of the same attack path |

```json
{ "mode": "subset", "scenario_ids": ["0c5dc06d-267d-5bb3-b9d3-1e027e1828e3"] }
```
```json
{ "mode": "all" }
```
```json
{ "mode": "subset", "scenario_ids": ["0c5dc06d-267d-5bb3-b9d3-1e027e1828e3"], "replace_accepted": true }
```
```json
{ "mode": "none" }
```

`{"mode": "none"}` decides nothing: `200` with four empty lists, and every scenario stays pending. With `mode`,
`scenario_ids` is sent only with `subset` (a list, not `"all"`), and so is `replace_accepted: true`. Anything else →
`422`. Swagger's example list shows each of these bodies.

**The v2 body is also accepted** (no `mode`); the response is the same `AcceptResult`:

| v2 body | Same as |
| --- | --- |
| `{"scenario_ids": [...]}` (+ `"replace_accepted": true`) | `{"mode": "subset", "scenario_ids": [...]}` (+ `"replace_accepted": true`) |
| `{"scenario_ids": "all"}` | `{"mode": "all"}` |

Notes for a TSG v1 client:
- v1 ignored unknown fields; here an unknown field, an id over 64 characters and a repeated id are each a `422`.
- The response is `AcceptResult` (below), not v1's `{session_id, user_id, status, accepted_count, replaced[{scenario_id, replaced_scenario_id}]}`: count `accepted`, and `replaced` lists the old ids only.
- The error body is the one in 1 (Error body), not v1's `{error_code, message, details}`: read `reason` and `errors[]`.
- Reasons changed: v1's `duplicate_identity` is now `duplicate_version`; an already rejected id was a `404`, now a `409 scenarios_not_decidable` with `already_rejected`. v1's `session_completed`, `session_cancelled`, `generation_abandoned` and `asset_busy` are gone; `run_failed`, `run_cancelled` and `nothing_to_accept` are new.
- `{"mode": "none"}` writes nothing: no decision and no audit entry.

**Response** `200`: `AcceptResult`

| Field | Type | Meaning |
| --- | --- | --- |
| `accepted` | string[] | accepted now or before (a repeat lists them again) |
| `replaced` | string[] | other versions sent back to `pending` by `replace_accepted` |
| `skipped[]` | object[] | `{scenario_id, reason}`; reason `duplicate_version`, `library_inactive`, `changed_concurrently` |
| `controls_pending` | string[] | accepted, controls still being mapped |

```json
{
  "accepted": ["0c5dc06d-267d-5bb3-b9d3-1e027e1828e3"],
  "replaced": [],
  "skipped": [],
  "controls_pending": []
}
```

**Errors**

| Status | Reason | Fix |
| --- | --- | --- |
| 422 | — | empty list, > 50 ids, repeated id, unknown field, a v1 `mode` rule broken |
| 409 | `generation_in_progress` | a start, regenerate or next-set job is queued/running: wait until `session_status` is not `active` |
| 409 | `run_failed` / `run_cancelled` | the run failed / was cancelled before any scenario; start a new run |
| 404 / 403 | — | as 3.2 |
| 409 | `scenarios_not_decidable` | see `errors[]` `{scenario_id, reason}`: `unknown`, `failure_scenario`, `already_rejected`, `duplicate_version` (two versions of one path sent), `library_inactive` |
| 409 | `duplicate_version` | another version of the path is accepted: resend with `replace_accepted: true` |
| 409 | `nothing_to_accept` | `"all"` with no written, non-rejected scenario |

Notes:
- `"all"` must be the plain string: `{"scenario_ids": "all"}`. `["all"]` is a list with an id `all` → `409 scenarios_not_decidable` (`unknown`).
- `"all"` never replaces an accepted version: such scenarios land in `skipped` as `duplicate_version`. `replace_accepted` has no effect with `"all"`.
- `replace_accepted: true`: the old accepted version goes back to `pending` (listed in `replaced`); the new one becomes accepted. Without it → `409 duplicate_version`. The old version's plan, if any, becomes read-only (review/regenerate → `409 scenario_not_accepted`); request a new plan for the new `scenario_id` (4.1).
- Decisions are final: an accepted scenario cannot be rejected, a rejected one cannot be accepted. Regenerate for a new version.
- `controls_pending` is no blocker: you can request the plan now (4.1); the plan job maps the controls first.
- The same holds when `controls_mapping_exhausted` is `true`: the plan job maps them itself. The plan never waits forever: it ends `done`, or `failed` (e.g. `control_library_empty`, or the mapping keeps failing) and you retry with regenerate (4.5).

### 3.6 `POST /v1/sessions/{session_id}/regenerate/scenarios`

Rewrite chosen scenarios as new versions, in the background. A failure card whose `failure.reason` is an AI outage (`ai_busy`, `ai_down`, `ai_unreachable`, `ai_timed_out`) is written again in its place: same `scenario_id`, version 1.

Headers: identity headers, `Content-Type`.

| Path param | Type |
| --- | --- |
| `session_id` | string ≤ 64 |

**Body** (`ScenarioIdsRequest`)

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `scenario_ids` | string[] (1-50, unique, each ≤ 64) | yes | current versions to rewrite, or AI-outage failure cards; `"all"` is not allowed |

```json
{ "scenario_ids": ["0c5dc06d-267d-5bb3-b9d3-1e027e1828e3"] }
```

**Response** `202`: `RunActionStarted`

| Field | Type | Meaning |
| --- | --- | --- |
| `session_id` | string | |
| `user_id` | string or null | run owner (not the caller) |
| `status` | string | `regenerating` |
| `epoch` | int | the run's new job number |

```json
{ "session_id": "938cc176aede40daa154f7c572cd2494", "user_id": "jane.doe@example.com", "status": "regenerating", "epoch": 3 }
```

**Errors**

| Status | Reason | Fix |
| --- | --- | --- |
| 422 | — | empty, > 50, repeated id, `"all"`, unknown field |
| 409 | `generation_in_progress` | wait for the current job |
| 409 | `run_failed` / `run_cancelled` | start a new run |
| 409 | `scenarios_not_regenerable` | `errors[]` `{scenario_id, reason}`: `unknown`, `failure_scenario` (a failure card that names no AI outage: it is not rewritten), `hand_written`, `version_not_current` (regenerate the newest), `duplicate_version` |
| 409 | `asset_busy` | asset has another active run (`details.active_session_id`) |
| 409 | `run_being_deleted` | the run is being deleted |
| 409 | `intel_no_data` | external intelligence empty |

Notes:
- When: `session_status` not `active`. While the job runs the run is `active` again: accept, next-set and another regenerate → `409 generation_in_progress`.
- Done when `session_status` leaves `active` and `progress.last_regen.outcome` is no longer `running` (`complete`, `partial`, `failed`, `cancelled`). `RunBoard` has no `epoch` field.
- The old version stays readable via `include_replaced=true`. If the new version breaks a rule, the old one stays current and gets `regenerate_error`.
- Regenerating an accepted scenario: the old version stays accepted (its plan untouched) and stays in `results`; the new one is `pending` with `replaces_accepted_version` set. Accepting it needs `replace_accepted: true` (3.5).
- Pending and rejected scenarios can be regenerated too.
- A failure card from an AI outage can always be regenerated, also after its path was given up after 5 tries: the path is written again in place. No new version is made and no spare path is pulled, so the run may end one scenario over its target. If the AI fails again on the last try, the card stays failed with its reason, `progress.last_regen` ends `partial`, and the run is not failed. If the path now repeats another scenario of the session, it is given up with no AI call and the card's `failure` becomes `{code: near_duplicate, message}` with no reason, so it is not regenerated again.

### 3.7 `POST /v1/sessions/{session_id}/scenarios/next-set`

Write more scenarios from attack paths not yet written. No body.

Headers: identity headers.

| Path param | Type |
| --- | --- |
| `session_id` | string ≤ 64 |

**Response** `202`: `RunActionStarted` (fields as 3.6). `status`:
- `generating`: a new set is being written (`epoch` +1).
- `mapping_controls`: no path left, but controls stopped by a cancel were resumed (`epoch` unchanged).

```json
{ "session_id": "938cc176aede40daa154f7c572cd2494", "user_id": "jane.doe@example.com", "status": "generating", "epoch": 2 }
```

**Errors**

| Status | Reason | Fix |
| --- | --- | --- |
| 409 | `generation_in_progress` | wait |
| 409 | `run_failed` / `run_cancelled` | start a new run |
| 409 | `nothing_left` | every selected path is written |
| 409 | `target_reached` | the rest were left out by `TOTAL_SCENARIO_COUNT` |
| 409 | `scenarios_abandoned` | every remaining path was given up |
| 409 | `asset_busy` | another active run on the asset |
| 409 | `run_being_deleted` | |
| 409 | `intel_no_data` | |

Notes:
- When: `session_status` not `active`. You do **not** have to decide the current set first: it is allowed during `awaiting_review` too (`awaiting_next_set` only means "everything written is decided and paths remain"). `progress.scenario_count.remaining` > 0 tells you paths are left.
- `generating`: the run is `active` until the set is written; accept/regenerate → `409 generation_in_progress` meanwhile. Done when `session_status` leaves `active` and `progress.last_next_set.outcome` is no longer `running`.

## 4. Remediation endpoints

Every route below except 4.1 is under `/v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan`. Path params for each of them:

| Path param | Type | Meaning |
| --- | --- | --- |
| `session_id` | string ≤ 64 | the run (for a manual scenario: the `session_id` returned by 4.1) |
| `scenario_id` | string ≤ 64 | the scenario |

Each of them: no plan for that scenario in that run → `404`; another entity's → `403`.

Not covered here: `POST /v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan/cancel` (stop a version being written), `GET /v1/sessions/{session_id}/treatment-plans` (a run's plans) and `GET /v1/entities/{listed_entity_id}/treatment-plans` (an entity's plans).

### 4.1 `POST /v1/remediation`

Request a remediation plan for one scenario: generated (`is_manual=false`) or hand-written (`is_manual=true`). Returns `202` at once; the plan is written in the background.

Headers: identity headers, `Content-Type`; `Idempotency-Key` required when `is_manual=true`.

**Body** (`PlanRequest`)

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `is_manual` | bool | yes | `false`: existing accepted scenario; `true`: send `manual_scenario` |
| `session_id` | string ≤ 64 | only `is_manual=false` | run holding the scenario. Must be absent for `true`. |
| `scenario_id` | string ≤ 64 | only `is_manual=false` | accepted scenario. Must be absent for `true`. |
| `manual_scenario` | object | only `is_manual=true` | see below. Must be absent for `false`. |
| `supporting_systems_applicable_to_risk` | int[] | no | supporting systems of the scenario's asset the risk applies to. `null`, `""` or `[]` (or left out): the risk is on the asset itself, on no supporting system. A repeat is dropped. |
| `supporting_systems_applicable_to_existing_controls` | int[] | no | supporting systems of the asset the existing controls are on, one list for all of them. `null`, `""` or `[]` (or left out): they are on no supporting system. Only the systems the risk applies to count; a repeat is dropped. |
| `existing_controls` | array (≤ 50) | no | each item a string or a control object (below); it names the control only |
| `existing_controls[].control_id` | int | one of id/code/name | library id |
| `existing_controls[].control_code` | string ≤ 100 | one of id/code/name | e.g. `CID-0446` |
| `existing_controls[].control_name` | string ≤ 500 | one of id/code/name | |
| `likelihood_rating` | number ≥ 0 | no | ≤ 15 digits, ≤ 4 decimals |
| `impact_rating` | number ≥ 0 | no | same |
| `final_risk_rating` | number ≥ 0 | no | stored as sent |
| `risk_level` | string ≤ 200 | no | e.g. `Critical`, `High` |
| `risk_identification_date` | datetime | no | naive = UTC |
| `risk_owner` | string ≤ 200 | no | |
| `impacted_business_division` | string ≤ 200 | no | |
| `existing_controls_all_subsystems_justification` | string ≤ 1000 | no | |
| `mitigation_start_date` | date | no, but both or neither | `YYYY-MM-DD` (a date-time's date part is used) |
| `mitigation_end_date` | date | no, but both or neither | on or after start |

A string in `existing_controls` is a name, and also a code if it looks like one (`CID-0446`). An empty string `""` in an optional field means "not given".

**`manual_scenario`** (`ManualScenario`)

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `asset_id` | int | yes | asset of your entity |
| `entity_id` | int | yes | must equal `X-Entity-Id` (else 403) |
| `supporting_system_id` | int or int[] | yes | as in 3.1 |
| `service_id` / `sector_id` / `subsector_id` | int | no | as in 3.1 |
| `threat_type_id` / `threat_type_name` | int / string ≤ 300 | at least one | library threat type |
| `threat_id` / `threat_name` | int / string ≤ 500 | at least one | library threat |
| `threat_category_id` / `threat_category_name` | int / string ≤ 200 | no | STRIDE category; default: the threat's |
| `threat_scenario` | string 1-4000 | yes | scenario statement |
| `risk_statement` | string 1-4000 | yes | |
| `mapped_controls` | array (≤ 50) of string or `{control_id, control_code, control_name}` | no | none → controls are matched automatically |

`scenario_title` is refused (422).

Generated scenario:

```json
{
  "is_manual": false,
  "session_id": "938cc176aede40daa154f7c572cd2494",
  "scenario_id": "0c5dc06d-267d-5bb3-b9d3-1e027e1828e3",
  "supporting_systems_applicable_to_risk": [1448, 1449, 1450, 1451],
  "supporting_systems_applicable_to_existing_controls": [1449, 1450],
  "existing_controls": [
    { "control_code": "CID-0446", "control_name": "Risk Assessment" },
    { "control_code": "CID-0995", "control_name": "Identity Threat Detection & Response" }
  ],
  "likelihood_rating": 4,
  "impact_rating": 5,
  "final_risk_rating": 20,
  "risk_level": "Critical",
  "risk_identification_date": "2026-10-20T09:30:00Z",
  "risk_owner": "Head of OT Operations",
  "impacted_business_division": "Traffic Operations",
  "mitigation_start_date": "2026-11-01",
  "mitigation_end_date": "2027-01-31"
}
```

Here the risk is on all four systems of asset 1166 and the existing controls are on 1449 and 1450. CID-0446 is an IT\OT control, so it counts on all four: `partially_implemented`, still needed on 1448 and 1451 (the plan in 4.3).

Hand-written scenario (with `Idempotency-Key`):

```json
{
  "is_manual": true,
  "manual_scenario": {
    "asset_id": 1166,
    "entity_id": 125,
    "supporting_system_id": [1448, 1451],
    "threat_category_name": "Denial of Service",
    "threat_type_name": "Malware/Ransomware",
    "threat_name": "Ransomware with data theft extortion",
    "threat_scenario": "An affiliate phishes an operator, reaches the SCADA server and encrypts it after stealing historian data.",
    "risk_statement": "Signal control is lost for days and stolen data is used for extortion.",
    "mapped_controls": [{ "control_code": "CID-0446", "control_name": "Risk Assessment" }]
  },
  "supporting_systems_applicable_to_risk": [1448, 1451],
  "supporting_systems_applicable_to_existing_controls": [1448, 1451],
  "existing_controls": [
    { "control_code": "CID-0995", "control_name": "Identity Threat Detection & Response" }
  ]
}
```

**Response** `202` (`200` on manual replay; `202` when that replay writes an outage-failed version again): `PlanStarted`

| Field | Type | Meaning |
| --- | --- | --- |
| `remediation_id` | string | plan id |
| `session_id` | string | keep: used in every treatment-plan path (new run id for a manual scenario) |
| `scenario_id` | string | keep: used in every treatment-plan path |
| `version` | int | `1` |
| `status` | string | `queued` (on replay: the current status) |
| `is_manual` | bool | the scenario is hand-written |
| `replayed` | bool | `true` when this key had already saved this scenario; then `version`/`status` are the plan's latest, not version 1; when the plan had failed for an outage, the answer is `202` and the same version is queued again |

```json
{
  "remediation_id": "5f2b9c1e7a4d4e0b9c3a8d6f1e2b4c7a",
  "session_id": "938cc176aede40daa154f7c572cd2494",
  "scenario_id": "0c5dc06d-267d-5bb3-b9d3-1e027e1828e3",
  "version": 1,
  "status": "queued",
  "is_manual": false,
  "replayed": false
}
```

**Errors**

| Status | Reason | Fix |
| --- | --- | --- |
| 422 | — | field errors: an id in either supporting system list that is not a positive integer; `supporting_system_ids` inside an existing control (an unknown field); an old flag (see the notes); unknown field; kinds mixed; window dates unpaired or reversed; existing control with no id/code/name |
| 422 | — | `is_manual=true` without `Idempotency-Key` (field `header.Idempotency-Key`) |
| 422 | — | `supporting_systems_applicable_to_risk[n]` or `supporting_systems_applicable_to_existing_controls[n]` is not a supporting system of the scenario's asset (`n` is the place in the list as sent, repeats counted; the message lists the asset's systems) |
| 422 | — / `type_mismatch` | manual: threat, type or category does not match the library |
| 422 | — | manual: `mapped_controls` not found in the library |
| 403 | — | scenario of another entity; `manual_scenario.entity_id` ≠ `X-Entity-Id` |
| 403 | `asset_not_owned` / `system_not_linked` | manual: asset or systems not yours |
| 404 | — | scenario unknown, or not in `session_id` |
| 409 | `scenario_not_accepted` | accept it first (3.5) |
| 409 | `plan_already_exists` | one plan per scenario, even if its version 1 failed: regenerate it (4.5); id in `details.remediation_id` |
| 409 | `idempotency_key_conflict` | key reused for another body |
| 409 | `control_library_empty` | control library not loaded; admin issue |
| 409 | `run_being_deleted` | |
| 503 | `actor_library_empty` | manual: threat library has no actor; admin issue |

Notes:
- Both supporting system lists are optional, and are sent once for the whole request (never per control). An id that is sent must be a supporting system of the scenario's asset: for a generated scenario, the run's asset systems as frozen at its start; for a hand-written one, the asset's systems in SQL. An existing-controls system outside the risk list is accepted; only the overlap counts.
- Every existing control is on the systems of `supporting_systems_applicable_to_existing_controls`. Over the affected systems of its own type (an IT control on the IT systems, an OT one on the OT systems): on all → `implemented`; on some → `partially_implemented` (still needed on the rest); on none, or not an existing control → `not_implemented`.
- With a risk list, the existing-controls list empty → every control is `not_implemented`, needed on every affected system (with the risk list empty too, see the next bullet).
- The risk list empty → the risk is on the asset itself: an existing control is `implemented`, any other is `not_implemented`, `protected_systems` and `required_systems` are `[]`, and the plan's actions name no supporting system.
- `plan.applicable_to_all_subsystems` is `Yes` only when the risk list names every supporting system of the asset.
- `is_manual` is a normal boolean.
- The old flags are refused: `all_supporting_systems_applicable`, `existing_controls_all_supporting_system_applicable` and `existing_controls_all_subsystems`. Sending one, with any value (`0`, `1`, a list, `null`, `""`), is a 422 on that field (for example `body.all_supporting_systems_applicable`). The message names the list to send instead: `supporting_systems_applicable_to_risk` for the first, `supporting_systems_applicable_to_existing_controls` for the other two. When the body also has other mistakes, only the old flags are reported; the others show on the next try. A plan stored before the two lists still regenerates as before, from its stored flags.
- `is_manual=true`: do not send `session_id` / `scenario_id` (422); TSG creates them and returns them.

**How TSG uses the two lists.** Example: the asset has four supporting systems, 1 historian, 2 workstation, 3 SCADA and 4 firewall, all of one type (so every control counts on all four). The table shows what TSG decides for an existing control (one listed in `existing_controls`); a control that is not an existing control is always `not_implemented`, needed on every system the risk applies to.

| `..._to_risk` | `..._to_existing_controls` | What TSG decides for an existing control |
| --- | --- | --- |
| `[1, 2, 3, 4]` | `[2, 3]` | the risk is on all four; the control is on 2 and 3 → `partially_implemented`, `protected_systems` 2 and 3, still needed on 1 and 4 (`required_systems`) |
| `[1, 2, 3, 4]` | `[1, 2, 3, 4]` | on every system the risk applies to → `implemented` |
| `[1, 2, 3, 4]` | `[]` | on no system → `not_implemented`, needed on 1, 2, 3 and 4 |
| `[1, 2]` | `[2, 3]` | only 2 counts (3 is outside the risk: accepted, ignored) → `partially_implemented`, still needed on 1 |
| `[]` | any | the risk is on the asset itself → `implemented`, no systems listed; the actions name no system |
| `[1, 5]` | `[2]` | 422 `body.supporting_systems_applicable_to_risk[1]`: 5 is not a supporting system of the asset |

### 4.2 `GET /v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan/status`

Cheap poll of the plan.

Headers: identity headers.

**Response** `200`: `RemediationStatus`

| Field | Type | Meaning |
| --- | --- | --- |
| `remediation_id` | string | |
| `entity_id` | int | |
| `scenario_id` / `session_id` | string | |
| `latest_version` | int | newest version number |
| `latest_status` | string | `queued`, `running`, `done`, `failed`, `cancelled` |
| `accepted_version` | int or null | the accepted version |
| `decision` | string | `pending`, `accepted`, `rejected` |
| `progress.generation` | string | = `latest_status` |
| `progress.review` | string | = `decision` |
| `progress.overall` | string | `failed`, `cancelled`, `generating`, `awaiting_review`, `accepted`, `rejected` |
| `progress.retrying` | object or null | waiting after an outage: `stage` (null), `reason`, `message`, `attempt`, `max_attempts`, `retry_at` |
| `error` | object or null | `{code, message}` of the latest version |
| `updated_at` | datetime | |

```json
{
  "remediation_id": "5f2b9c1e7a4d4e0b9c3a8d6f1e2b4c7a",
  "entity_id": 125,
  "scenario_id": "0c5dc06d-267d-5bb3-b9d3-1e027e1828e3",
  "session_id": "938cc176aede40daa154f7c572cd2494",
  "latest_version": 1,
  "latest_status": "done",
  "accepted_version": null,
  "decision": "pending",
  "progress": { "generation": "done", "review": "pending", "overall": "awaiting_review", "retrying": null },
  "error": null,
  "updated_at": "2026-10-23T09:41:17.204000Z"
}
```

**Errors**

| Status | Reason | Fix |
| --- | --- | --- |
| 404 | — | no plan requested for this scenario in this run |
| 403 | — | another entity's plan |

### 4.3 `GET /v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan`

Read the plan: the accepted version, else the newest finished one.

Headers: identity headers.

| Query param | Type | Default | Meaning |
| --- | --- | --- | --- |
| `include_history` | bool | `false` | add `versions[]` |

**Response** `200`: `RemediationResult` = every `RemediationStatus` field (4.2) plus:

| Field | Type | Meaning |
| --- | --- | --- |
| `shown_version` | int or null | version shown; null until one is done |
| `plan` | object or null | null until a version is done |
| `plan.title` | string | |
| `plan.treatment_strategy` | string | `Mitigate` |
| `plan.control_coverage` | string | `gaps`, `covered` |
| `plan.controls_to_be_implemented[]` | object[] | `control_id`, `control_code`, `control_name`, `control_type` (`preventive`/`detective`/`corrective`/`compensating`), `domain`, `description`, `priority` (`Critical`/`High`/`Medium`/`Low`), `implementation_status`, `required_systems[{supporting_system_id, name}]` |
| `plan.actions[]` | object[] | `action_id`, `action`, `owner`, `priority`, `dependencies`, `depends_on[]`, `duration_days`, `start_date`, `end_date` (null without window), `timeline`, `implements_controls[]`, `supporting_systems[{supporting_system_id, name}]`, `success_criteria` |
| `plan.action_plan` | string | narrative |
| `plan.mitigation_owner` | string | |
| `plan.applicable_to_all_subsystems` | `Yes`/`No` or null | `Yes` only when `supporting_systems_applicable_to_risk` names every supporting system of the asset |
| `plan.critical_path` | string[] | action ids |
| `plan.mitigation_timeline` / `.mitigation_timeline_days` / `.mitigation_end_date_planned` | | |
| `plan.risk_identification_date` / `.risk_owner` / `.impacted_business_division` | | from the request |
| `plan.prompt_version` | string | the prompt that wrote the version, e.g. `remediation-1` |
| `plan.control_assessment[]` | object[] | `control_id`, `control_code`, `control_name`, `domain`, `match`, `implementation_status`, `recommended`, `protected_systems[]`, `required_systems[]`, `validation` (`retained`/`replaced`/`flagged_for_review`), `validation_reason`, `replaced_by`, `replaces[]` |
| `plan.unresolved_gaps[]` | object[] | `kind` (`flagged_control`/`no_validated_control`/`uncovered_risk`), `control_code`, `detail` |
| `warnings` | string[] | checks on the shown version; never a block |
| `scenario` | object or null | `scenario_id`, `title`, `statement`, `risk_statement`, `category`, `threat`, `actors[{name, role}]`, `controls[]` |
| `register_data` | object | the register fields as sent in 4.1 (ratings as strings; each system list with each id once, `[]` when not sent) |
| `versions` | array or null | only with `include_history=true`: `version`, `status`, `decision`, `decided_by`, `decided_at`, `review_comment`, `requested_by`, `requested_at`, `completed_at`, `error`, `plan`, `warnings` |

`implementation_status`: `implemented`, `partially_implemented`, `not_implemented`, `unverified`.

```json
{
  "remediation_id": "5f2b9c1e7a4d4e0b9c3a8d6f1e2b4c7a",
  "entity_id": 125,
  "scenario_id": "0c5dc06d-267d-5bb3-b9d3-1e027e1828e3",
  "session_id": "938cc176aede40daa154f7c572cd2494",
  "latest_version": 1, "latest_status": "done", "accepted_version": null, "decision": "pending",
  "progress": { "generation": "done", "review": "pending", "overall": "awaiting_review", "retrying": null },
  "error": null,
  "updated_at": "2026-10-23T09:41:17.204000Z",
  "shown_version": 1,
  "plan": {
    "title": "Backup Remediation",
    "treatment_strategy": "Mitigate",
    "control_coverage": "gaps",
    "controls_to_be_implemented": [
      { "control_id": 446, "control_code": "CID-0446", "control_name": "Offline backups",
        "control_type": "corrective", "domain": "Backup",
        "description": "Extend offline backups to the command centre and incident platforms.",
        "priority": "High", "implementation_status": "partially_implemented",
        "required_systems": [ { "supporting_system_id": 1448, "name": "Enterprise Command & Control Centre Platform" },
                              { "supporting_system_id": 1451, "name": "Incident Detection & Response Platform" } ] }
    ],
    "actions": [
      { "action_id": "A1", "action": "Extend offline backups to the command centre and incident platforms", "owner": "OT Operations",
        "priority": "High", "dependencies": "", "depends_on": [], "duration_days": 10,
        "start_date": "2026-11-01", "end_date": "2026-11-10", "timeline": "2026-11-01 → 2026-11-10 (10 days)",
        "implements_controls": ["CID-0446"],
        "supporting_systems": [ { "supporting_system_id": 1448, "name": "Enterprise Command & Control Centre Platform" },
                                { "supporting_system_id": 1451, "name": "Incident Detection & Response Platform" } ],
        "success_criteria": "Weekly restore test passes." }
    ],
    "action_plan": "...",
    "mitigation_owner": "Head of OT Operations",
    "applicable_to_all_subsystems": "Yes",
    "critical_path": ["A1"],
    "mitigation_timeline": "2026-11-01 → 2026-11-10 (10 days, critical path A1)",
    "mitigation_timeline_days": 10,
    "mitigation_end_date_planned": "2026-11-10",
    "risk_identification_date": "2026-10-20T09:30:00Z",
    "risk_owner": "Head of OT Operations",
    "impacted_business_division": "Traffic Operations",
    "prompt_version": "remediation-1",
    "control_assessment": [],
    "unresolved_gaps": []
  },
  "warnings": [],
  "scenario": { "scenario_id": "0c5dc06d-267d-5bb3-b9d3-1e027e1828e3", "title": "Ransomware halts signal control", "...": "..." },
  "register_data": { "risk_level": "Critical", "final_risk_rating": "20", "...": "..." },
  "versions": null
}
```

**Errors**

| Status | Reason | Fix |
| --- | --- | --- |
| 404 | — | no plan for this scenario in this run |
| 403 | — | another entity's plan |

### 4.4 `POST /v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan/review`

Accept or reject one finished version.

Headers: identity headers, `Content-Type`.

**Body** (`ReviewRequest`)

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `decision` | `"accepted"` / `"rejected"` | yes | |
| `version` | int ≥ 1 | no | omitted = the newest finished (`done`) version |
| `comment` | string ≤ 2000 | no | stored with the decision |

```json
{ "decision": "accepted", "version": 2, "comment": "Matches the register." }
```

**Response** `200`: `RemediationStatus` (4.2).

**Errors**

| Status | Reason | Fix |
| --- | --- | --- |
| 422 | — | bad `decision`, `version` < 1, unknown field |
| 404 / 403 | — | as 4.2 |
| 404 | `version_not_found` | no such version |
| 409 | `not_complete` | version not `done`, or no version is done yet |
| 409 | `scenario_not_accepted` | plan is read-only |
| 409 | `changed_concurrently` | another decision landed: read again and retry |

Notes: accepting a version makes it the plan; an earlier accepted version goes back to pending. Rejecting the accepted version clears `accepted_version` (no plan is accepted then). Any `done` version can be reviewed by `version`, even while a newer one is still being written. Repeating the same decision changes nothing and returns `200`.

### 4.5 `POST /v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan/regenerate`

Write a new version (2, 3, ...) from the same register data. Earlier versions stay. If the latest version failed for an outage (`error.code` `unavailable`), regenerate writes that same version again instead: `version` is the latest number, no version is added, and `version_limit_reached` does not apply. Any other failure, or a cancel, gets a new version.

Headers: identity headers, `Content-Type`.

**Body** (`RegenerateRequest`): must be `{}`. Any field → 422.

```json
{}
```

**Response** `202`: `PlanRequested`

| Field | Type | Meaning |
| --- | --- | --- |
| `remediation_id` / `session_id` / `scenario_id` | string | |
| `version` | int | new version number (the same number when an outage-failed version is written again) |
| `status` | string | `queued` |

```json
{
  "remediation_id": "5f2b9c1e7a4d4e0b9c3a8d6f1e2b4c7a",
  "session_id": "938cc176aede40daa154f7c572cd2494",
  "scenario_id": "0c5dc06d-267d-5bb3-b9d3-1e027e1828e3",
  "version": 2,
  "status": "queued"
}
```

**Errors**

| Status | Reason | Fix |
| --- | --- | --- |
| 422 | — | body not `{}` |
| 404 / 403 | — | as 4.2 |
| 409 | `generation_in_progress` | latest version still queued/running: wait for `done`/`failed`/`cancelled` |
| 409 | `version_limit_reached` | max versions (`REGENERATIONS_MAX_VERSION_COUNT`, default 10) reached, never when the latest version failed for an outage (that one is written again in place): final, reviewing does not free a slot. Accept one of the existing versions |
| 409 | `scenario_not_accepted` | scenario no longer accepted: plan is read-only |
| 409 | `control_library_empty` | admin issue |
| 409 | `run_being_deleted` | |

Notes:
- Regenerating an **accepted** plan keeps `decision: accepted`: `overall` goes `generating` → `accepted`, never `awaiting_review`. `GET .../treatment-plan` (4.3) keeps showing the accepted version until you accept the new one (review, 4.4: `{"decision": "accepted", "version": N}`). Detect the new version by `latest_version`/`latest_status` in 4.2, not by `overall`.
- A failed or cancelled latest version is retried with regenerate, never with a new `POST /v1/remediation`; an outage failure is retried in place as the same version.

### 4.6 `GET /v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan/events` (SSE)

Live status of the plan. `text/event-stream`. Defined in `scenario.py`.

Headers: identity headers (same SSE auth as 3.3: headers only).

**Events**

| `event:` | `data:` (JSON) | When |
| --- | --- | --- |
| `remediation.updated` | the `RemediationStatus` of 4.2 | once on connect, then on every change |
| `remediation.deleted` | `{"remediation_id": "..."}` | once, when its run is deleted; then the stream closes |

`retry: 3000`, `: ping` every 15 s idle, re-read every 30 s, same end conditions as 3.3 (not on `done`).

**Errors** (before the stream starts)

| Status | Reason | Fix |
| --- | --- | --- |
| 401 | — | send identity headers |
| 404 | — | no plan requested yet for this scenario: call 4.1 first |
| 403 | — | another entity's plan |

## 5. Service Mapper endpoints

Describe one service: TSG finds the services it depends on (**upstream**) and the services that depend on it (**downstream**), from the onboarding catalog and the AI. A reviewer then accepts or rejects each one. There is no review of the mapping as a whole: the review is complete when every service has a decision (`progress.relationships.pending` is `0`, 5.2).

Not covered here: `GET /v1/service-mapper` (list an entity's mappings) and `GET /v1/entities/{listed_entity_id}/services` (the entity's catalog services).

Regenerate, in short (`POST /v1/service-mapper/{mapping_id}/regenerate`, a new generation): `202` starts the next generation of a `done` or `failed` mapping; `409 generation_in_progress` while one is queued or running. The same `Idempotency-Key` answers `200` with the generation it started, or `202` with a new try when that generation failed for an outage and is still the latest.

Path param for every `/v1/service-mapper/{mapping_id}` route:

| Path param | Type | Meaning |
| --- | --- | --- |
| `mapping_id` | string ≤ 64 | from 5.1 |

Every such route: unknown mapping (or another tenant's) → `404` (`No such mapping.`); another entity's → `403`.

### 5.1 `POST /v1/service-mapper`

Start a mapping for one service. Returns `202` at once; the services are found in the background.

Headers: identity headers, `Content-Type`, optional `Idempotency-Key`.

**Body** (`CreateMappingRequest`)

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `service_name` | string 1-255 | yes | the service to map |
| `service_description` | string 1-4000 | yes | what the service does; the AI works from this |
| `sector` | string 1-255 | yes | sector name, e.g. `Transport`. `sector_name` is also accepted. |
| `subsector` | string 1-255 | yes | sub-sector name, e.g. `Land`. `sub_sector_name` is also accepted. |
| `entity_names` | string[] 1-20 | yes | the entities that run the service; each 1-255 chars, no repeats in any letter case |

```json
{
  "service_name": "Traffic Management & Control",
  "service_description": "Monitors, manages and optimizes road traffic flow using traffic signals, surveillance, sensors and intelligent transportation systems.",
  "sector": "Transport",
  "subsector": "Land",
  "entity_names": ["Road Transport Authority"]
}
```

**Response** `202` (`200` on replay; `202` when a replay starts a new try after an outage): `MappingAccepted`

| Field | Type | Meaning |
| --- | --- | --- |
| `mapping_id` | string | keep it |
| `status` | string | always `queued` in this answer, also on a replay: read the real state from 5.2 |
| `generation` | int | `1`; on a replay, the generation this key started (a new try after an outage counts one more) |

```json
{ "mapping_id": "41f4c1247cc2460e8e09e176a29a8ae9", "status": "queued", "generation": 1 }
```

**Errors**

| Status | Reason | Fix |
| --- | --- | --- |
| 422 | — | fix `errors[]`: a field missing, blank or too long; no entity names or more than 20; an entity name repeated; unknown field |
| 409 | — | `Idempotency-Key` used before with another body (`This Idempotency-Key was already used for another mapping input.`): use a new key |

Notes:
- Text is trimmed and runs of spaces collapsed before it is saved; a value of only spaces is blank (`A required value cannot be blank.`). A replay compares the body after this, and after `sector_name` / `sub_sector_name` are read as `sector` / `subsector`.
- `sector`, `subsector` and `entity_names` are free text for the AI: names, not ids, and not checked against the catalog. The mapping belongs to the entity in `X-Entity-Id`, whatever `entity_names` says.
- How many services to find per direction is a server setting (default 10 upstream and 10 downstream); 5.3 shows it as `summary.max_upstream` / `summary.max_downstream`. Fewer come back when fewer are defensible.
- A replay (same key, same body) after the mapping failed for an outage (`error.code` `unavailable`) starts a new try (`202`, `generation` one more), but only while this key's generation is still the latest: once another request started a later generation, the same key replays (`200`). After any other failure it replays (`200`) and the mapping stays `failed`. A create replay never answers `409 generation_in_progress`.

### 5.2 `GET /v1/service-mapper/{mapping_id}/status`

Cheap poll of the mapping. Poll this (or use SSE, 5.4) until `progress.overall` is no longer `generating`.

Headers: identity headers.

**Response** `200`: `MappingStatus`

| Field | Type | Meaning |
| --- | --- | --- |
| `mapping_id` | string | |
| `entity_id` | int | |
| `user_id` | string or null | who created it (`X-User-Id`) |
| `status` | string | the generation's job: `queued`, `running`, `done`, `failed`, `cancelled` |
| `generation` | int | `1` for the first; one more each time the mapping is regenerated |
| `progress.overall` | string | what to do now: `generating` (queued or running: wait), `done` (decide the services, 5.5), `failed` (`error` says why), `cancelled` |
| `progress.relationships.total` / `.accepted` / `.rejected` / `.pending` | int | the current generation's services and their decisions; all `0` while generating |
| `retrying` | object or null | waiting after an AI or store outage: `stage` (null), `reason`, `message`, `attempt`, `max_attempts`, `retry_at` |
| `error` | object or null | when `failed`: `{code, message, reason}` |
| `created_at` / `updated_at` | datetime | |

```json
{
  "mapping_id": "41f4c1247cc2460e8e09e176a29a8ae9",
  "entity_id": 125,
  "user_id": "e2e-tester",
  "status": "done",
  "generation": 3,
  "progress": {
    "overall": "done",
    "relationships": { "total": 14, "accepted": 0, "rejected": 0, "pending": 14 }
  },
  "retrying": null,
  "error": null,
  "created_at": "2026-10-21T15:34:15.706000Z",
  "updated_at": "2026-10-22T12:33:01.451000Z"
}
```

**Errors**

| Status | Reason | Fix |
| --- | --- | --- |
| 404 | — | unknown mapping |
| 403 | — | another entity's mapping |

Notes:
- A failed generation's `error`: `code: internal_error` with `The AI answer did not satisfy the Service Mapper output contract.` or `The AI answer was too long for the model; ...`; or `code: unavailable` with `reason` `ai_down`, `ai_unreachable`, `ai_busy` or `ai_timed_out` when the AI stayed unavailable through every retry.
- A failed generation stays `failed`: it is not retried by itself and never turns `done`. Regenerate it (see the start of section 5). After an outage (`error.code` `unavailable`) you can also send the same create request again with the same `Idempotency-Key`, while that key's generation is still the latest: that starts a new try.
- `done` means the services are ready to decide, not that they are decided. The review is complete when `progress.relationships.pending` is `0`.
- `retrying` is set only while the job is `queued` for its next try after an outage. It is null again once that try starts.
- `cancelled` belongs to the shared status vocabulary; no call cancels a mapping today.

### 5.3 `GET /v1/service-mapper/{mapping_id}`

The mapping: its upstream and downstream services and their decisions.

Headers: identity headers.

**Response** `200`: `MappingView`

| Field | Type | Meaning |
| --- | --- | --- |
| `mapping_id` | string | |
| `status` / `generation` | string / int | as 5.2 |
| `upstream_services[]` | object[] | services the mapped service depends on (below) |
| `downstream_services[]` | object[] | services that depend on it (below) |
| `summary.unique_services` | int | services in both lists |
| `summary.upstream_count` / `.downstream_count` | int | how many in each list |
| `summary.max_upstream` / `.max_downstream` | int | the most asked for per direction (the server setting) |
| `error` / `retrying` | object or null | as 5.2 |
| `created_at` / `updated_at` | datetime | |

Each service in `upstream_services[]` / `downstream_services[]`:

| Field | Type | Meaning |
| --- | --- | --- |
| `dependency_id` | string | send this to 5.5 |
| `service_id` | int or null | onboarding catalog id; `null` when the AI proposed a service outside the catalog |
| `service_name` | string | |
| `sector` / `subsector` | string or null | |
| `dependency_reason` | string | why it is a direct dependency, in this direction; starts `Recorded:` when the onboarding catalog records the link, else `Inferred:` |
| `applicability` | string or null | when it applies; `null` = always |
| `ai_suggested` | bool | `true` when it is not from the catalog (`service_id` is `null`) |
| `isAccepted` | bool or null | `null` pending, `true` accepted, `false` rejected |
| `accepted_datetime` / `accepted_by` | datetime / string, or null | set for an accepted service only; `accepted_by` = the decider's `X-User-Id`. Who rejected a service, and when, is not returned. |

Trimmed (the full answer has 4 upstream and 10 downstream services):

```json
{
  "mapping_id": "41f4c1247cc2460e8e09e176a29a8ae9",
  "status": "done",
  "generation": 3,
  "upstream_services": [
    {
      "dependency_id": "6ad43b3b40155429bc486d476fce7fa0",
      "service_id": null,
      "service_name": "Water Supply System",
      "sector": "Energy",
      "subsector": "Water",
      "dependency_reason": "Provides cooling water and process water required for thermal power plant operations and steam cycle management.",
      "applicability": "Applicable to thermal generation plants (fossil fuel, nuclear, concentrated solar thermal) ...",
      "ai_suggested": true,
      "isAccepted": null,
      "accepted_datetime": null,
      "accepted_by": null
    }
  ],
  "downstream_services": [
    {
      "dependency_id": "99b094278ef85c6bac58abefe56fccec",
      "service_id": 1548,
      "service_name": "Dubai Metro Operations",
      "sector": "Transport",
      "subsector": "Land",
      "dependency_reason": "Directly consumes electrical energy supplied through the grid for traction power and station operations.",
      "applicability": null,
      "ai_suggested": false,
      "isAccepted": null,
      "accepted_datetime": null,
      "accepted_by": null
    }
  ],
  "summary": { "unique_services": 14, "upstream_count": 4, "downstream_count": 10, "max_upstream": 10, "max_downstream": 10 },
  "error": null,
  "retrying": null,
  "created_at": "2026-10-21T15:34:15.706000Z",
  "updated_at": "2026-10-22T12:33:01.451000Z"
}
```

**Errors**

| Status | Reason | Fix |
| --- | --- | --- |
| 404 | — | unknown mapping |
| 403 | — | another entity's mapping |

Notes:
- Both lists are empty until `status` is `done` (and stay empty after a failure). A `done` mapping may also have empty lists, when the AI found nothing defensible: then there is nothing to decide.
- Each list is ordered by relevance, strongest first.
- A service is in one direction only. (A mapping generated by an older version may list one service in both, with the same `dependency_id`.)
- A new generation replaces both lists with new `dependency_id`s; the old generation's decisions stay with it.

### 5.4 `GET /v1/service-mapper/{mapping_id}/events` (SSE)

Live status of the mapping. `text/event-stream`.

Headers: identity headers (same SSE auth as 3.3: headers only).

**Events**

| `event:` | `data:` (JSON) | When |
| --- | --- | --- |
| `mapping.updated` | the `MappingStatus` of 5.2 | once on connect, then on every change (identical bodies are not resent) |

There is no `*.deleted` event: mappings are not deleted. `retry: 3000`, `: ping` every 15 s idle, re-read every 30 s, same end conditions as 3.3 (the stream does not end on `done`).

Changes close together are sent as one: when the worker picks the job up at once, `queued` is skipped and the first update already says `running`. Act on `progress.overall`, not on each `status` step.

**Errors** (before the stream starts)

| Status | Reason | Fix |
| --- | --- | --- |
| 401 | — | send identity headers |
| 404 | — | unknown mapping |
| 403 | — | another entity's mapping |

### 5.5 `POST /v1/service-mapper/{mapping_id}/dependencies/decision`

Accept or reject one or more upstream and downstream services in one call.

Headers: identity headers, `Content-Type`.

**Body** (`DependencyDecisionRequest`)

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `accept` | string[] or null | no | `dependency_id`s to accept |
| `reject` | string[] or null | no | `dependency_id`s to reject |

- Either list may be `null`, missing, `[]` or `[""]`: blanks are dropped, ids trimmed, repeats removed.
- At least one id in all; an id may not be in both lists; at most 200 ids; each id ≤ 64 chars.

```json
{ "accept": ["99b094278ef85c6bac58abefe56fccec", "6ad43b3b40155429bc486d476fce7fa0"], "reject": [""] }
```

**Response** `200`: the `MappingView` of 5.3, with the decisions applied, plus:

| Field | Type | Meaning |
| --- | --- | --- |
| `failed[]` | object[] | the ids not saved; `[]` when every id was saved |
| `failed[].dependency_id` | string | |
| `failed[].reason` | string | `dependency_not_found`: not in the current generation; `decision_final`: it already has the other decision |
| `failed[].message` | string | `No such dependency in the current generation.` / `This recommendation was already decided differently; decisions are final.` |

```json
{
  "mapping_id": "41f4c1247cc2460e8e09e176a29a8ae9",
  "status": "done",
  "generation": 3,
  "upstream_services": ["... as 5.3, each isAccepted updated ..."],
  "downstream_services": ["..."],
  "summary": { "unique_services": 14, "upstream_count": 4, "downstream_count": 10, "max_upstream": 10, "max_downstream": 10 },
  "error": null,
  "retrying": null,
  "created_at": "2026-10-21T15:34:15.706000Z",
  "updated_at": "2026-10-22T12:33:01.451000Z",
  "failed": [
    {
      "dependency_id": "0000000000000000000000000000dead",
      "reason": "dependency_not_found",
      "message": "No such dependency in the current generation."
    }
  ]
}
```

**Errors**

| Status | Reason | Fix |
| --- | --- | --- |
| 422 | — | fix `errors[]`. Field `body`: nothing to decide (`Name at least one dependency_id in accept or reject.`), an id in both lists, more than 200 ids in all. Field `body.accept` / `body.reject`: one list over 200 items. Field `body.accept.N` / `body.reject.N`: an id over 64 chars. Unknown field. |
| 404 | — | unknown mapping |
| 403 | — | another entity's mapping |
| 409 | — | `status` is not `done` (`The mapping is not done: wait while it generates, or regenerate it if it failed.`): wait for `done` (5.2); a `failed` mapping never gets there: regenerate it. |
| 409 | `generation_in_progress` | `A round is already running for this mapping.`: another change kept landing at the same moment (e.g. a new generation started). Read 5.3 again and retry with its ids. |

Notes:
- **A `200` does not mean every id was saved: always check `failed[]`.** It is `200` even when every id failed.
- Ids from an earlier generation come back as `dependency_not_found`: after a new generation, read 5.3 again and use its ids.
- An id decides that service's relationship in the direction it is listed in (in both, for an older mapping that lists it twice).
- Decisions are final: accept → reject (or the reverse) comes back in `failed` as `decision_final`. Sending the same decision again changes nothing and is not a failure, so retries are safe.
- The valid ids are saved together in one update; the answer already shows them decided, and one `mapping.updated` event follows (5.4).
- An accepted service counts as approved at once; there is no separate review of the whole mapping. Any caller of the same entity may decide; `accepted_by` records the `X-User-Id`.

## 6. JavaScript

### POST with headers

```js
const BASE = "https://<tsg-host>";
const identity = {
  "X-API-Key": API_KEY,
  "X-User-Id": "jane.doe@example.com",
  "X-Entity-Id": "125",
  "X-Tenant-Id": "tenant-01",
};

async function tsg(method, path, body, extra = {}) {
  const res = await fetch(BASE + path, {
    method,
    headers: { ...identity, "Content-Type": "application/json", ...extra },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await res.json();
  if (!res.ok) {
    // problem+json: branch on data.reason, show data.detail, log data.request_id
    const err = new Error(data.detail);
    Object.assign(err, { status: res.status, reason: data.reason, errors: data.errors, details: data.details });
    throw err;
  }
  return data; // 200 or 202
}

const run = await tsg("POST", "/v1/sessions",
  { asset_id: 1166, supporting_system_id: [1448, 1451] },
  { "Idempotency-Key": crypto.randomUUID() });
```

### SSE (headers required, so no `EventSource`)

```js
async function streamEvents(path, onEvent, signal) {
  const res = await fetch(BASE + path, {
    headers: { ...identity, Accept: "text/event-stream" },
    signal, // AbortController: the server never closes on "complete"
  });
  if (!res.ok) throw await res.json(); // 401/403/404 as problem+json
  const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
  let buf = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) return; // closed by server: deleted, or key revoked
    buf += value;
    let i;
    while ((i = buf.indexOf("\n\n")) >= 0) {
      const block = buf.slice(0, i);
      buf = buf.slice(i + 2);
      let event = "message", data = "";
      for (const line of block.split("\n")) {
        if (line.startsWith(":")) continue; // ": ping"
        if (line.startsWith("event:")) event = line.slice(6).trim();
        else if (line.startsWith("data:")) data += line.slice(5).trim();
      }
      if (data) onEvent(event, JSON.parse(data));
    }
  }
}

const ctrl = new AbortController();
streamEvents(`/v1/sessions/${run.session_id}/events`, (event, body) => {
  if (event === "session.deleted") return ctrl.abort();
  const overall = body.progress.overall;
  if (["awaiting_review", "awaiting_next_set", "complete", "error", "cancelled"].includes(overall)) ctrl.abort();
}, ctrl.signal);
```

Reconnect yourself after a drop (the server suggests 3000 ms). From a browser, the origin must be in `CII_CORS_ORIGINS`; CORS allows these headers and exposes `X-Request-Id`.

### Service mapper: create, wait, decide

```js
const mapping = await tsg("POST", "/v1/service-mapper", {
  service_name: "Traffic Management & Control",
  service_description: "Monitors, manages and optimizes road traffic flow.",
  sector: "Transport",
  subsector: "Land",
  entity_names: ["Road Transport Authority"],
}, { "Idempotency-Key": crypto.randomUUID() });

// Wait for the generation (5.2); or stream `.../events` and stop when overall is not "generating".
const base = `/v1/service-mapper/${mapping.mapping_id}`;
let status;
do {
  await new Promise((resolve) => setTimeout(resolve, 3000));
  status = await tsg("GET", `${base}/status`);
} while (status.progress.overall === "generating");
if (status.progress.overall !== "done") throw new Error(status.error?.message ?? status.progress.overall);

// Read the services (5.3) and decide them in one call (5.5): here every one is accepted.
const view = await tsg("GET", base);
const ids = [...view.upstream_services, ...view.downstream_services].map((s) => s.dependency_id);
const decided = await tsg("POST", `${base}/dependencies/decision`, { accept: ids, reject: [] });
for (const f of decided.failed) console.warn(f.dependency_id, f.reason); // a 200 can still carry failures
const after = await tsg("GET", `${base}/status`);
const reviewed = after.progress.relationships.pending === 0; // the review is complete
```
