# Service Mapper — Problem, Plan and Solution

Status: **Planned** (not built yet).

## 1. The problem

A user gives a service name (which may be new and exist in no table), its sector, its subsector and one or more
entities. Example: "Online Payment Service", Finance, Payments, DEWA.

We must identify possible service-to-service dependencies in both directions, always from the selected service's point of view:

- **Upstream** = a service that the selected service *needs*.
- **Downstream** = a service that *needs or relies on* the selected service.

```
Identity Service  ->  Online Payment Service  ->  Customer Application
   (upstream)             (selected)                 (downstream)
```

Hard parts:

1. The service may be new, so a database lookup cannot answer it. The LLM must reason it out.
2. `onboarding_services` is reference only. It may be empty or irrelevant, so correctness cannot depend on it.
3. LLMs commonly flip direction, invent services, or list the service as its own dependency.
4. There can be several entities, and a dependency may apply to only some of them.

## 2. Design decisions

- Synchronous `POST /v1/service-map`. Nothing is persisted. No Celery job.
- Any database read goes through a stored procedure.
- Reference names are optional hints, fail-open, and never a constraint.
- The LLM does the reasoning. Code validates the answer.

## 3. The solution, step by step

**Step 1 - Take the request.**

```json
{"service_name": "Online Payment Service", "sector": "Finance", "subsector": "Payments", "entities": ["DEWA"]}
```

Inputs are checked for length and empty values. They are free text, so they are treated as data (via
`engine/shared/prompt_redaction.py`) and never as instructions.

**Step 2 - Fetch optional hints.** Stored procedure `tsg_GetServiceReference(@Sector, @Subsector)` returns up to
about 40 service names from the same sector/subsector (matched by name, not ID). Empty result, no match or
failure means we continue with no hints. A failure is logged through a `LogEvent`, not hidden.

**Step 3 - Build the prompt.** It holds the upstream/downstream definitions with the Online Payment example, the
selected service, sector, subsector and entities, and the hint names marked: "Reference names may be irrelevant;
use one only if it truly fits, otherwise ignore it. Do not invent a dependency just to use a reference name."
It asks for real operational dependencies (power, identity, data, network, payment, dispatch), at most 8 per
side, and allows an empty list when none is plausible. Temperature is low.

**Step 4 - Ask the LLM for structured JSON.** Per item (pydantic, `extra="forbid"`):

| Field | Meaning |
|---|---|
| `name` | dependent service name |
| `sector` | best-guess sector |
| `reason` | one-line why |
| `relation` | `selected_needs_this` or `this_needs_selected` |
| `confidence` | high / medium / low |
| `applies_to_entities` | subset of the input entities |

`relation` makes the model state the direction in its own words so code can verify it.

**Step 5 - Check the answer in code** (via `ask_ai_and_check`; one re-ask with the problem list):

- Upstream items must have `selected_needs_this`; downstream items `this_needs_selected`. This catches flipped direction.
- The selected service cannot be its own dependency (normalized-name compare).
- No duplicates within a list. The same service in both lists is accepted only when relations differ and reasons are given.
- Reason is non-empty and names the other service.
- `applies_to_entities` must be a subset of the input entities (empty defaults to all).
- Per-side cap. Truncated or unreadable answers use the existing `TruncatedAiAnswer` / `UnreadableAiAnswer`.
- A second failure returns a clear error.

**Step 6 - Finish.** Code (not the AI) sets `in_reference` by normalized-name match to the hints and sorts by
confidence. The response is labelled "possible dependencies".

```json
{
  "upstream":   [{"name": "Identity Service", "reason": "Payment needs identity to verify the payer", "confidence": "high", "in_reference": false}],
  "downstream": [{"name": "Customer Application", "reason": "The app relies on payment to charge users", "confidence": "high", "in_reference": false}]
}
```

## 4. Files (layering enforced by `tests/test_code_conventions.py`)

- `scripts/sql/tsg_GetServiceReference.sql`, `scripts/sql/grants.sql`, `tests/sql/schema.sql`, `tests/sql/seed.sql`
- `app/models/service_map.py` - request, AI contract, response
- `app/data_access/service_map_reference.py` - wraps the procedure (model on `asset_context.py`)
- `app/engine/service_map/{prompts,mapper,checks}.py` - model on `app/engine/remediation/planner.py`
- `app/services/service_map/mapper_service.py` - singleton, `@traced`, `record_audit`, fail-open hint fetch
- `app/api/routers/service_map.py`, registered in `create_app()` in `app/main.py`
- `app/core/constants/service_map.py`; extend `AiTask`, `CHAT_TEMPERATURES`, `StoredProcedure`, `AuditAction`, `LogEvent`, `ErrorMessage`
- `tests/test_service_map.py` (uses `FakeChatModel`), a procedure case in `tests/test_sql_procedures.py`
- `docs/BLUEPRINT.md` entry

## 5. Tests

No reference data (empty or procedure error) still returns a map; irrelevant reference ignored; flipped relation
triggers a re-ask; self-reference and duplicates rejected; multi-entity subset check; two bad answers give a clear
error; hostile `service_name` treated as data.

## 6. Verification

```
.venv\Scripts\python -m pytest tests/test_service_map.py tests/test_sql_procedures.py tests/test_code_conventions.py
ruff check .
mypy app
```

Manual: POST with "Online Payment Service" / Finance / Payments / [DEWA], with and without reference rows.
