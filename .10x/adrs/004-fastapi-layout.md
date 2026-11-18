# ADR-004: Build the app the way FastAPI builds an API

**Status:** Accepted (owner, 16 Nov 2026: "yes follow FastAPI guidelines ... production ready clean clear KISS codebase ...
io optimized, no functional or fundamental gap")
**Date:** 2026-11-16
**Feature:** simplify-codebase
**Author:** 10x-Team (Architect + Staff Engineer)
**Supersedes:** the 18 Oct rules "one service class per module, one repository per collection, a DI container" and the
scenario "few files" layout (memories rearchitecture-2026-10-18, architecture-hybrid-decision, scenario-few-files-layout).

## Context
`app/` is 34,572 lines in ten layers (`api`, `services`, `domain`, `models`, `data_access`, `core/constants`, `ai`,
`search`, `worker`, `realtime`) wired by a custom container (`app/container.py`). A request passes route -> service
class -> domain -> repository class, and most service methods only pass the call on. The owner finds it hard to read.

## Decision
The FastAPI documentation's layout ("Bigger Applications", the full-stack template, Dependencies, Settings, Testing):

```
app/
  main.py            FastAPI app: lifespan (open/close clients), include_router, exception handlers
  core/config.py     one pydantic-settings Settings + get_settings() (lru_cache)
  core/db.py         the shared, pooled MongoDB / SQL Server / Redis clients
  core/security.py   the API-key check that finds the caller
  api/deps.py        Annotated Depends aliases: SettingsDep, DbDep, CallerDep, ...
  api/routes/        one APIRouter per feature; a route calls crud and logic functions directly
  schemas/           Pydantic request/response models (the frozen API, unchanged)
  crud/              database reads and writes as plain functions taking the collection
  <feature>/         the feature's rules (prompts, checks) as plain functions
  ai/                the gateway calls (chat, embeddings, rerank) and the one slot cap
  worker/            the Celery app and tasks, calling the same crud and logic functions
```

Rules:
- No service class that only passes a call on; no custom container: routes use `Depends`, Celery tasks pass the same
  objects as arguments; tests use `app.dependency_overrides`.
- A constant lives next to its only user; shared names stay in one small module per feature.
- Sync `def` routes with sync PyMongo (FastAPI runs them in its thread pool); `async def` only where nothing blocks.
- Every external call has a timeout; clients are created once (lifespan / worker start) and pooled.
- Fixed: every API path, request, response and status (`tests/contract/openapi.json`, `ui_api_frozen.json`), the text
  the AI is sent, the database layout, every AI tuning setting name.

## Alternatives Considered
| Alternative | Pros | Cons | Why Not |
|---|---|---|---|
| Keep the layers, trim inside them (the 16 Nov plan, steps B-C) | Small steps | Still ten layers and a container; about 2% smaller | The owner rejected it ("the approach is wrong") |
| Merge layers per feature in a custom way | Fewer files | A shape no FastAPI developer knows | Not the framework's way |
| Async everywhere (PyMongo async client, async Celery) | Fewer threads | A rewrite of every IO call; Celery has no async tasks | Not KISS at 5-10 users; the thread pool fits |

## Consequences
### Positive
- One way to find anything: route -> crud/logic. Standard to any FastAPI developer.
- The container, the pass-through services and most repository classes go.
### Negative
- Nearly every import moves; tests that build objects through the container change to `dependency_overrides`.
### Risks
- A behaviour silently lost in the move: checked against the behaviour inventory (`specs/`), the frozen contract
  tests and the 55-operation e2e run at every step.

## Dependencies
- ADR-002 (one AI limit path) and the job-runtime design fold into `ai/` and `worker/`.
- ADR-003 is replaced by the job-runtime design (one Redis set of running records), pending the owner's yes.
