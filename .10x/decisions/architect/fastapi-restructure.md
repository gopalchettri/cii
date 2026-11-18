# Architect: FastAPI restructure, under 20,000 lines (16 Nov 2026)

- Layout: ADR-004. Request path: `api/routes/<feature>.py` -> `domain/<feature>/` plain functions -> `crud/<feature>.py`
  plain functions -> `crud/base.py` helpers (validators, indexes, never-deleted stores). `api/deps.py` gives SettingsDep,
  DbDep, SqlDep, RedisDep, Caller, CallersRun, CallersPlan, IdempotencyKey, AdminUser.
- Workers: Celery tasks call the same domain/crud functions with explicit arguments; no container.
- Long-lived objects that hold real state (ChatModel, EmbeddingModel, RerankModel, AiSlots, LibraryCache,
  EvidenceIndexKeeper, IntelligenceSwitch, EventHub) keep a `@singleton` getter next to their class.
- Job runtime: ADR-006 (ack at start, reaper is the only recovery). External intelligence: ADR-005 (ATT&CK only).
- SQL Server: stored-procedure calls only; every app record in MongoDB.
- Failure modes unchanged: leases fence stale writers, the reaper re-sends, the 8-slot reranker cap holds.
