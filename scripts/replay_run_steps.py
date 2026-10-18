"""Replays the search and ranking inner sub-steps of an EXISTING run with the app's own code, read-only, and
writes them as step-trace lines (app/core/tracing.py) to logs/replay-<run id's first 8>.log: tsg_console.html
(How it runs -> Load run data) then shows that run's real BM25, similarity, merge-by-rank, per-category and
ranking data.

Nothing is written to MongoDB or SQL Server and no AI model is called: every vector comes from MongoDB, and a
text with no stored vector stops the replay. The merge (threats.merge) is not replayed: its input, the
threats each category accepted, was never stored.

From the project folder: .venv\\Scripts\\python scripts\\replay_run_steps.py [run id]   (default: TSG_RUN_ID
in debug/.env)"""

from __future__ import annotations

import json
import logging
import sys
from collections import Counter
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from debug_tools import debug_value  # noqa: E402  (scripts/ is on the path: this script's own folder)

#: Vectors this replay read from MongoDB, per store: "<kind> found" / "<kind> missing".
CACHE: Counter[str] = Counter()


class NotCached(Exception):
    """A text with no stored vector: the replay never asks the embedding model for one."""


class ReadOnlyVectors:
    """Mixed into a vector repository (app/data_access/admin/repository.py): reads as the app does,
    counts what it found, and never writes: save_vectors() and update_library_vector_corpus() do nothing."""

    kind = "vectors"

    def list(self, *args: Any, **where: Any) -> list[dict[str, Any]]:
        """The vectors found by their keys (`ids`), counted as found or missing."""
        found = super().list(*args, **where)  # type: ignore[misc]
        CACHE[f"{self.kind} found"] += len(found)
        CACHE[f"{self.kind} missing"] += len(set(where.get("ids", ()))) - len(found)
        return found

    def save_vectors(self, vectors: list[dict[str, Any]]) -> None:
        """Nothing stored: the replay is read-only."""

    def update_library_vector_corpus(self, *_: Any) -> int:
        return 0  # nothing retired: the replay is read-only


class NoProvider:
    """Stands in for the embedding provider: a cache miss stops the replay, never an AI call."""

    def embed_batch(self, batch: list[str]) -> list[bytes]:
        missing = {kind: n for kind, n in CACHE.items() if kind.endswith("missing") and n}
        raise NotCached(f"texts with no stored vector: {missing} (this batch {len(batch)}); no AI call made")


def load_run(run_id: str) -> tuple[Any, dict[str, Any]]:
    """The run's frozen context and its plan."""
    from app.data_access.scenario.repository import scenario_sessions
    from app.models.asset_context import FrozenContext

    found = scenario_sessions.get(fields=["context", "plan"], _id=run_id)
    if found is None or not found.get("context"):
        raise SystemExit(f"  No run with id '{run_id}' (or it has no context).")
    context, plan = FrozenContext.from_record(found["context"]), found.get("plan")
    if not plan or "made_with" not in plan:
        raise SystemExit(f"  Run '{run_id}' has no frozen plan: nothing to replay.")
    return context, plan


def load_library(plan: dict[str, Any]) -> Any:
    """Both libraries as app/search/library_cache.py loads them (the stamp first), compared with the run's."""
    from app.core.database import get_stored_procedure_client
    from app.data_access.library.repository import SqlServerRepository

    library = SqlServerRepository(get_stored_procedure_client()).load_library()
    assert library is not None  # no stamp passed: always loaded
    stamp = library.stamp
    now = {table: digest.hex() if digest else None for table, digest in stamp}
    then = plan["made_with"]["library"]
    changed = sorted(table for table in now.keys() | then.keys() if now.get(table) != then.get(table))
    print(
        f"  library changed since the run: {', '.join(changed)}; numbers may differ"
        if changed
        else "  library unchanged since the run"
    )
    return library


def build_snapshot(library: Any, embedding_model: str) -> Any:
    """The app's own snapshot builder, with the run's embedding model over read-only vector stores."""
    from app.ai.embeddings import EmbeddingModel
    from app.ai.profiles import EMBEDDING_MODEL_PROFILES, find_model_profile
    from app.core.constants import Collection
    from app.core.database import get_mongodb
    from app.data_access.admin.repository import LibraryVectorRepository, VectorRepository
    from app.search.service import _SnapshotBuilder

    class ReadOnlyLibrary(ReadOnlyVectors, LibraryVectorRepository):
        kind = "library"

    class ReadOnlyQueries(ReadOnlyVectors, VectorRepository):
        kind = "query"

    db = get_mongodb()
    profile = find_model_profile(EMBEDDING_MODEL_PROFILES, embedding_model)
    stores = ReadOnlyLibrary(db[Collection.EMBEDDINGS]), ReadOnlyQueries(db[Collection.QUERY_VECTORS])
    model = EmbeddingModel(embedding_model, profile, "", "", *stores)  # no address or key: never called
    # private: a cache miss must stop here, not reach the AI provider (a stand-in: only embed_batch is called)
    model._provider = NoProvider()  # type: ignore[assignment]
    # Private builder: get_library_search() would start the library checker and the real (writing) stores.
    return _SnapshotBuilder(model).build(library)


def start_step_log(run_id: str) -> Path:
    """A new logs/replay-<8>.log with every step and inner sub-step, each line under the run's record_id."""
    import structlog

    from app.core.config import get_settings
    from app.core.logging import configure_logging

    settings = get_settings()
    folder = REPO / (settings.log_dir or "logs")
    role = f"replay-{run_id[:8]}"
    path = folder / f"{role}.log"
    path.unlink(missing_ok=True)  # the file is appended to: one replay per file
    trace = {
        "log_dir": str(folder),
        "log_level": "INFO",
        "debug_step_output": True,
        "debug_step_detail": True,
    }
    configure_logging(settings.model_copy(update=trace), role=role)
    root = logging.getLogger()
    # The lines go to the file only: on stdout they would bury this script's summary.
    root.handlers = [handler for handler in root.handlers if isinstance(handler, logging.FileHandler)]
    structlog.contextvars.bind_contextvars(record_id=run_id, task="replay")
    return path


def replay_search(snapshot: Any, context: Any, plan: dict[str, Any]) -> None:
    """The run's landscape, by the app's own function (planning judges every library threat of a category,
    so there is no library search to replay)."""
    from app.ai.profiles import CHAT_MODEL_PROFILES, find_model_profile
    from app.domain.scenario.plan import describe_asset_for_ai

    # ChatModel.max_prompt_chars of the run's chat models (app/ai/chat.py), halved as find_threats does.
    chat_models = plan["made_with"]["chat_models"]
    budget = min(find_model_profile(CHAT_MODEL_PROFILES, m).max_input_chars for m in chat_models) // 2
    describe_asset_for_ai(context, budget)


def replay_ranking(plan: dict[str, Any]) -> tuple[int, int]:
    """rank_paths over the plan's own paths, each rebuilt from its stored threat and systems (the merges,
    G213, are on the record: the replay re-asks no AI): (same place, paths)."""
    from app.core.constants import StrideCategory
    from app.domain.scenario.plan import attack_path_id, path_on, rank_paths
    from app.models.scenario.plan import PlannedThreat

    threats = [
        PlannedThreat(  # the fields ranking reads (no from_record: actors play no part in it)
            key=record["key"],
            catalogue_id=record["library_id"],
            type_id=record["type"]["id"],
            type_name=record["type"]["name"],
            name=record["name"],
            categories=tuple(StrideCategory(category) for category in record["categories"]),
            systems=tuple(record["systems"]),
            impact=record["impact"],
            confidence=record["confidence"],
            reason=record["reason"],
        )
        for record in plan["threats"]
    ]
    by_key = {threat.key: threat for threat in threats}
    ranking = rank_paths(
        path_on(by_key[path["steps"][0]], tuple(path["systems"]), StrideCategory(path["categories"][0]))
        for path in plan["paths"]
    )
    again = {attack_path_id(path): rank for rank, path in enumerate(ranking, start=1)}
    stored = {path["path_id"]: path["rank"] for path in plan["paths"]}
    return sum(again.get(path_id) == place for path_id, place in stored.items()), len(stored)


def count_lines(path: Path) -> Counter[str]:
    """Inner sub-step lines per sub name, and traced calls per step."""
    counts: Counter[str] = Counter()
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            fields = json.loads(line)
        except ValueError:
            continue  # a library's plain-text line
        sub = (fields.get("results") or {}).get("sub") if isinstance(fields.get("results"), dict) else None
        if sub:
            counts[f"sub   {sub}"] += 1
        elif fields.get("event") == "step.started":
            counts[f"call  {fields['step']}"] += 1
    return counts


def main(run_id: str) -> int:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]  # sub names hold → and ·
    run_id = run_id or debug_value("TSG_RUN_ID")
    if not run_id:
        raise SystemExit("usage: replay_run_steps.py <run id>   (or TSG_RUN_ID in debug/.env)")
    context, plan = load_run(run_id)
    library = load_library(plan)
    try:
        snapshot = build_snapshot(library, plan["made_with"]["embedding_model"])
        log_file = start_step_log(run_id)
        replay_search(snapshot, context, plan)
    except NotCached as exc:
        print(f"  stopped, nothing written: {exc}")
        return 1
    matched, total = replay_ranking(plan)
    print(f"  step trace: {log_file}")
    for name, count in sorted(count_lines(log_file).items()):
        print(f"    {count:5}  {name}")
    print(f"  vectors read from MongoDB (no AI call): {dict(sorted(CACHE.items()))}")
    print(f"  ranking: {matched} of {total} paths got the run's rank and choice again")
    print("  not replayed: threats.merge; its input, each category's accepted threats, was never stored")
    print("  open app/ux/tsg_console.html -> How it runs -> Load run data -> pick the step trace above")
    return 0 if matched == total else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else ""))
