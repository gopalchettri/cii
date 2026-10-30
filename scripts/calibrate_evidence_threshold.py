"""Calibrates EVIDENCE_SIMILARITY_THRESHOLD for the reranker THIS environment's .env names (a local model
folder or a LiteLLM proxy: the app's own rerank model, so the scale is exactly the one the app will score on).

Each reranker scores on its own 0-100 scale, so the threshold cannot be shared between environments: run
this on each one. Input: a CSV with the columns  query,ref,label  where `query` is a threat's search text
and `ref` an intelligence record's id, both as a threat's search audit stores them (`query`,
`considered[].ref`: T1055.011, CVE-2024-0001), and `label` 1 when a person judges the record to be real
evidence for that threat, 0 when not (60 or more pairs, a third of them 1, make a usable table). The records
are read, never written, from tsg_intel's current records, and each pair is scored on exactly what the app
scores: the query without indicators and the record's scoring_text
(app/search/external_intelligence/evidence_index.py). Output: for each candidate threshold the pairs kept,
the precision (kept pairs that are evidence), the recall (evidence pairs that were kept) and the recommended
value: the highest-recall threshold whose precision is at least 0.9 (noise is worse than a miss), else the
best F1. Then set EVIDENCE_SIMILARITY_THRESHOLD in this environment's env file and record the model, the
date and that threshold in EVIDENCE_THRESHOLD_CALIBRATED_ON (app/core/constants/evidence.py).

From the project folder:  .venv\\Scripts\\python scripts\\calibrate_evidence_threshold.py
labelled_pairs.csv"""

import csv
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from app.core.constants import IntelSource  # noqa: E402
from app.models.external_intelligence.evidence import IntelHit  # noqa: E402
from app.search.external_intelligence.corpus_builder import build_corpus  # noqa: E402
from app.search.external_intelligence.evidence_index import (  # noqa: E402
    remove_indicators,
    scoring_text,
    technique_titles,
)

CANDIDATES = (0.5, 1, 2, 5, 10, 20, 30, 40, 50, 60, 70, 80, 90)
PRECISION_WANTED = 0.9
Row = tuple[float, float, float, float]  # threshold, kept, precision, recall
Scorer = Callable[[str, list[str]], list[float]]


def read_pairs(path: Path) -> list[tuple[str, str, int]]:
    """The labelled pairs of the CSV (query, record ref, 0 or 1)."""
    with path.open(encoding="utf-8", newline="") as handle:
        return [
            (row["query"], row["ref"].strip(), 1 if row["label"].strip() == "1" else 0)
            for row in csv.DictReader(handle)
        ]


def current_records() -> tuple[IntelHit, ...]:
    """tsg_intel's current records of every source, read only, as the app's evidence index holds them."""
    from app.container import get_intel_record_repository

    return build_corpus(get_intel_record_repository().stream_current_intel_records(list(IntelSource))).hits


def score_pairs(
    pairs: Sequence[tuple[str, str, int]], hits: Sequence[IntelHit], score: Scorer
) -> list[float]:
    """The reranker's 0-100 score of every pair on the text the app scores, one call per distinct query."""
    by_ref = {hit.external_id: hit for hit in hits}
    titles = technique_titles(hits)
    by_query: dict[str, list[int]] = {}
    for index, (query, _, _) in enumerate(pairs):
        by_query.setdefault(query, []).append(index)
    scores = [0.0] * len(pairs)
    for query, indexes in by_query.items():
        texts = [scoring_text(by_ref[pairs[i][1]], titles) for i in indexes]
        for index, value in zip(indexes, score(remove_indicators(query), texts), strict=True):
            scores[index] = value
    return scores


def sweep(
    scores: Sequence[float], labels: Sequence[int], candidates: Sequence[float] = CANDIDATES
) -> list[Row]:
    """For each candidate threshold: pairs kept, precision and recall (1.0 precision when nothing is kept)."""
    wanted = sum(labels)
    rows = []
    for threshold in candidates:
        kept = [label for value, label in zip(scores, labels, strict=True) if value >= threshold]
        hits = sum(kept)
        rows.append(
            (
                float(threshold),
                float(len(kept)),
                hits / len(kept) if kept else 1.0,
                hits / wanted if wanted else 0.0,
            )
        )
    return rows


def recommend(rows: Sequence[Row]) -> float:
    """The highest-recall threshold with precision of at least PRECISION_WANTED (the higher one on a
    tie), else the best F1."""
    precise = [row for row in rows if row[2] >= PRECISION_WANTED and row[1] > 0]
    if precise:
        return max(precise, key=lambda row: (row[3], row[0]))[0]
    return max(rows, key=lambda row: (_f1(row), row[0]))[0]


def _f1(row: Row) -> float:
    return 2 * row[2] * row[3] / (row[2] + row[3]) if row[2] + row[3] else 0.0


def report(rows: Sequence[Row]) -> str:
    lines = ["threshold   kept  precision  recall"]
    lines += [
        f"{t:9g}  {int(kept):5d}  {precision:9.2f}  {recall:6.2f}" for t, kept, precision, recall in rows
    ]
    return "\n".join([*lines, f"recommended EVIDENCE_SIMILARITY_THRESHOLD={recommend(rows):g}"])


def main(argv: Sequence[str], score: Scorer | None = None, hits: Sequence[IntelHit] | None = None) -> int:
    """Prints the table for the CSV in `argv`; 2 for a wrong call or a ref with no current record."""
    if len(argv) != 1:
        sys.stdout.write(__doc__ or "")
        return 2
    pairs = read_pairs(Path(argv[0]))
    hits = current_records() if hits is None else hits
    missing = sorted({ref for _, ref, _ in pairs} - {hit.external_id for hit in hits})
    if missing:
        sys.stdout.write(f"No current record in tsg_intel for: {', '.join(missing)}\n")
        return 2
    if score is None:
        from app.container import get_rerank_model

        score = get_rerank_model().score_relevance
    scores = score_pairs(pairs, hits, score)
    sys.stdout.write(report(sweep(scores, [label for _, _, label in pairs])) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
