"""Calibrates EVIDENCE_SIMILARITY_THRESHOLD for the reranker THIS environment's .env names (a local model
folder or a LiteLLM proxy: the app's own rerank model, so the scale is exactly the one the app will score on).

Each reranker scores on its own 0-100 scale, so the threshold cannot be shared between environments: run
this on each one. Input: a CSV with the columns  query,record,label  where `query` is a threat's search
text, `record` an intelligence record's text, and `label` 1 when a person judges the record to be real
evidence for that threat, 0 when not (60 or more pairs, a third of them 1, make a usable table). Output:
for each candidate threshold the pairs kept, the precision (kept pairs that are evidence), the recall
(evidence pairs that were kept) and the recommended value: the highest-recall threshold whose precision
is at least 0.9 (noise is worse than a miss), else the best F1. Then set EVIDENCE_SIMILARITY_THRESHOLD in
this environment's env file and add the model to EVIDENCE_THRESHOLD_CALIBRATED_ON
(app/core/constants/evidence_story.py).

From the project folder:  .venv\\Scripts\\python scripts\\calibrate_evidence_threshold.py
labelled_pairs.csv"""

import csv
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

CANDIDATES = (0.5, 1, 2, 5, 10, 20, 30, 40, 50, 60, 70, 80, 90)
PRECISION_WANTED = 0.9
Row = tuple[float, float, float, float]  # threshold, kept, precision, recall
Scorer = Callable[[str, list[str]], list[float]]


def read_pairs(path: Path) -> list[tuple[str, str, int]]:
    """The labelled pairs of the CSV (query, record, 0 or 1)."""
    with path.open(encoding="utf-8", newline="") as handle:
        return [
            (row["query"], row["record"], 1 if row["label"].strip() == "1" else 0)
            for row in csv.DictReader(handle)
        ]


def score_pairs(pairs: Sequence[tuple[str, str, int]], score: Scorer) -> list[float]:
    """The reranker's 0-100 score of every pair, one call per distinct query."""
    by_query: dict[str, list[int]] = {}
    for index, (query, _, _) in enumerate(pairs):
        by_query.setdefault(query, []).append(index)
    scores = [0.0] * len(pairs)
    for query, indexes in by_query.items():
        for index, value in zip(indexes, score(query, [pairs[i][1] for i in indexes]), strict=True):
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


def main(argv: Sequence[str], score: Scorer | None = None) -> int:
    if len(argv) != 1:
        sys.stdout.write(__doc__ or "")
        return 2
    pairs = read_pairs(Path(argv[0]))
    if score is None:
        from app.container import get_rerank_model

        score = get_rerank_model().score_relevance
    scores = score_pairs(pairs, score)
    sys.stdout.write(report(sweep(scores, [label for _, _, label in pairs])) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
