"""scripts/calibrate_evidence_threshold.py: precision and recall per candidate threshold from a labelled
CSV, scored by the app's rerank model (a fake here), and the recommended value."""

import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location(
    "calibrate", REPO / "scripts" / "calibrate_evidence_threshold.py"
)
calibrate = importlib.util.module_from_spec(_SPEC)  # type: ignore[arg-type]
_SPEC.loader.exec_module(calibrate)  # type: ignore[union-attr]

#: record text -> the fake reranker's score; labels: the first three are evidence.
SCORES = {"a": 95.0, "b": 70.0, "c": 40.0, "x": 35.0, "y": 8.0, "z": 0.2}
LABELS = {"a": 1, "b": 1, "c": 1, "x": 0, "y": 0, "z": 0}


def _fake(query: str, documents: list[str]) -> list[float]:
    return [SCORES[document] for document in documents]


def _csv(tmp_path: Path) -> Path:
    path = tmp_path / "pairs.csv"
    rows = "\n".join(f"q1,{record},{label}" for record, label in LABELS.items())
    path.write_text(f"query,record,label\n{rows}\n", encoding="utf-8")
    return path


def test_precision_and_recall_per_threshold(tmp_path: Path) -> None:
    pairs = calibrate.read_pairs(_csv(tmp_path))
    assert pairs[0] == ("q1", "a", 1) and len(pairs) == 6
    rows = {
        row[0]: row for row in calibrate.sweep(calibrate.score_pairs(pairs, _fake), [p[2] for p in pairs])
    }
    assert rows[50] == (50.0, 2.0, 1.0, 2 / 3)  # a and b kept, both evidence
    assert rows[30][1] == 4.0 and rows[30][2] == 0.75 and rows[30][3] == 1.0  # x is noise
    assert rows[0.5][1] == 5.0 and rows[0.5][2] == 0.6  # everything but z


def test_the_recommendation_is_the_highest_recall_with_enough_precision() -> None:
    pairs = [("q1", r, LABELS[r]) for r in LABELS]
    rows = calibrate.sweep(calibrate.score_pairs(pairs, _fake), [p[2] for p in pairs])
    assert calibrate.recommend(rows) == 40  # keeps a, b, c (recall 1.0) before x (35) lets noise in


def test_with_no_precise_threshold_the_best_f1_is_recommended() -> None:
    rows = [(1.0, 10.0, 0.5, 1.0), (50.0, 2.0, 0.6, 0.2)]
    assert calibrate.recommend(rows) == 1.0


def test_the_script_reads_the_csv_and_prints_the_table(tmp_path: Path, capsys) -> None:  # noqa: ANN001
    assert calibrate.main([str(_csv(tmp_path))], _fake) == 0
    out = capsys.readouterr().out
    assert (
        "threshold   kept  precision  recall" in out and "recommended EVIDENCE_SIMILARITY_THRESHOLD=40" in out
    )
    assert calibrate.main([], _fake) == 2
