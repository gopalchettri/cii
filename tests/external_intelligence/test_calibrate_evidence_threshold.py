"""scripts/calibrate_evidence_threshold.py: precision and recall per candidate threshold from a labelled
CSV, each pair scored on the text the app scores by the app's rerank model (a fake here), and the
recommended value."""

import importlib.util
import re
from pathlib import Path

from app.search.external_intelligence.corpus_builder import build_corpus
from app.search.external_intelligence.evidence_index import build_index
from tests.external_intelligence.evidence_fakes import ScoredBy, TextEmbeddings, technique_doc

REPO = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location(
    "calibrate", REPO / "scripts" / "calibrate_evidence_threshold.py"
)
calibrate = importlib.util.module_from_spec(_SPEC)  # type: ignore[arg-type]
_SPEC.loader.exec_module(calibrate)  # type: ignore[union-attr]

#: record ref -> the fake reranker's score; labels: the first three are evidence.
SCORES = {"T1": 95.0, "T2": 70.0, "T3": 40.0, "T4": 35.0, "T5": 8.0, "T6": 0.2}
LABELS = {"T1": 1, "T2": 1, "T3": 1, "T4": 0, "T5": 0, "T6": 0}
HITS = build_corpus([technique_doc(ref) for ref in SCORES]).hits


def _fake() -> ScoredBy:
    return ScoredBy({f"Technique {ref}.": score for ref, score in SCORES.items()})


def _csv(tmp_path: Path) -> Path:
    path = tmp_path / "pairs.csv"
    rows = "\n".join(f"q1,{ref},{label}" for ref, label in LABELS.items())
    path.write_text(f"query,ref,label\n{rows}\n", encoding="utf-8")
    return path


def test_precision_and_recall_per_threshold(tmp_path: Path) -> None:
    pairs = calibrate.read_pairs(_csv(tmp_path))
    assert pairs[0] == ("q1", "T1", 1) and len(pairs) == 6
    scores = calibrate.score_pairs(pairs, HITS, _fake().score_relevance)
    rows = {row[0]: row for row in calibrate.sweep(scores, [p[2] for p in pairs])}
    assert rows[50] == (50.0, 2.0, 1.0, 2 / 3)  # T1 and T2 kept, both evidence
    assert rows[30][1] == 4.0 and rows[30][2] == 0.75 and rows[30][3] == 1.0  # T4 is noise
    assert rows[0.5][1] == 5.0 and rows[0.5][2] == 0.6  # everything but T6


def test_each_pair_is_scored_on_exactly_the_text_the_app_scores() -> None:
    """The query without indicators and the record's scoring_text (no "T1055.011 " id, no "Tactics:" tail,
    the parent's title first), the same as EvidenceIndex.score_candidates sends the reranker."""
    docs = [technique_doc("T1055"), technique_doc("T1055.011", text="Writes to window memory.")]
    corpus = build_corpus(docs)
    sub_technique = next(hit for hit in corpus.hits if hit.external_id == "T1055.011")
    assert sub_technique.text.startswith("T1055.011 ") and "Tactics:" in sub_technique.text
    query = "Process injection from 10.0.0.1"
    app, script = ScoredBy(), ScoredBy()
    build_index(corpus, TextEmbeddings(), app).score_candidates(query, [sub_technique])
    calibrate.score_pairs([(query, "T1055.011", 1)], corpus.hits, script.score_relevance)
    cleaned = ("Process injection from", ["Technique T1055: Technique T1055.011. Writes to window memory."])
    assert script.calls == app.calls == [cleaned]


def test_the_recommendation_is_the_highest_recall_with_enough_precision() -> None:
    pairs = [("q1", ref, LABELS[ref]) for ref in LABELS]
    rows = calibrate.sweep(calibrate.score_pairs(pairs, HITS, _fake().score_relevance), [p[2] for p in pairs])
    assert calibrate.recommend(rows) == 40  # keeps T1, T2, T3 (recall 1.0) before T4 (35) lets noise in


def test_with_no_precise_threshold_the_best_f1_is_recommended() -> None:
    rows = [(1.0, 10.0, 0.5, 1.0), (50.0, 2.0, 0.6, 0.2)]
    assert calibrate.recommend(rows) == 1.0


def test_the_script_reads_the_csv_and_prints_the_table(tmp_path: Path, capsys) -> None:  # noqa: ANN001
    assert calibrate.main([str(_csv(tmp_path))], _fake().score_relevance, HITS) == 0
    out = capsys.readouterr().out
    assert (
        "threshold   kept  precision  recall" in out and "recommended EVIDENCE_SIMILARITY_THRESHOLD=40" in out
    )
    assert calibrate.main([], _fake().score_relevance, HITS) == 2


def test_a_ref_with_no_current_record_stops_the_script(tmp_path: Path, capsys) -> None:  # noqa: ANN001
    assert calibrate.main([str(_csv(tmp_path))], _fake().score_relevance, HITS[:4]) == 2
    assert capsys.readouterr().out == "No current record in tsg_intel for: T5, T6\n"


def test_the_files_the_instructions_name_exist() -> None:
    named = re.findall(r"app/[\w/]+\.py", calibrate.__doc__ or "")
    assert "app/core/constants/evidence.py" in named and all((REPO / path).is_file() for path in named)
