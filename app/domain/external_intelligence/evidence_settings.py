"""The evidence settings the health report shows: the reranker's name, the threshold and its calibration."""

from typing import Any

from app.core.constants import EVIDENCE_THRESHOLD_CALIBRATED_ON


def evidence_settings(rerank_model: str, threshold: float) -> dict[str, Any]:
    """The reranker's name (never its path), the threshold and whether an operator calibrated it there."""
    model = rerank_model.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    calibrated_on = EVIDENCE_THRESHOLD_CALIBRATED_ON.get(model)
    return {
        "rerank_model": model,
        "threshold": threshold,
        "threshold_calibrated": calibrated_on is not None,
        "threshold_calibrated_on": calibrated_on,
    }
