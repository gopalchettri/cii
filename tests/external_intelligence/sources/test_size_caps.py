"""A giant or unpacking-to-giant source file fails with IntelFetchFailed and an enum message; it never
reaches a parser's memory. The cap is shrunk for the test, so the 'bomb' stays a few kilobytes."""

import json

import pytest

from app.core.constants import IntelMessage, IntelSource, SourceDownload
from app.core.exceptions import IntelFetchFailed
from app.domain.intel.sources.attack import MitreAttackSource
from app.domain.intel.sources.common import load_json
from tests.external_intelligence.sources.web import serving

CAP = 10_000
HEADER = b"#model_version:v1,score_date:2026-10-12T00:00:00Z\ncve,epss,percentile\n"


@pytest.fixture(autouse=True)
def small_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(SourceDownload, "MAX_PARSED_BYTES", CAP)


def test_a_json_text_over_the_cap_is_refused_before_it_is_parsed() -> None:
    with pytest.raises(IntelFetchFailed) as refused:
        load_json(b"[" + b"1," * CAP + b"1]", "src")
    assert refused.value.message == IntelMessage.BAD_FORMAT.format(source="src")
    assert load_json(b"[1]", "src") == [1]


def test_a_giant_attack_bundle_fails_the_source() -> None:
    body = json.dumps({"objects": [{"type": "x", "id": "x" * 100}] * 500}).encode()
    with pytest.raises(IntelFetchFailed):
        MitreAttackSource(IntelSource.ATTACK_ENTERPRISE, serving(body)).download_changes(None)
