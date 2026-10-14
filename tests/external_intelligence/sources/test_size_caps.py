"""A giant or unpacking-to-giant source file fails with IntelFetchFailed and an enum message; it never
reaches a parser's memory. The cap is shrunk for the test, so the 'bomb' stays a few kilobytes."""

import gzip
import json

import httpx
import pytest

from app.core.constants import IntelMessage, IntelSource, SourceDownload
from app.core.exceptions import IntelFetchFailed
from app.services.external_intelligence.sources.bounded_parse import load_json, open_gzip_text
from app.services.external_intelligence.sources.cisa_known_exploited_source import CisaKnownExploitedSource
from app.services.external_intelligence.sources.first_epss_scores_source import FirstEpssScoresSource
from app.services.external_intelligence.sources.mitre_attack_source import MitreAttackSource
from app.services.external_intelligence.sources.nist_nvd_details_source import NistNvdDetailsSource
from tests.external_intelligence.sources.web import serving

CAP = 10_000
HEADER = b"#model_version:v1,score_date:2026-10-12T00:00:00Z\ncve,epss,percentile\n"


@pytest.fixture(autouse=True)
def small_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(SourceDownload, "MAX_PARSED_BYTES", CAP)


def _epss(body: bytes) -> None:
    FirstEpssScoresSource(lambda: {"CVE-2024-0001"}, serving(gzip.compress(body))).download_changes(None)


def test_a_gzip_bomb_of_rows_is_refused_while_it_unpacks() -> None:
    with pytest.raises(IntelFetchFailed) as refused:
        _epss(HEADER + b"CVE-2024-0002,0.1,0.2\n" * 5_000)
    assert refused.value.message == IntelMessage.BAD_FORMAT.format(source=IntelSource.FIRST_EPSS)


def test_a_gzip_bomb_of_one_endless_line_is_refused() -> None:
    with pytest.raises(IntelFetchFailed):
        _epss(b"#" + b"A" * 1_000_000)  # no newline: only a byte cap stops it
    with pytest.raises(IntelFetchFailed):
        _epss(HEADER + b"CVE-2024-0001," + b"9" * 1_000_000)


def test_a_normal_gzip_under_the_cap_still_reads() -> None:
    with open_gzip_text(gzip.compress(b"a,b\n" * 100), "x") as lines:
        assert len(lines.read()) == 400


def test_a_json_text_over_the_cap_is_refused_before_it_is_parsed() -> None:
    with pytest.raises(IntelFetchFailed) as refused:
        load_json(b"[" + b"1," * CAP + b"1]", "src")
    assert refused.value.message == IntelMessage.BAD_FORMAT.format(source="src")
    assert load_json(b"[1]", "src") == [1]


def test_a_giant_kev_catalogue_fails_the_source() -> None:
    body = json.dumps({"catalogVersion": "1", "vulnerabilities": ["x" * 100] * 500}).encode()
    with pytest.raises(IntelFetchFailed):
        CisaKnownExploitedSource(serving(body)).download_changes(None)


def test_a_giant_attack_bundle_fails_the_source() -> None:
    body = json.dumps({"objects": [{"type": "x", "id": "x" * 100}] * 500}).encode()
    with pytest.raises(IntelFetchFailed):
        MitreAttackSource(IntelSource.ATTACK_ENTERPRISE, serving(body)).download_changes(None)


def test_a_giant_nvd_page_fails_the_source(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        SourceDownload, "MAX_NVD_PAGE_BYTES", CAP
    )  # the page is read in chunks and stopped here
    page = json.dumps({"vulnerabilities": [], "pad": "x" * 100_000}).encode()
    client = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, content=page)))
    source = NistNvdDetailsSource(
        lambda: {"CVE-2024-0001"}, lambda: set(), api_key=lambda: "", client=client, sleep=lambda _s: None
    )
    with pytest.raises(IntelFetchFailed):
        source.download_changes(None)
