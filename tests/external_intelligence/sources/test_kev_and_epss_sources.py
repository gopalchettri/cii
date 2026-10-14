"""The KEV and EPSS adapters, on tiny inline files served by a mock transport (no network)."""

import gzip
import json

import pytest

from app.core.constants import IntelKind, IntelRejection, IntelSource
from app.core.exceptions import IntelFetchFailed
from app.services.external_intelligence.sources.cisa_known_exploited_source import CisaKnownExploitedSource
from app.services.external_intelligence.sources.first_epss_scores_source import FirstEpssScoresSource
from tests.external_intelligence.sources.web import serving

ANY_CVE = {f"CVE-2024-{n:04d}" for n in range(10_000)}


_client = serving


class kev:  # noqa: N801  # keeps the ported tests' call shape: kev.fetch(checkpoint, downloader)
    @staticmethod
    def fetch(checkpoint, downloader):
        return CisaKnownExploitedSource(downloader).download_changes(checkpoint)


class epss:  # noqa: N801
    @staticmethod
    def fetch(checkpoint, downloader, *, only_cves=None):
        known = ANY_CVE if only_cves is None else only_cves
        return FirstEpssScoresSource(lambda: known, downloader).download_changes(checkpoint)


def _kev_body(items: list) -> bytes:
    return json.dumps({"catalogVersion": "2026.10.12", "vulnerabilities": items}).encode()


GOOD = {
    "cveID": "CVE-2024-0001",
    "vendorProject": "Acme",
    "product": "Gate",
    "vulnerabilityName": "Acme Gate RCE",
    "dateAdded": "2026-10-01",
    "shortDescription": "Allows remote code execution.",
    "requiredAction": "Apply updates.",
    "dueDate": "2026-10-22",
    "knownRansomwareCampaignUse": "Known",
}


def test_kev_entry_becomes_a_vulnerability_record() -> None:
    result = kev.fetch(None, _client(_kev_body([GOOD])))
    record = result.records[0]
    assert (result.checkpoint, record.kind, record.external_id) == (
        "2026.10.12",
        IntelKind.VULNERABILITY,
        "CVE-2024-0001",
    )
    assert record.asset_type == "IT" and record.url.endswith("/CVE-2024-0001")
    assert "Acme Gate" in record.text and "Apply updates." in record.text
    assert record.text.startswith("CVE-2024-0001 Acme Gate RCE.") and len(record.text) <= 1200
    assert record.data["known_ransomware_use"] is True and record.data["due_date"] == "2026-10-22"


def test_kev_unchanged_checkpoint_returns_none() -> None:
    assert kev.fetch("2026.10.12", _client(_kev_body([GOOD]))) is None


def test_kev_malformed_records_are_rejected_not_dropped() -> None:
    result = kev.fetch(None, _client(_kev_body([GOOD, {"cveID": "CVE-2024-0002"}, "junk"])))
    assert len(result.records) == 1
    assert [r.reason for r in result.rejected] == [
        IntelRejection.KEV_MISSING_FIELD,
        IntelRejection.NOT_AN_OBJECT,
    ]
    assert result.rejected[0].external_id == "CVE-2024-0002" and result.rejected[0].raw_hash


def test_kev_wrong_shape_fails_the_whole_fetch() -> None:
    with pytest.raises(IntelFetchFailed):
        kev.fetch(None, _client(b'{"nope": 1}'))


def _epss_body(rows: str, header: str = "cve,epss,percentile") -> bytes:
    first = "#model_version:v2025.03.14,score_date:2026-10-12T00:00:00Z"
    return gzip.compress(f"{first}\n{header}\n{rows}".encode())


ROWS = "CVE-2024-0001,0.5,0.9\nCVE-2024-0002,0.1,0.2\nCVE-2024-0003,0.3,0.4\n"


def test_epss_rows_become_exploit_scores() -> None:
    result = epss.fetch(None, _client(_epss_body(ROWS)))
    assert result.checkpoint.startswith("2026-10-12T00:00:00Z|") and len(result.records) == 3
    first = result.records[0]
    assert first.kind == IntelKind.EXPLOIT_SCORE and first.source == IntelSource.FIRST_EPSS
    assert first.data == {
        "cve": "CVE-2024-0001",
        "epss": 0.5,
        "percentile": 0.9,
        "score_date": "2026-10-12",
    }


def test_epss_unchanged_checkpoint_returns_none() -> None:
    first = epss.fetch(None, _client(_epss_body(ROWS)))
    assert epss.fetch(first.checkpoint, _client(_epss_body(ROWS))) is None


def test_epss_keeps_only_the_requested_cves() -> None:
    result = epss.fetch(None, _client(_epss_body(ROWS)), only_cves={"CVE-2024-0002"})
    assert [r.external_id for r in result.records] == ["CVE-2024-0002"]
    assert epss.fetch(None, _client(_epss_body(ROWS)), only_cves=set()) is None  # nothing asked for


def test_epss_bad_floats_and_rows_are_rejected_and_capped() -> None:
    rows = (
        "CVE-2024-0001,1.5,0.9\nCVE-2024-0002,abc,0.2\nCVE-2024-0003,nan,0.1\nCVE-2024-0004,0.1,0.1,extra\n"
        + "".join(f"CVE-2024-1{i:03d},2,0\n" for i in range(150))
    )
    result = epss.fetch(None, _client(_epss_body(rows)))
    assert result.records == () and len(result.rejected) == 100
    assert {r.reason for r in result.rejected} == {IntelRejection.EPSS_BAD_SCORE, IntelRejection.EPSS_BAD_ROW}


def test_epss_corrupt_or_unexpected_file_fails_the_whole_fetch() -> None:
    for body in (b"not gzip", _epss_body(ROWS, header="a,b,c"), gzip.compress(b"no comment line\n")):
        with pytest.raises(IntelFetchFailed):
            epss.fetch(None, _client(body))


def test_epss_fetches_again_when_the_cves_asked_for_change_on_the_same_score_date() -> None:
    first = epss.fetch(None, _client(_epss_body(ROWS)), only_cves={"CVE-2024-0001"})
    assert epss.fetch(first.checkpoint, _client(_epss_body(ROWS)), only_cves={"CVE-2024-0001"}) is None
    wider = epss.fetch(
        first.checkpoint, _client(_epss_body(ROWS)), only_cves={"CVE-2024-0001", "CVE-2024-0002"}
    )
    assert wider is not None and len(wider.records) == 2
