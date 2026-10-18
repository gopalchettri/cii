"""The CISA ICS (CSAF) adapter on small real-shaped advisories served by a mock transport (no network)."""

import json
from datetime import UTC, datetime

import httpx
import pytest

from app.core.constants import IntelKind, IntelLimits, IntelRejection, IntelSource, IntelUrl
from app.core.exceptions import IntelFetchFailed
from app.services.external_intelligence.sources.cisa_ics_advisories_source import CisaIcsAdvisoriesSource
from app.services.external_intelligence.sources.ics_advisory_reader import parse_versions
from tests.external_intelligence.sources.web import downloader

NOW = datetime(2026, 10, 12, tzinfo=UTC)
NEW, MID, OLD, TOO_OLD = (
    "2026-10-08T06:00:00.000000Z",
    "2026-07-01T06:00:00.000000Z",
    "2025-01-15T06:00:00.000000Z",
    "2023-05-01T06:00:00.000000Z",
)


def _doc(advisory_id: str, title: str, branches: list, vulns: list) -> dict:
    page = f"https://www.cisa.gov/news-events/ics-advisories/{advisory_id.lower()}"
    return {
        "document": {
            "notes": [
                {"category": "summary", "title": "Summary", "text": "<p>Remote code execution &amp; DoS.</p>"}
            ],
            "references": [
                {"category": "self", "url": "https://raw.githubusercontent.com/cisagov/CSAF/x.json"},
                {"category": "self", "url": page},
            ],
            "title": title,
            "tracking": {
                "id": advisory_id,
                "initial_release_date": "2026-09-29T00:00:00.000000Z",
                "current_release_date": NEW,
            },
        },
        "product_tree": {"branches": branches},
        "vulnerabilities": vulns,
    }


def _leaf(category: str, name: str, pid: str) -> dict:
    return {"category": category, "name": name, "product": {"name": f"p {name}", "product_id": pid}}


def _vendor(vendor: str, product: str, leaves: list) -> list:
    return [
        {
            "category": "vendor",
            "name": vendor,
            "branches": [{"category": "product_name", "name": product, "branches": leaves}],
        }
    ]


SOI = _doc(
    "ICSA-26-279-04",
    "Hitachi Energy SOI",
    _vendor(
        "Hitachi Energy",
        "SOI",
        [
            _leaf("product_version_range", "vers:SOI/>=2.0.0|<=2.2.0", "P1"),
            _leaf("product_version", "2.3.0", "P2"),
            _leaf("product_version_range", "vers:all/*", "P3"),
        ],
    ),
    [
        {
            "cve": "CVE-2026-34197",
            "product_status": {"known_affected": ["P1"], "fixed": ["P2", "P3"]},
            "remediations": [
                {"category": "vendor_fix", "details": "Apply the patch SOI EP2."},
                {"category": "mitigation", "details": "Segment the network."},
                {"category": "none_available", "details": "ignored"},
            ],
            "scores": [{"cvss_v3": {"baseScore": 8.8}}, {"cvss_v4": {"baseScore": 9.3}}],
        },
        {
            "cve": "CVE-2026-0001",
            "product_status": {"known_affected": ["P1"]},
            "scores": [{"cvss_v3": {"baseScore": 5}}],
        },
    ],
)
RED_LION = _doc(
    "ICSA-26-281-01",
    "Red Lion N-Tron 700 Series",
    _vendor(
        "Red Lion Controls",
        "700 Series",
        [
            _leaf("product_version_range", "<=Firmware_3.11.0", "P1"),
            _leaf("product_version_range", "vers:all/*", "P2"),
        ],
    ),
    [{"cve": "CVE-2026-32645", "product_status": {"known_affected": ["P1", "P2"]}}],
)
FILES = {
    "2026/icsa-26-279-04.json": SOI,
    "2026/icsa-26-281-01.json": RED_LION,
}
PREFIX = "/cisagov/CSAF/develop/csaf_files/OT/white/"


class ics_advisories:  # noqa: N801  # keeps the ported tests' call shape
    @staticmethod
    def fetch(checkpoint, web, now):
        return CisaIcsAdvisoriesSource(web, clock=lambda: now).download_changes(checkpoint)


def _csv(rows: list[tuple[str, str]]) -> bytes:
    return "".join(f'"{path}","{stamp}"\r\n' for path, stamp in rows).encode()


def _client(listing: list[tuple[str, str]], files: dict | None = None, seen: list | None = None):
    files = FILES if files is None else files

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix(PREFIX)
        if seen is not None:
            seen.append(path)
        if path == "changes.csv":
            return httpx.Response(200, content=_csv(listing))
        body = files.get(path)
        if body is None:
            return httpx.Response(404)
        return httpx.Response(200, content=body if isinstance(body, bytes) else json.dumps(body).encode())

    return downloader(handler)


def test_advisory_becomes_an_ot_record_with_ranges_fixes_cves_and_score() -> None:
    result = ics_advisories.fetch(None, _client([("2026/icsa-26-279-04.json", NEW)]), NOW)
    record = result.records[0]
    assert (record.source, record.kind, record.asset_type) == (IntelSource.CISA_ICS, IntelKind.ADVISORY, "OT")
    assert (record.external_id, record.title, record.modified) == (
        "ICSA-26-279-04",
        "Hitachi Energy SOI",
        NEW,
    )
    assert record.url == "https://www.cisa.gov/news-events/ics-advisories/icsa-26-279-04"
    assert record.data == {
        "advisory_id": "ICSA-26-279-04",
        "vendor": "Hitachi Energy",
        "cves": ["CVE-2026-34197", "CVE-2026-0001"],
        "cvss_max": 9.3,
        "published": "2026-09-29T00:00:00.000000Z",
        "affected": [
            {
                "vendor": "Hitachi Energy",
                "product": "SOI",
                "versions": [{"start": "2.0.0", "end": "2.2.0", "end_inclusive": True}],
                "fixed": ["2.3.0"],
            }
        ],
        "mitigations": ["Apply the patch SOI EP2.", "Segment the network."],
    }
    assert record.text.startswith("ICSA-26-279-04 Hitachi Energy SOI. ") and len(record.text) <= 1500
    assert "Remote code execution & DoS." in record.text and "<p>" not in record.text
    assert "Fixed in: SOI 2.3.0." in record.text and "Mitigations: Apply the patch SOI EP2." in record.text
    assert (result.checkpoint, result.rejected) == (NEW, ())


def test_unparseable_version_stays_empty_and_its_wording_goes_to_the_text_only() -> None:
    record = ics_advisories.fetch(None, _client([("2026/icsa-26-281-01.json", NEW)]), NOW).records[0]
    (group,) = record.data["affected"]
    assert group["versions"] == [{"start": None, "end": None, "end_inclusive": False}]  # only "all versions"
    assert "<=Firmware_3.11.0" in record.text and "all versions" in record.text
    assert "Firmware" not in json.dumps(record.data)


@pytest.mark.parametrize(
    ("wording", "expected"),
    [
        ("<=Firmware_3.11.0", []),
        (">V3.0|<V4.0", []),
        ("!=2.0", []),
        ("<V8.0", [(None, "8.0", False)]),
        ("<= 11.3", [(None, "11.3", True)]),
        (">= 1.0, < 2.0", [("1.0", "2.0", False)]),
        ("vers:intdot/>=2022.4|<2023.1", [("2022.4", "2023.1", False)]),
        ("3.5|3.0_SP1", [("3.5", "3.5", True), ("3.0_SP1", "3.0_SP1", True)]),
        (">=5", [("5", None, False)]),
    ],
)
def test_version_wording(wording: str, expected: list) -> None:
    assert [(r["start"], r["end"], r["end_inclusive"]) for r in parse_versions(wording)] == expected


def test_checkpoint_downloads_only_newer_advisories() -> None:
    listing = [("2026/icsa-26-281-01.json", NEW), ("2026/icsa-26-279-04.json", MID)]
    seen: list[str] = []
    result = ics_advisories.fetch(MID, _client(listing, seen=seen), NOW)
    assert seen == ["changes.csv", "2026/icsa-26-281-01.json"]
    assert [r.external_id for r in result.records] == ["ICSA-26-281-01"] and result.checkpoint == NEW
    assert ics_advisories.fetch(NEW, _client(listing), NOW) is None


def test_first_run_reads_only_the_last_24_months() -> None:
    listing = [
        ("2026/icsa-26-281-01.json", NEW),
        ("2026/icsa-26-279-04.json", OLD),
        ("2023/icsa-23-1.json", TOO_OLD),
    ]
    seen: list[str] = []
    result = ics_advisories.fetch(None, _client(listing, seen=seen), NOW)
    assert "2023/icsa-23-1.json" not in seen and len(result.records) == 2
    assert result.checkpoint == NEW


def test_per_run_cap_stops_at_a_change_time_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(IntelLimits, "ICS_MAX_PER_RUN", 2)
    listing = [
        ("2026/icsa-26-281-01.json", NEW),
        ("2026/icsa-26-279-04.json", MID),
        ("2025/icsa-25-1.json", MID),
        ("2025/icsa-25-2.json", OLD),
    ]
    files = FILES | {"2025/icsa-25-1.json": SOI, "2025/icsa-25-2.json": SOI}
    seen: list[str] = []
    first = ics_advisories.fetch(None, _client(listing, files, seen), NOW)
    assert (
        seen[1:] == ["2025/icsa-25-2.json"] and first.checkpoint == OLD
    )  # MID's two files would pass the cap
    seen.clear()
    second = ics_advisories.fetch(first.checkpoint, _client(listing, files, seen), NOW)
    assert seen[1:] == ["2025/icsa-25-1.json", "2026/icsa-26-279-04.json"] and second.checkpoint == MID


LISTING = [
    ("2026/icsa-26-279-04.json", MID),
    ("2026/icsa-26-001-01.json", MID),
    ("2026/icsa-26-001-02.json", MID),
    ("2026/icsa-26-001-03.json", NEW),
]
FILES_WITH_A_HOLE = {
    "2026/icsa-26-279-04.json": SOI,
    "2026/icsa-26-001-01.json": b"{not json",
    "2026/icsa-26-001-03.json": {"document": {"title": "no id"}},
}  # icsa-26-001-02 answers 404


def test_a_broken_file_is_rejected_and_a_missing_one_is_retried_not_skipped() -> None:
    result = ics_advisories.fetch(None, _client(LISTING, FILES_WITH_A_HOLE), NOW)
    assert [r.external_id for r in result.records] == ["ICSA-26-279-04"]
    assert sorted((r.external_id, r.reason) for r in result.rejected) == [
        ("ICSA-26-001-01", IntelRejection.ICS_BAD_ADVISORY),
        ("ICSA-26-001-03", IntelRejection.ICS_BAD_ADVISORY),
    ]
    assert all(r.raw_hash for r in result.rejected)
    # The checkpoint stays BEFORE the failed file (the first-run floor: nothing earlier was done), and the
    # file is remembered with one failed run: it is read again next time.
    stamp, _, failed = result.checkpoint.partition("|")
    assert stamp < MID and failed == "2026/icsa-26-001-02.json=1"
    assert result.partial and not result.more


def test_the_checkpoint_stops_before_the_first_failed_file_even_when_later_files_were_read() -> None:
    listing = [
        ("2026/icsa-26-279-04.json", OLD),
        ("2026/icsa-26-001-02.json", MID),
        ("2026/icsa-26-281-01.json", NEW),
    ]
    result = ics_advisories.fetch(None, _client(listing), NOW)
    assert sorted(r.external_id for r in result.records) == ["ICSA-26-279-04", "ICSA-26-281-01"]
    assert result.checkpoint == f"{OLD}|2026/icsa-26-001-02.json=1"


def test_a_file_that_failed_once_is_read_again_and_the_checkpoint_then_moves_on() -> None:
    listing = [("2026/icsa-26-279-04.json", OLD), ("2026/icsa-26-281-01.json", MID)]
    held = ics_advisories.fetch(None, _client(listing, {"2026/icsa-26-279-04.json": SOI}), NOW)
    assert held.checkpoint == f"{OLD}|2026/icsa-26-281-01.json=1"
    healed = ics_advisories.fetch(held.checkpoint, _client(listing), NOW)
    assert [r.external_id for r in healed.records] == ["ICSA-26-281-01"]
    assert healed.checkpoint == MID  # no failed file left: plain change time


def test_a_file_that_keeps_failing_is_rejected_after_three_runs_and_stops_blocking() -> None:
    listing = [
        ("2026/icsa-26-279-04.json", OLD),
        ("2026/icsa-26-001-02.json", MID),
        ("2026/icsa-26-281-01.json", NEW),
    ]
    checkpoint = None
    for run in (1, 2):
        result = ics_advisories.fetch(checkpoint, _client(listing), NOW)
        checkpoint = result.checkpoint
        assert checkpoint.endswith(f"icsa-26-001-02.json={run}") and not result.rejected
    final = ics_advisories.fetch(checkpoint, _client(listing), NOW)
    assert [(r.external_id, r.reason) for r in final.rejected] == [
        ("ICSA-26-001-02", IntelRejection.ICS_DOWNLOAD_FAILED)
    ]
    assert final.checkpoint == NEW  # the dead file no longer holds the checkpoint back


def test_failures_while_the_whole_host_is_down_are_not_counted_against_the_files() -> None:
    listing = [("2026/icsa-26-001-01.json", MID), ("2026/icsa-26-001-02.json", NEW)]
    with pytest.raises(IntelFetchFailed):
        ics_advisories.fetch(None, _client(listing, {}), NOW)


def test_host_down_fails_the_run_so_the_checkpoint_does_not_move() -> None:
    listing = [(f"2026/icsa-26-001-0{n}.json", NEW) for n in range(IntelLimits.ICS_MAX_CONSECUTIVE_FAILURES)]
    with pytest.raises(IntelFetchFailed):
        ics_advisories.fetch(None, _client(listing, {}), NOW)


def test_an_unusable_listing_fails_the_run() -> None:
    client = downloader(lambda request: httpx.Response(200, content=b"<html>"))
    with pytest.raises(IntelFetchFailed):
        ics_advisories.fetch(None, client, NOW)
    assert IntelUrl.ICS_CHANGES.endswith("changes.csv")
