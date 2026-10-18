"""What a hostile or broken server can make a download do: redirect it to another host or to plain http, send
the NVD key along, send an unparseable "retry-after", or send more than the source's file can weigh."""

import copy
import gzip
import json

import httpx
import pytest

from app.core.constants import IntelMessage, IntelSource, SourceDownload
from app.core.exceptions import IntelFetchFailed
from app.services.external_intelligence.sources.cisa_known_exploited_source import CisaKnownExploitedSource
from app.services.external_intelligence.sources.first_epss_scores_source import FirstEpssScoresSource
from app.services.external_intelligence.sources.http_download import HttpDownloader
from app.services.external_intelligence.sources.mitre_attack_source import MitreAttackSource
from app.services.external_intelligence.sources.nist_nvd_details_source import NvdApiClient
from tests.external_intelligence.sources import test_cisa_ics_advisories_source as ics_fixtures
from tests.external_intelligence.sources import test_kev_and_epss_sources as kev_fixtures
from tests.external_intelligence.sources import test_mitre_attack_source as attack_fixtures
from tests.external_intelligence.sources.web import downloader, serving

START = "https://x.test/start"


def _redirecting(location: str, seen: list[str], status: int = 302) -> HttpDownloader:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if request.url.path == "/start":
            return httpx.Response(status, headers={"location": location})
        return httpx.Response(200, content=b"final")

    return downloader(handler)


@pytest.mark.parametrize(
    "location",
    ["/other", "https://x.test/other", "https://raw.githubusercontent.com/o", "https://www.cisa.gov/o"],
)
def test_a_redirect_to_the_same_host_or_an_allowed_one_over_https_is_followed(location: str) -> None:
    seen: list[str] = []
    assert _redirecting(location, seen).download(START) == b"final" and len(seen) == 2


@pytest.mark.parametrize(
    "location",
    [
        "https://evil.test/f",
        "http://x.test/f",
        "https://x.test.evil.test/f",
        "https://evil.test/?next=https://x.test/f",
        "https://user@x.test.evil.test/f",
        "ftp://x.test/f",
        "//evil.test/f",
        "",
    ],
)
def test_a_redirect_to_another_host_or_to_http_is_refused_and_never_requested(location: str) -> None:
    seen: list[str] = []
    with pytest.raises(IntelFetchFailed) as refused:
        _redirecting(location, seen).download(START)
    assert seen == [START] and "302" in refused.value.message


def test_a_redirect_loop_is_cut_off() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(307, headers={"location": START})

    with pytest.raises(IntelFetchFailed):
        downloader(handler).download(START)
    assert len(calls) == SourceDownload.MAX_REDIRECTS + 1


def test_the_nvd_key_is_never_sent_to_another_host_because_nvd_is_never_redirected() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(302, headers={"location": "https://evil.test/steal"})

    client = NvdApiClient("SECRET-KEY", httpx.Client(transport=httpx.MockTransport(handler)), lambda _s: None)
    with pytest.raises(IntelFetchFailed) as refused:
        client.get({"cveId": "CVE-2024-0001"})
    assert [r.url.host for r in seen] == ["services.nvd.nist.gov"] and "302" in refused.value.message
    assert all("evil.test" not in str(r.url) for r in seen)


@pytest.mark.parametrize("value", ["²", "1e3", "-5", "1.5", "99999", "", " 5"])
def test_a_retry_after_that_is_not_a_small_whole_number_is_ignored_not_a_crash(value: str) -> None:
    answers, slept = iter([429, 200]), []
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda r: httpx.Response(next(answers), headers=[(b"retry-after", value.encode("latin-1"))])
        )
    )
    assert HttpDownloader(client, sleep=slept.append).download(START) == b""
    assert slept == [2]


@pytest.mark.parametrize("error", [httpx.DecodingError("bad gzip"), httpx.TooManyRedirects("loop")])
def test_a_request_error_that_is_not_a_transport_error_fails_the_source_without_a_retry(
    error: httpx.RequestError,
) -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        raise error

    with pytest.raises(IntelFetchFailed) as failed:
        downloader(handler).download(START)
    assert len(calls) == 1 and failed.value.message == IntelMessage.BAD_FORMAT.format(source=START)


@pytest.fixture
def tiny_caps(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("MAX_KEV_BYTES", "MAX_ATTACK_BYTES", "MAX_ICS_FILE_BYTES", "MAX_ICS_CHANGES_BYTES"):
        monkeypatch.setattr(SourceDownload, name, 2_000)
    monkeypatch.setattr(SourceDownload, "MAX_NVD_PAGE_BYTES", 2_000)


def test_each_source_has_its_own_cap_below_the_general_one(tiny_caps: None) -> None:
    assert SourceDownload.MAX_BYTES > 2_000
    big = b"x" * 2_001
    with pytest.raises(IntelFetchFailed):
        CisaKnownExploitedSource(serving(big)).download_changes(None)
    with pytest.raises(IntelFetchFailed):
        MitreAttackSource(IntelSource.ATTACK_ICS, serving(big)).download_changes(None)


def test_an_oversized_kev_catalogue_is_refused_while_a_normal_one_reads(tiny_caps: None) -> None:
    body = kev_fixtures._kev_body([kev_fixtures.GOOD])
    assert len(body) < 2_000
    assert CisaKnownExploitedSource(serving(body)).download_changes(None)
    padded = kev_fixtures._kev_body([kev_fixtures.GOOD | {"shortDescription": "a" * 3_000}])
    with pytest.raises(IntelFetchFailed):
        CisaKnownExploitedSource(serving(padded)).download_changes(None)


def test_an_oversized_attack_bundle_is_refused(tiny_caps: None) -> None:
    body = json.dumps(attack_fixtures._bundle([{"type": "x", "id": "p" * 3_000}])).encode()
    with pytest.raises(IntelFetchFailed):
        MitreAttackSource(IntelSource.ATTACK_ENTERPRISE, serving(body)).download_changes(None)


def test_an_oversized_ics_listing_fails_the_run(tiny_caps: None) -> None:
    rows = [(f"2026/icsa-26-{n:03d}-01.json", ics_fixtures.NEW) for n in range(100)]
    with pytest.raises(IntelFetchFailed):
        ics_fixtures.ics_advisories.fetch(None, ics_fixtures._client(rows), ics_fixtures.NOW)


def test_an_oversized_ics_advisory_is_a_failed_file_not_a_parsed_one(tiny_caps: None) -> None:
    files = {"2026/icsa-26-279-04.json": b"{" + b" " * 3_000 + b"}"}
    client = ics_fixtures._client([("2026/icsa-26-279-04.json", ics_fixtures.NEW)], files)
    with pytest.raises(IntelFetchFailed):  # the only file failed: the host looks unreachable
        ics_fixtures.ics_advisories.fetch(None, client, ics_fixtures.NOW)


def test_an_epss_first_line_is_read_at_most_to_its_cap() -> None:
    header = b"cve,epss,percentile\n"
    ok = gzip.compress(b"#model_version:v1,score_date:2026-10-12T00:00:00Z\n" + header)
    assert FirstEpssScoresSource(lambda: {"CVE-2024-0001"}, serving(ok)).download_changes(None)
    for first in (
        b"#" + b"A" * 5_000 + b"\n",
        b"#model_version:v1,score_date:2026-10-12T00:00:00Z" + b"," * 2_000,
    ):
        body = gzip.compress(first + header)
        with pytest.raises(IntelFetchFailed) as refused:
            FirstEpssScoresSource(lambda: {"CVE-2024-0001"}, serving(body)).download_changes(None)
        assert refused.value.message == IntelMessage.BAD_FORMAT.format(source=IntelSource.FIRST_EPSS)


def _ics_with_page(url: str) -> dict:
    doc = copy.deepcopy(ics_fixtures.FILES["2026/icsa-26-279-04.json"])
    doc["document"]["references"] = [{"category": "self", "url": url}]
    return doc


@pytest.mark.parametrize(
    "url, kept",
    [
        ("https://www.cisa.gov/news-events/ics-advisories/icsa-26-279-04", True),
        ("https://cisa.gov/a", True),
        ("https://evil.example/?x=cisa.gov/", False),
        ("https://cisa.gov.evil.example/a", False),
        ("https://evilcisa.gov/a", False),
        ("http://www.cisa.gov/a", False),
        ("https://user@evil.example/cisa.gov/", False),
    ],
)
def test_an_ics_page_link_must_be_https_on_cisa_gov_else_the_canonical_page_is_used(
    url: str, kept: bool
) -> None:
    files = {"2026/icsa-26-279-04.json": _ics_with_page(url)}
    client = ics_fixtures._client([("2026/icsa-26-279-04.json", ics_fixtures.NEW)], files)
    record = ics_fixtures.ics_advisories.fetch(None, client, ics_fixtures.NOW).records[0]
    assert record.url == (url if kept else "https://www.cisa.gov/news-events/ics-advisories/icsa-26-279-04")


@pytest.mark.parametrize(
    "url, kept",
    [
        ("https://attack.mitre.org/techniques/T1059/001", True),
        ("https://evil.example/?x=attack.mitre.org/", False),
        ("https://attack.mitre.org.evil.example/t", False),
        ("http://attack.mitre.org/techniques/T1059/001", False),
        ("https://evil.example/techniques/T1059/001", False),
    ],
)
def test_an_attack_technique_link_must_be_https_on_attack_mitre_org_else_the_page_is_built_from_the_id(
    url: str, kept: bool
) -> None:
    bundle = attack_fixtures._bundle()
    technique = next(o for o in bundle["objects"] if o.get("id") == "t--1")
    technique["external_references"][0]["url"] = url
    body = json.dumps(bundle).encode()
    [record] = MitreAttackSource(IntelSource.ATTACK_ENTERPRISE, serving(body)).download_changes(None).records
    assert record.url == (url if kept else "https://attack.mitre.org/techniques/T1059/001")


def test_a_future_change_time_never_becomes_the_checkpoint() -> None:
    future = "9999-01-01T00:00:00.000000Z"
    listing = [("2026/icsa-26-279-04.json", ics_fixtures.NEW), ("2026/icsa-26-281-01.json", future)]
    result = ics_fixtures.ics_advisories.fetch(None, ics_fixtures._client(listing), ics_fixtures.NOW)
    assert [r.external_id for r in result.records] == ["ICSA-26-279-04"]
    assert result.checkpoint == ics_fixtures.NEW


def test_a_checkpoint_already_in_the_future_is_dropped_so_the_source_is_not_stalled() -> None:
    future = "9999-01-01T00:00:00.000000Z"
    listing = [("2026/icsa-26-279-04.json", ics_fixtures.NEW)]
    result = ics_fixtures.ics_advisories.fetch(future, ics_fixtures._client(listing), ics_fixtures.NOW)
    assert result is not None and result.checkpoint == ics_fixtures.NEW
    result = ics_fixtures.ics_advisories.fetch(
        f"{future}|2026/icsa-26-279-04.json=2", ics_fixtures._client(listing), ics_fixtures.NOW
    )
    assert result is not None and result.checkpoint == ics_fixtures.NEW
