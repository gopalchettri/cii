"""What a hostile or broken server can make a download do: redirect it to another host or to plain http, send
the NVD key along, send an unparseable "retry-after", or send more than the source's file can weigh."""

import json

import httpx
import pytest

from app.core.constants import IntelMessage, IntelSource, SourceDownload
from app.core.exceptions import IntelFetchFailed
from app.domain.intel.sources.attack import MitreAttackSource
from app.domain.intel.sources.common import HttpDownloader
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


@pytest.mark.parametrize("location", ["/other", "https://x.test/other", "https://raw.githubusercontent.com/o"])
def test_a_redirect_to_the_same_host_or_an_allowed_one_over_https_is_followed(location: str) -> None:
    seen: list[str] = []
    assert _redirecting(location, seen).download_if_changed(START, None).body == b"final" and len(seen) == 2


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
        _redirecting(location, seen).download_if_changed(START, None)
    assert seen == [START] and "302" in refused.value.message


def test_a_redirect_loop_is_cut_off() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(307, headers={"location": START})

    with pytest.raises(IntelFetchFailed):
        downloader(handler).download_if_changed(START, None)
    assert len(calls) == SourceDownload.MAX_REDIRECTS + 1


@pytest.mark.parametrize("value", ["²", "1e3", "-5", "1.5", "99999", "", " 5"])
def test_a_retry_after_that_is_not_a_small_whole_number_is_ignored_not_a_crash(value: str) -> None:
    answers, slept = iter([429, 200]), []
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda r: httpx.Response(next(answers), headers=[(b"retry-after", value.encode("latin-1"))])
        )
    )
    assert HttpDownloader(client, sleep=slept.append).download_if_changed(START, None).body == b""
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
        downloader(handler).download_if_changed(START, None)
    assert len(calls) == 1 and failed.value.message == IntelMessage.BAD_FORMAT.format(source=START)


@pytest.fixture
def tiny_caps(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(SourceDownload, "MAX_ATTACK_BYTES", 2_000)


def test_an_oversized_attack_bundle_is_refused(tiny_caps: None) -> None:
    body = json.dumps(attack_fixtures._bundle([{"type": "x", "id": "p" * 3_000}])).encode()
    with pytest.raises(IntelFetchFailed):
        MitreAttackSource(IntelSource.ATTACK_ENTERPRISE, serving(body)).download_changes(None)


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
