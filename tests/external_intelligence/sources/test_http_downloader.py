"""The downloader: retries, refusals, conditional requests, size limit, shared connection, and the reason a
source that never answered gives."""

import httpx
import pytest

from app.core.constants import SourceDownload
from app.core.exceptions import IntelFetchFailed
from app.services.external_intelligence.sources.http_download import HttpDownloader
from app.services.external_intelligence.sources.nist_nvd_details_source import NvdApiClient


def _web(handler, slept: list[float] | None = None) -> HttpDownloader:
    client = httpx.Client(transport=httpx.MockTransport(handler))
    return HttpDownloader(client, sleep=(slept if slept is not None else []).append)


def test_a_busy_source_is_retried_with_back_off_then_answers() -> None:
    answers, slept = iter([503, 429, 200]), []
    web = _web(lambda r: httpx.Response(next(answers), content=b"ok"), slept)
    assert web.download("https://x.test/f") == b"ok"
    assert slept == [2, 4]


def _never_answers(error: httpx.TransportError):
    def handler(request: httpx.Request) -> httpx.Response:
        raise error

    return handler


def test_a_source_that_never_answers_fails_with_the_enum_message_and_its_reason() -> None:
    with pytest.raises(IntelFetchFailed) as error:
        _web(_never_answers(httpx.ConnectError("down"))).download("https://x.test/f")
    # G263: "did not answer" alone hid that the proxy was switched off (UAT, 2026-10-16)
    expected = "https://x.test/f did not answer after 3 attempts (last: ConnectError: down)."
    assert error.value.message == expected


def test_a_source_busy_on_every_try_names_its_last_status() -> None:
    with pytest.raises(IntelFetchFailed) as error:
        _web(lambda r: httpx.Response(503)).download("https://x.test/f")
    assert error.value.message.endswith("(last: HTTP 503).")


def test_the_reason_never_shows_a_proxy_password_or_an_internal_host() -> None:
    refused = httpx.ProxyError("407 from http://ops:S3cret-pw@proxy.corp.local:8080")
    with pytest.raises(IntelFetchFailed) as error:
        _web(_never_answers(refused)).download("https://x.test/f")
    assert "ProxyError: 407" in error.value.message
    assert "S3cret-pw" not in error.value.message and "corp.local" not in error.value.message


@pytest.mark.parametrize(
    ("answer", "reason"),
    [(httpx.ConnectTimeout("timed out"), "ConnectTimeout: timed out"), (503, "HTTP 503")],
)
def test_nvd_names_the_reason_too(answer: httpx.TransportError | int, reason: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if isinstance(answer, int):
            return httpx.Response(answer)
        raise answer

    client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(IntelFetchFailed) as error:
        NvdApiClient("", client, sleep=lambda _seconds: None).get({})
    assert error.value.message.endswith(f"(last: {reason}).")


def test_a_refusal_fails_at_once_without_a_retry() -> None:
    calls = []
    web = _web(lambda r: calls.append(1) or httpx.Response(404))
    with pytest.raises(IntelFetchFailed) as error:
        web.download("https://x.test/f")
    assert len(calls) == 1 and "404" in error.value.message


def test_retry_after_is_honoured_but_capped() -> None:
    answers, slept = iter([429, 200]), []
    web = _web(lambda r: httpx.Response(next(answers), headers={"retry-after": "999"}), slept)
    web.download("https://x.test/f")
    assert slept == [60]


def test_a_conditional_request_sends_the_etag_and_a_304_means_nothing_new() -> None:
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("if-none-match"))
        if request.headers.get("if-none-match") == '"v1"':
            return httpx.Response(304)
        return httpx.Response(200, content=b"body", headers={"etag": '"v1"'})

    web = _web(handler)
    first = web.download_if_changed("https://x.test/f", None)
    assert (first.body, first.etag) == (b"body", '"v1"')
    assert web.download_if_changed("https://x.test/f", first.etag) is None
    assert seen == [None, '"v1"']


def test_a_body_over_the_size_limit_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(SourceDownload, "MAX_BYTES", 10)
    with pytest.raises(IntelFetchFailed):
        _web(lambda r: httpx.Response(200, content=b"x" * 100)).download("https://x.test/f")


def test_a_batch_shares_one_downloader_when_a_client_was_given() -> None:
    web = _web(lambda r: httpx.Response(200, content=b"a"))
    with web.batch() as shared:
        assert shared is web and shared.download("https://x.test/f") == b"a"
