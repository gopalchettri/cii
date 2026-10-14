"""Test helpers: a downloader over a mock transport (no network, no real waiting)."""

from collections.abc import Callable

import httpx

from app.services.external_intelligence.sources.http_download import HttpDownloader


def downloader(handler: Callable[[httpx.Request], httpx.Response]) -> HttpDownloader:
    client = httpx.Client(transport=httpx.MockTransport(handler))
    return HttpDownloader(client, sleep=lambda _seconds: None)


def serving(body: bytes) -> HttpDownloader:
    return downloader(lambda request: httpx.Response(200, content=body))
