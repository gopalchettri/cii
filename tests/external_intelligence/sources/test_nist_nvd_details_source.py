"""The NVD adapter on a real-shaped NVD 2.0 answer (trimmed from CVE-2021-44228) served by a mock
transport: no network, no real sleeping."""

import copy
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest
from pydantic import SecretStr

from app.core.constants import IntelKind, IntelLimits, IntelRejection
from app.core.exceptions import IntelFetchFailed
from app.models.external_intelligence.fetch_result import FetchResult
from app.services.external_intelligence.sources import nist_nvd_details_source as nvd_module
from app.services.external_intelligence.sources.nist_nvd_details_source import NistNvdDetailsSource

SLEEPS: list[float] = []


class nvd:  # noqa: N801  # keeps the ported tests' call shape
    @staticmethod
    def fetch(checkpoint, only_cves, client, *, stored=None, api_key=None):
        source = NistNvdDetailsSource(
            lambda: only_cves,
            lambda: stored or set(),
            api_key=None if api_key is None else (lambda: api_key),
            client=client,
            sleep=SLEEPS.append,
        )
        return source.download_changes(checkpoint)


_TIME = "%Y-%m-%dT%H:%M:%S.000+00:00"
_CVSS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"


def _cwe(*values: str) -> dict:
    return {"type": "Secondary", "description": [{"lang": "en", "value": v} for v in values]}


def _cpe(criteria: str, **bounds: str) -> dict:
    return {"vulnerable": True, "criteria": criteria, **bounds}


LOG4SHELL = {
    "cve": {
        "id": "CVE-2021-44228",
        "published": "2021-12-10T10:15:09.143",
        "lastModified": "2026-08-11T19:33:44.513",
        "vulnStatus": "Analyzed",
        "descriptions": [
            {
                "lang": "en",
                "value": "Apache Log4j2 JNDI features do not protect against attacker "
                + "controlled input " * 60,
            },
            {"lang": "es", "value": "otro idioma"},
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "type": "Secondary",
                    "cvssData": {"baseScore": 9.0, "baseSeverity": "CRITICAL", "vectorString": "CVSS:3.1/X"},
                },
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "cvssData": {
                        "version": "3.1",
                        "vectorString": _CVSS,
                        "baseScore": 10.0,
                        "baseSeverity": "CRITICAL",
                    },
                },
            ],
            "cvssMetricV2": [
                {
                    "type": "Primary",
                    "cvssData": {"baseScore": 9.3, "vectorString": "AV:N"},
                    "baseSeverity": "HIGH",
                }
            ],
        },
        "weaknesses": [_cwe("CWE-20", "CWE-502"), _cwe("CWE-20", "NVD-CWE-Other")],
        "configurations": [
            {
                "operator": "AND",
                "nodes": [
                    {
                        "operator": "OR",
                        "negate": False,
                        "cpeMatch": [
                            _cpe(
                                "cpe:2.3:o:siemens:6bk1602-0aa12-0tp0_firmware:*:*:*:*:*:*:*:*",
                                versionEndExcluding="2.7.0",
                            )
                        ],
                    },
                    {
                        "operator": "OR",
                        "negate": False,
                        "cpeMatch": [
                            {
                                "vulnerable": False,
                                "criteria": "cpe:2.3:h:siemens:6bk1602-0aa12-0tp0:-:*:*:*:*:*:*:*",
                            }
                        ],
                    },
                ],
            },
            {
                "nodes": [
                    {
                        "operator": "OR",
                        "negate": False,
                        "cpeMatch": [
                            _cpe(
                                "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                                versionStartIncluding="2.0.1",
                                versionEndExcluding="2.3.1",
                            ),
                            _cpe(
                                "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                                versionStartExcluding="2.4.0",
                                versionEndIncluding="2.12.1",
                            ),
                            _cpe("cpe:2.3:a:apache:log4j:2.0:-:*:*:*:*:*:*"),
                            _cpe("cpe:2.3:a:apache:log4j:2.0:beta9:*:*:*:*:*:*"),
                            _cpe("cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"),
                            _cpe("cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"),
                        ],
                    }
                ]
            },
        ],
        "references": [
            {"url": "https://a.example/1", "tags": ["Patch", "Vendor Advisory"]},
            {"url": "https://a.example/2", "tags": ["Third Party Advisory"]},
            {"url": "https://a.example/1", "tags": ["Patch"]},
            {"url": "https://a.example/3", "tags": ["Patch"]},
            {"url": "https://a.example/4", "tags": ["Patch"]},
            {"url": "https://a.example/5", "tags": ["Patch"]},
        ],
    }
}


def _item(cve: str, modified: str = "2026-09-01T00:00:00.000") -> dict:
    return {"cve": {"id": cve, "lastModified": modified, "published": "2020-01-01T00:00:00.000"}}


class FakeNvd:
    """cveId lookups and lastMod windows over `items`; every request after `ok_first` gets status `fail`."""

    def __init__(self, items: list[dict], *, ok_first: int | None = None, fail: int = 429) -> None:
        self.items = {i["cve"]["id"]: i for i in items}
        self.ok_first, self.fail = ok_first, fail
        self.requests: list[httpx.Request] = []
        self.changed: list[str] = []  # what a lastMod window lists

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.ok_first is not None and len(self.requests) > self.ok_first:
            return httpx.Response(self.fail)
        query = dict(request.url.params)
        found = [self.items[query["cveId"]]] if query.get("cveId") in self.items else []
        if "lastModStartDate" in query:
            found = [self.items[c] for c in self.changed]
        return httpx.Response(200, json={"totalResults": len(found), "vulnerabilities": found})

    @property
    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self))


@pytest.fixture
def sleeps() -> list[float]:
    SLEEPS.clear()
    return SLEEPS


def _fetch(server: FakeNvd, cves: set[str], checkpoint: str | None = None, **kw) -> FetchResult | None:
    kw.setdefault("api_key", "")
    return nvd.fetch(checkpoint, cves, server.client, **kw)


def _days_ago(days: int) -> str:
    return (datetime.now(UTC) - timedelta(days=days)).strftime(_TIME)


def test_the_real_shaped_item_becomes_a_detail_record(sleeps) -> None:
    result = _fetch(FakeNvd([LOG4SHELL]), {"CVE-2021-44228"})
    (record,) = result.records
    assert (record.kind, record.asset_type, record.external_id) == (
        IntelKind.VULNERABILITY_DETAIL,
        "IT",
        "CVE-2021-44228",
    )
    assert record.url == "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
    assert record.modified == "2026-08-11T19:33:44.513"
    assert record.text.startswith("CVE-2021-44228. CVSS 10.0 CRITICAL. Apache Log4j2")
    assert len(record.text) <= IntelLimits.NVD_SUMMARY_MAX_CHARS
    data = record.data
    assert (data["cvss"], data["cvss_vector"], data["severity"]) == (10.0, _CVSS, "CRITICAL")
    assert data["cwes"] == ["CWE-20", "CWE-502"] and data["published"] == "2021-12-10T10:15:09.143"
    assert data["references_patch"] == ["https://a.example/1", "https://a.example/3", "https://a.example/4"]
    json.dumps(data)  # flat JSON types only
    assert result.partial and result.checkpoint.endswith("+00:00")


def test_affected_ranges_exact_versions_and_wildcards(sleeps) -> None:
    listed = _fetch(FakeNvd([LOG4SHELL]), {"CVE-2021-44228"}).records[0].data["affected"]
    affected = {(a["vendor"], a["product"]): a for a in listed}
    assert len(affected) == 3  # the hardware cpe is not vulnerable: not listed
    firmware = affected[("siemens", "6bk1602-0aa12-0tp0_firmware")]
    assert firmware["versions"] == [
        {"start": None, "start_inclusive": True, "end": "2.7.0", "end_inclusive": False}
    ]
    assert firmware["fixed"] == ["2.7.0"]
    log4j = affected[("apache", "log4j")]
    assert log4j["versions"] == [
        {"start": "2.0.1", "start_inclusive": True, "end": "2.3.1", "end_inclusive": False},
        {"start": "2.4.0", "start_inclusive": False, "end": "2.12.1", "end_inclusive": True},
        {"start": "2.0", "start_inclusive": True, "end": "2.0", "end_inclusive": True},
    ]
    assert log4j["fixed"] == ["2.3.1"]
    assert affected[("acme", "widget")] == {
        "vendor": "acme",
        "product": "widget",
        "versions": [],
        "fixed": [],
    }


def test_a_cve_with_no_rating_or_configuration_still_gives_a_record(sleeps) -> None:
    (record,) = _fetch(FakeNvd([_item("CVE-2024-0001")]), {"CVE-2024-0001"}).records
    assert record.data["cvss"] is None and record.data["affected"] == [] and record.data["cwes"] == []
    assert record.text == "CVE-2024-0001."


def test_malformed_items_are_quarantined_not_dropped(sleeps) -> None:
    server = FakeNvd([_item("CVE-2024-0001")])
    server.items["CVE-2024-0002"] = {"cve": {"id": "CVE-2024-0002"}}  # no lastModified
    result = _fetch(server, {"CVE-2024-0001", "CVE-2024-0002"})
    assert [r.external_id for r in result.records] == ["CVE-2024-0001"]
    assert [(r.external_id, r.reason) for r in result.rejected] == [
        ("CVE-2024-0002", IntelRejection.NVD_BAD_ITEM)
    ]


def test_nothing_wanted_asks_nothing() -> None:
    server = FakeNvd([])
    assert _fetch(server, set()) is None and server.requests == []


def test_first_pass_resumes_across_runs_and_later_runs_only_read_what_changed(
    sleeps, monkeypatch: pytest.MonkeyPatch
) -> None:
    ids = ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"]
    server = FakeNvd([_item(c) for c in ids] + [_item("CVE-2099-0001")])
    monkeypatch.setattr(IntelLimits, "NVD_MAX_REQUESTS_PER_RUN", 2)
    run1 = _fetch(server, set(ids))
    assert [r.external_id for r in run1.records] == ids[:2] and run1.partial and run1.more
    # Run 2: one request for the window since run 1, one for the single CVE not yet stored.
    server.requests.clear()
    run2 = _fetch(server, set(ids), run1.checkpoint, stored=set(ids[:2]))
    assert [r.external_id for r in run2.records] == ids[2:]
    params = [dict(r.url.params) for r in server.requests]
    assert params[0]["lastModStartDate"] == run1.checkpoint and params[1] == {"cveId": ids[2]}
    # Run 3: all stored; the window lists one CVE of ours and one we do not track: one request in all.
    server.requests.clear()
    server.changed = [ids[0], "CVE-2099-0001"]
    run3 = _fetch(server, set(ids), run2.checkpoint, stored=set(ids))
    assert [r.external_id for r in run3.records] == [ids[0]] and len(server.requests) == 1
    assert run3.checkpoint >= run2.checkpoint


def test_an_unfinished_window_does_not_advance_the_checkpoint(
    sleeps, monkeypatch: pytest.MonkeyPatch
) -> None:
    def two_pages(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"totalResults": 4000, "vulnerabilities": [_item("CVE-2024-0001")] * 2000}
        )

    monkeypatch.setattr(IntelLimits, "NVD_MAX_REQUESTS_PER_RUN", 1)
    since = _days_ago(2)
    client = httpx.Client(transport=httpx.MockTransport(two_pages))
    result = nvd.fetch(since, {"CVE-2024-0001"}, client, stored=set(), api_key="")
    assert result.checkpoint == since and len(result.records) == 1


def test_a_stale_checkpoint_reads_at_most_the_longest_window(sleeps) -> None:
    old = datetime.fromisoformat(_days_ago(300))
    result = _fetch(FakeNvd([]), {"CVE-2024-0001"}, old.strftime(_TIME), stored={"CVE-2024-0001"})
    expected = old + timedelta(days=IntelLimits.NVD_MAX_WINDOW_DAYS)
    assert datetime.fromisoformat(result.checkpoint) == expected.replace(microsecond=0)


def test_requests_are_paced_by_the_key(sleeps) -> None:
    ids = {"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"}
    _fetch(FakeNvd([_item(c) for c in ids]), ids)
    assert sleeps == [IntelLimits.NVD_SLEEP_UNKEYED_SECONDS] * 2
    sleeps.clear()
    _fetch(FakeNvd([_item(c) for c in ids]), ids, api_key="secret-key")
    assert sleeps == [IntelLimits.NVD_SLEEP_KEYED_SECONDS] * 2


def test_rate_limiting_after_progress_is_partial_not_failure(sleeps) -> None:
    ids = {"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"}
    server = FakeNvd([_item(c) for c in ids], ok_first=1, fail=429)
    result = _fetch(server, ids)
    assert [r.external_id for r in result.records] == ["CVE-2024-0001"] and result.partial
    assert sleeps.count(IntelLimits.NVD_BACKOFF_SECONDS) == IntelLimits.FETCH_ATTEMPTS - 1
    assert len(server.requests) == 1 + IntelLimits.FETCH_ATTEMPTS  # it gave up: no lookups after that


def test_rate_limited_from_the_start_is_a_failure(sleeps) -> None:
    with pytest.raises(IntelFetchFailed):
        _fetch(FakeNvd([_item("CVE-2024-0001")], ok_first=0, fail=503), {"CVE-2024-0001"})


def test_the_api_key_goes_in_a_header_and_never_in_a_url_or_an_error(sleeps) -> None:
    server = FakeNvd([_item("CVE-2024-0001")])
    _fetch(server, {"CVE-2024-0001"}, api_key="top-secret-key")
    assert all("top-secret-key" not in str(r.url) for r in server.requests)
    assert server.requests[0].headers["apiKey"] == "top-secret-key"
    broken = FakeNvd([], ok_first=0, fail=404)
    with pytest.raises(IntelFetchFailed) as error:
        _fetch(broken, {"CVE-2024-0001"}, api_key="top-secret-key")
    assert "top-secret-key" not in str(error.value)


def test_the_key_is_read_from_settings_when_not_passed(sleeps, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = SimpleNamespace(nvd_api_key=SecretStr("env-key"))
    monkeypatch.setattr(nvd_module, "get_settings", lambda: settings)
    server = FakeNvd([_item("CVE-2024-0001")])
    nvd.fetch(None, {"CVE-2024-0001"}, server.client)
    assert server.requests[0].headers["apiKey"] == "env-key"


def test_parsing_does_not_mutate_the_answer(sleeps) -> None:
    before = copy.deepcopy(LOG4SHELL)
    _fetch(FakeNvd([LOG4SHELL]), {"CVE-2021-44228"})
    assert before == LOG4SHELL


def test_more_is_set_only_when_the_budget_or_the_rate_limit_cut_the_run(sleeps) -> None:
    ids = {"CVE-2024-0001", "CVE-2024-0002"}
    assert _fetch(FakeNvd([_item(c) for c in ids]), ids).more is False
    cut = _fetch(FakeNvd([_item(c) for c in ids], ok_first=1), ids)
    assert cut.more is True
