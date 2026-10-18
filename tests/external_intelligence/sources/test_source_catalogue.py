"""The catalogue: six sources, in the order they must run, wired to the record store for the CVE ids."""

from app.core.constants import IntelSource
from app.services.external_intelligence.sources.source_catalogue import SourceCatalogue


class _Store:
    def __init__(self) -> None:
        self.asked: list[IntelSource] = []

    def list(self, fields: object = None, **where: IntelSource) -> list[dict[str, str]]:
        self.asked.append(where["source"])
        return [{"external_id": "CVE-2024-0001"}]


def test_every_source_is_built_kev_first_and_nvd_last() -> None:
    fetchers = SourceCatalogue(_Store()).fetchers()  # type: ignore[arg-type]
    order = list(fetchers)
    assert (
        set(order) == set(IntelSource)
        and order[0] == IntelSource.CISA_KEV
        and order[-1] == IntelSource.NIST_NVD
    )
    assert order.index(IntelSource.CISA_KEV) < order.index(IntelSource.FIRST_EPSS)
    assert all(fetcher.source_id == source for source, fetcher in fetchers.items())


def test_the_store_is_asked_when_a_source_runs_not_when_it_is_built() -> None:
    store = _Store()
    SourceCatalogue(store).fetchers()  # type: ignore[arg-type]
    assert store.asked == []
