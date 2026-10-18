"""The evidence of a scenario as the API shows it: only what its own text cites by a marker [n], in the order
the text first cites it, without the reranker's scores. The source's own id and link live here, never in the
story. All of it stays stored with the scenario (content.evidence); a read never needs the intelligence."""

import re
from typing import Any

from pydantic import BaseModel, Field

MARKER = re.compile(r"\[(\d+(?:\s*,\s*\d+)*)\]")
_SHOWN = (
    "n", "ref", "kind", "source", "title", "url", "facts", "applicability",
    "published", "modified", "fetched_at", "searched_at", "role", "supports", "mitigations",
)  # fmt: skip


class EvidenceView(BaseModel):
    """One cited evidence entry as the API serves it."""

    n: int
    ref: str
    kind: str
    source: str
    title: str
    url: str
    facts: list[str] = Field(default_factory=list)
    applicability: str | None = None  # only for a vulnerability or advisory; "unknown" stays unknown
    published: str | None = None
    modified: str | None = None  # the source's last change to the record
    fetched_at: str | None = None
    searched_at: str | None = None
    role: str | None = None  # direct: a weakness confirmed in the asset's product; context: otherwise
    supports: str | None = None  # the claim it supports
    mitigations: list[str] = Field(default_factory=list)  # what reduces it; the control search reads it


def markers_of(text: str) -> list[int]:
    """Every marker number in `text`, in order of appearance ("[1, 2]" gives 1 and 2)."""
    return [int(n) for found in MARKER.findall(text) for n in re.split(r"\s*,\s*", found)]


def cited_evidence(content: dict[str, Any]) -> list[EvidenceView]:
    """The stored evidence the scenario's statement and risk cite, in marker order; none cited, none shown."""
    by_number = {item.get("n"): _with_modified_date(item) for item in content.get("evidence") or []}
    text = f"{content.get('statement') or ''}\n{content.get('risk_statement') or ''}"
    cited = dict.fromkeys(n for n in markers_of(text) if n in by_number)
    return [
        EvidenceView(**{key: by_number[n].get(key) for key in _SHOWN if key in by_number[n]}) for n in cited
    ]


def _with_modified_date(item: dict[str, Any]) -> dict[str, Any]:
    """An entry stored with no `modified` field held the source's last-modified date in `published`: served
    as `modified`, with `published` null."""
    return item if "modified" in item else item | {"modified": item.get("published"), "published": None}
