"""The evidence of a scenario as the API shows it: only what its own text cites by a marker [n], in the order
the text first cites it, without the reranker's scores; a story citing none shows its closest source as
related intelligence, never numbered (G250). The source's own id and link live here, never in the
story. All of it stays stored with the scenario (content.evidence); a read never needs the intelligence."""

import re
from typing import Any

from pydantic import BaseModel, Field

MARKER = re.compile(r"\[(\d+(?:\s*,\s*\d+)*)\]")
_SHOWN = (
    "n", "ref", "kind", "source", "title", "url", "facts", "applicability",
    "published", "fetched_at", "searched_at", "role", "supports", "scope", "mitigations",
)  # fmt: skip


class EvidenceView(BaseModel):
    n: int | None  # None only on related intelligence: no sentence cites it (G250)
    ref: str
    kind: str
    source: str
    title: str
    url: str
    facts: list[str] = Field(default_factory=list)
    applicability: str | None = None  # only for a vulnerability or advisory; "unknown" stays unknown
    # G229 (owner 2026-10-13): the source's own date, when it was fetched and searched, what it proves
    # (direct: a weakness confirmed in the asset's product; context: otherwise) and the claim it supports.
    published: str | None = None
    fetched_at: str | None = None
    searched_at: str | None = None
    role: str | None = None
    supports: str | None = None
    scope: str | None = None  # G232: country, regional or global: what the source tells about place
    mitigations: list[str] = Field(default_factory=list)  # G234: what reduces it; the control search reads it


def markers_of(text: str) -> list[int]:
    """Every marker number in `text`, in order of appearance ("[1, 2]" gives 1 and 2)."""
    return [int(n) for found in MARKER.findall(text) for n in re.split(r"\s*,\s*", found)]


def related_evidence(content: dict[str, Any]) -> list[EvidenceView]:
    """G250: the closest source of a story that cites none, shown as related intelligence, never numbered."""
    return [
        EvidenceView(**{"n": None} | {key: item[key] for key in _SHOWN if key in item and key != "n"})
        for item in content.get("related_evidence") or []
    ]


def cited_evidence(content: dict[str, Any]) -> list[EvidenceView]:
    """The stored evidence the scenario's statement and risk cite, in marker order; none cited, none shown."""
    by_number = {item.get("n"): item for item in content.get("evidence") or []}
    text = f"{content.get('statement') or ''}\n{content.get('risk_statement') or ''}"
    cited = dict.fromkeys(n for n in markers_of(text) if n in by_number)
    return [
        EvidenceView(**{key: by_number[n].get(key) for key in _SHOWN if key in by_number[n]}) for n in cited
    ]
