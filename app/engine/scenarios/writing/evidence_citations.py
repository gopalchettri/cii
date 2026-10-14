"""Citation numbers as the final scenario uses them (G224, owner 2026-10-13: "If only one evidence source is
available and supports the claim, cite it as [1], not [2]"; "Every citation must map to an existing evidence
record"). The writer reads the threat's evidence numbered 1..n and may cite any of them; once it has
written, the markers are renumbered 1..k in the order the text first cites them (the statement, then the
risk), a marker naming no entry is dropped, and only the cited entries are kept, each under its new number."""

import re
from collections.abc import Mapping
from typing import Any

_CITATION = re.compile(r"(\s?)\[(\d+(?:\s*,\s*\d+)*)\]")


def renumber_citations(
    statement: str, risk: str, evidence: list[dict[str, Any]], claims: Mapping[int, str] | None = None
) -> tuple[str, str, list[dict[str, Any]]]:
    """(statement, risk, the cited entries with their new `n`): `evidence` as the writer read it, 1..n.
    `claims`: the writer's claim per old number (G229), kept on its entry as `supports`."""
    known = dict(enumerate(evidence, start=1))
    new_number: dict[int, int] = {}

    def rewrite(match: re.Match[str]) -> str:
        numbers: list[int] = []
        for old in (int(n) for n in re.split(r"\s*,\s*", match.group(2))):
            if old in known:
                number = new_number.setdefault(old, len(new_number) + 1)
                numbers += [number] if number not in numbers else []
        return f"{match.group(1)}[{', '.join(map(str, numbers))}]" if numbers else ""

    # A dropped marker at the very start leaves the space after it: the texts are trimmed (G227).
    statement, risk = _CITATION.sub(rewrite, statement).strip(), _CITATION.sub(rewrite, risk).strip()
    supports = claims or {}
    cited = [
        {**known[old], "n": number} | ({"supports": supports[old]} if old in supports else {})
        for old, number in new_number.items()
    ]
    return statement, risk, cited
