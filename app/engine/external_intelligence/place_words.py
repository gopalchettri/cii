"""The places and sectors a text names (G232, owner 2026-10-14: threats and actors relevant to the UAE).
Read from a group's ATT&CK description (whom it attacked) and from the asset's own sector facts, with fixed
word lists (PLACE_WORDS, SECTOR_WORDS) matched as whole words: no AI call. Where a group comes from is never
whom it attacked ("a group that targeted the UAE" is never "UAE-based"): what says where it comes from is left
out before the places it attacked are read. Pure."""

import re
from collections.abc import Iterable

from app.core.constants import PLACE_WORDS, SECTOR_WORDS


def _whole_words(words: Iterable[str]) -> re.Pattern[str]:
    alternatives = "|".join(re.escape(word) for word in sorted(words, key=len, reverse=True))
    return re.compile(rf"(?<![\w.])({alternatives})(?!\w)", re.I)


_PLACES = _whole_words(PLACE_WORDS)
_SECTORS = _whole_words(SECTOR_WORDS)
#: What says where a group comes from: "attributed to Russia's GRU", "based in China", "a China-based group",
#: and what a group IS ("is a Middle Eastern threat group", up to the first group or actor).
_ORIGIN = re.compile(
    r"\b(?:attributed|linked|tied|nexus) to\b[^.;]*|\b(?:associated with|on behalf of|sponsored by|backed by|"
    r"based in|operat\w* (?:out of|from)|origins? in)\b[^.;,]*|[\w.]+-based\b|"
    r"\b(?:is|be|was) an? [^.;,]*?\b(?:group|actor)\b",
    re.I,
)


def places_in(text: str) -> list[str]:
    """The places the text names, by their own names ("Emirati" is the United Arab Emirates), sorted."""
    return sorted({PLACE_WORDS[found.casefold()] for found in _PLACES.findall(text)})


def sectors_in(text: str) -> list[str]:
    """The sectors the text names ("airlines" is aviation), sorted."""
    return sorted({SECTOR_WORDS[found.casefold()] for found in _SECTORS.findall(text)})


def targets_of(description: str) -> tuple[list[str], list[str]]:
    """The places and sectors a group's own description says it attacked."""
    attacked = _ORIGIN.sub(" ", description)
    return places_in(attacked), sectors_in(attacked)
