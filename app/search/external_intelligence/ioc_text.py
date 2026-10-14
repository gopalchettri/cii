"""Indicators of compromise (links, addresses, mail, file hashes) are not meaning: they are taken out of
a text before it is embedded, keyword-indexed or reranked: no record or query sends them to a model."""

import re

_INDICATOR = re.compile(
    "|".join(
        [
            r"\b(?:https?|hxxps?|ftp)://\S+",
            r"\bwww\.\S+",
            r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b",
            r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
            r"\b[a-f0-9]{32,128}\b",
        ]
    ),
    re.IGNORECASE,
)
_SPACES = re.compile(r"\s+")


def remove_indicators(text: str) -> str:
    """The text without indicators, spaces collapsed."""
    return _SPACES.sub(" ", _INDICATOR.sub(" ", text)).strip()
