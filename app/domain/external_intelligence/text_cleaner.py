"""The gate every stored string passes again before it becomes part of a fact (plain words, no markup, link or
id; dropped, never repaired), and the grammar of a NAME field (a few words, never a sentence)."""

import re
from typing import Any

from app.core.constants import FactWordLimits, NameGrammar
from app.domain.external_intelligence.untrusted_text import UntrustedTextSanitiser
from app.domain.shared.names import TECHNIQUE_CODE

_PLAIN = re.compile(r"[\w .,'’&()/+:;%\-]+")
#: A public number a business reader cannot use: CVE, CISA ICS advisory, GitHub, Microsoft bulletin, CERT/CC,
#: CAPEC pattern, ATT&CK / ATLAS technique. The evidence panel shows them; the story never does.
ID_IN_TEXT = re.compile(
    r"(?<![\w.-])(?:CVE-\d{4}-\d{4,}|ICSM?A-\d{2}-\d{3}-\d{2}[A-Z]?|GHSA(?:-[0-9a-z]{4}){3}|MS\d{2}-\d{3}"
    rf"|CAPEC-\d+|{TECHNIQUE_CODE})(?![\w-])|\bVU#\d+",
    re.IGNORECASE,
)
_LINK = re.compile(r"(?:https?|ftp)://|www\.", re.IGNORECASE)
_NAME = re.compile(r"[\w.&'()/+@\-]+(?: [\w.&'()/+@\-]+)*")  # "@" for admin@338, an ATT&CK group
#: An ATT&CK tactic as the source writes it ("initial-access", "command-and-control").
_TACTIC = re.compile(r"[a-z][a-z0-9]{0,29}(?:-[a-z0-9]{1,30}){0,4}")


class TextCleaner:
    """Sanitises a string once more and keeps it only when it reads as plain words."""

    def __init__(self, sanitiser: UntrustedTextSanitiser | None = None) -> None:
        self._sanitiser = sanitiser or UntrustedTextSanitiser()

    def clean(self, value: Any, max_chars: int) -> str | None:
        """The string in plain words, or None when it must not be used (not a string, empty, longer than
        `max_chars`, flagged by the sanitiser, markup, a link or an id). Never cut."""
        if not isinstance(value, str):
            return None
        text = " ".join(value.split())
        if not text or len(text) > max_chars:
            return None
        result = self._sanitiser.sanitise(text, max_chars)
        if result.unsafe:
            return None
        cleaned = " ".join(result.text.split())
        if (
            not cleaned
            or not _PLAIN.fullmatch(cleaned)
            or ID_IN_TEXT.search(cleaned)
            or _LINK.search(cleaned)
        ):
            return None
        return cleaned

    def clean_name(self, value: Any) -> str | None:
        """`clean` for a NAME field: None as well when it does not read as a name (is_plain_name)."""
        name = self.clean(value, FactWordLimits.MAX_NAME_CHARS)
        return name if name is not None and is_plain_name(name) else None


def is_plain_name(text: str) -> bool:
    """True when `text` reads as a name (APT28, Sandworm Team, SIMATIC S7-1500, Data Backup): not too long, no
    lower-case opening word in a phrase, no sentence verb, opening command or many function words."""
    if len(text) > FactWordLimits.MAX_NAME_CHARS or not _NAME.fullmatch(text):
        return False
    words = text.split(" ")
    first = words[0]
    # A brand may open in lower case (iOS, macOS, gh0st RAT) but a phrase never opens in a plain lower-case
    # word; one lower-case word alone is a real name too (the Windows tools "cmd", "netstat").
    if len(words) > 1 and not any(char.isupper() or char.isdigit() for char in first):
        return False
    if len(words) > NameGrammar.MAX_WORDS or first.casefold() in NameGrammar.COMMAND_WORDS:
        return False
    if any(word in NameGrammar.SENTENCE_WORDS for word in words):
        return False
    return (
        sum(word.casefold() in NameGrammar.FUNCTION_WORDS for word in words) <= NameGrammar.MAX_FUNCTION_WORDS
    )


def as_name(text: str) -> str:
    """`text` when it is a plain name, else '' (what a source stores in a name field)."""
    return text if is_plain_name(text) else ""


def is_tactic(text: str) -> bool:
    """True when `text` has the shape of an ATT&CK tactic name (words joined by hyphens, all lower case)."""
    return _TACTIC.fullmatch(text) is not None
