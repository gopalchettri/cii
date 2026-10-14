"""The one gate every string passes before it can become part of a fact for the scenario writer.

A string comes from a structured field of a stored record. Records were sanitised when they were stored; it is
done again here (a record stored before a pattern was added, or by a source with a gap, must not reach a
prompt), and then the string must read as plain words: letters, digits and ordinary punctuation, no markup,
no link, no technique / CVE / advisory id. A string failing any check is dropped, never repaired."""

import re
from typing import Any

from app.core.constants import FactWordLimits
from app.engine.external_intelligence.name_grammar import is_plain_name
from app.engine.external_intelligence.untrusted_text import UntrustedTextSanitiser
from app.engine.shared.names import TECHNIQUE_CODE

_PLAIN = re.compile(r"[\w .,'’&()/+:;%\-]+")
#: A public number a business reader cannot use: CVE, CISA ICS advisory, GitHub, Microsoft bulletin, CERT/CC,
#: CAPEC pattern, ATT&CK / ATLAS technique. The evidence panel shows them; the story never does.
ID_IN_TEXT = re.compile(
    r"(?<![\w.-])(?:CVE-\d{4}-\d{4,}|ICSM?A-\d{2}-\d{3}-\d{2}[A-Z]?|GHSA(?:-[0-9a-z]{4}){3}|MS\d{2}-\d{3}"
    rf"|CAPEC-\d+|{TECHNIQUE_CODE})(?![\w-])|\bVU#\d+",
    re.IGNORECASE,
)
_LINK = re.compile(r"(?:https?|ftp)://|www\.", re.IGNORECASE)


class TextCleaner:
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
        """`clean` for a NAME field (a group, software, mitigation, vendor or product): None as well when it
        does not read as a name (see name_grammar.py)."""
        name = self.clean(value, FactWordLimits.MAX_NAME_CHARS)
        return name if name is not None and is_plain_name(name) else None
