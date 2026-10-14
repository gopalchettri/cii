"""Untrusted text: all that an external source says is DATA for a scenario-writer prompt, never an order.

Defence in depth at ingest, in this order (each step is a pure function of the text; nothing is shared or
cached, so any number of requests and workers may call one sanitiser at once):
 1. only a bounded prefix is looked at (a 100 MB field costs what a 20 KB one does);
 2. Unicode NFKC, then control, zero-width, bidi, format, private-use and combining characters are dropped;
 3. HTML entities are decoded, then comments, script/style blocks, tags, markdown links and images and every
    URL are removed; steps 2 and 3 repeat until the text stops changing, so "<<b>script>" or an entity-encoded
    tag cannot rebuild itself, and the markup is checked as it was BEFORE it was stripped;
 4. the injection patterns (injection_patterns.py) run on the text with its markup, on its skeleton
    (look-alike letters mapped to Latin ones), on the skeleton without spacing, and on the final text;
    live markup is checked after a span the text only QUOTES (`<script>` in backticks, a <code> example) is
    dropped;
 5. a character allow-list (Latin letters, digits and plain punctuation; a backslash and other symbols
    become a space, so a registry path stays words), whitespace collapsed, long encoded runs refused (a path
    or a hash is no payload, see blob_runs.py), a word or sentence boundary cut.
Text that reads as instructions to an AI comes back EMPTY with `unsafe=True` and a short reason code: the
caller quarantines the record, and nothing here ever repeats the payload."""

import re
import string
import unicodedata
from html import unescape
from typing import Any, Final

from app.core.constants import TextCleaning
from app.engine.external_intelligence.blob_runs import is_plain_run
from app.engine.external_intelligence.injection_patterns import (
    BLOB_PATTERNS,
    CONFUSABLES,
    MARKUP_PATTERNS,
    SQUASHED_PATTERNS,
    TEXT_PATTERNS,
)
from app.models.external_intelligence.sanitised_text import SanitisedText

Patterns = tuple[tuple[str, re.Pattern[str]], ...]
_SENTENCE_ENDS: Final = (". ", "! ", "? ")
_NEWLINE: Final = chr(10)
_NEWLINES: Final = (chr(10), chr(13))
_MIXED_SCRIPT: Final = "mixed_script"
_UNSTABLE_MARKUP: Final = (
    "unstable_markup"  # still changing after every round: nested markup built to rebuild
)

_DROPPED = frozenset({"Cc", "Cf", "Co", "Cs", "Cn", "Mn", "Me", "Zl", "Zp"})
_ASCII_TABLE: Final = {
    **{code: None for code in range(32) if code not in (9, 10, 13)},
    9: " ",
    13: "\n",
    127: None,
}
_TYPOGRAPHY: Final = str.maketrans({"‘": "'", "’": "'", "“": '"', "”": '"', "–": "-", "—": "-", "•": "-"})
_ALLOWED: Final = frozenset(string.ascii_letters + string.digits + " .,;:!?'\"()[]-_/%+=<>*&#@|")

_COMMENT = re.compile(r"<!--.*?(?:-->|\Z)", re.DOTALL)
_BLOCK = re.compile(r"<(script|style)\b[^>]*>.*?(?:</\1\s*>|\Z)", re.DOTALL | re.IGNORECASE)
_TAG = re.compile(r"</?[A-Za-z!?][^<>]{0,300}>")
_IMAGE = re.compile(r"!\[[^\]]{0,300}\]\([^)]{0,2000}\)")
_LINK = re.compile(r"\[([^\]]{0,300})\]\([^)]{0,2000}\)")
_REFERENCE = re.compile(r"^[ \t]*\[[^\]]{1,100}\]:[ \t]*\S+", re.MULTILINE)
_QUOTED_CODE = re.compile(r"`[^`\n]{1,300}`|<code>.{0,1500}?</code>", re.DOTALL | re.IGNORECASE)
_URL_END = r"""[^\s<>"']+"""  # a link ends at a space, an angle bracket or a quote
_URL = re.compile(
    rf"(?:[a-z][a-z0-9+.-]{{1,15}}://|\bwww\.){_URL_END}"
    rf"|\b(?:javascript|data|vbscript|file|mailto|tel):{_URL_END}",
    re.IGNORECASE,
)
_SPACES = re.compile(r"\s+")
_WORD = re.compile(r"\w+")
_NOT_LETTER = re.compile(r"[^a-z]")


class UntrustedTextSanitiser:
    """Stateless: build one anywhere and share it. The pattern tables are the ingest ones unless a caller with
    a narrower purpose gives its own (the writer's echo check: ECHO_PATTERNS, no squashed view)."""

    def __init__(
        self,
        text_patterns: Patterns = TEXT_PATTERNS,
        squashed_patterns: Patterns = SQUASHED_PATTERNS,
        markup_patterns: Patterns = MARKUP_PATTERNS,
    ) -> None:
        self._text_patterns = text_patterns
        self._squashed_patterns = squashed_patterns
        self._markup_patterns = markup_patterns
        self._all_patterns = text_patterns + markup_patterns

    def sanitise(self, text: Any, max_chars: int) -> SanitisedText:
        """The clean text of `text`, at most `max_chars` long, or an unsafe verdict with a reason code."""
        if not isinstance(text, str) or max_chars <= 0:
            return SanitisedText("")
        raw = text[: max(TextCleaning.MIN_RAW_CHARS, max_chars * TextCleaning.RAW_FACTOR)]
        for _ in range(TextCleaning.MAX_ROUNDS):
            cleaned, reason = self._normalise_and_strip(raw)
            if reason:
                return SanitisedText("", True, reason)
            if cleaned == raw:
                break
            raw = cleaned
        else:
            return SanitisedText("", True, _UNSTABLE_MARKUP)
        reason = self._skeleton_reason(raw) or _mixed_script_reason(raw)
        if reason:
            return SanitisedText("", True, reason)
        final = _plain(raw, " ")  # stored: a symbol such as a backslash separates words
        reason = (
            _first_match(self._all_patterns, _plain(raw, ""))  # and as the symbols glue the words
            or _first_match(self._all_patterns, final)
            or _blob_reason(final)
        )
        if reason:
            return SanitisedText("", True, reason)
        return SanitisedText(_cut(final, max_chars))

    def _normalise_and_strip(self, text: str) -> tuple[str, str | None]:
        """One round: decoded and normalised, checked WITH its markup, then the markup removed."""
        text = _normalise(unescape(text))
        reason = _first_in_views(self._text_patterns, text)
        if reason:
            return text, reason
        text = self._without_quoted_markup(text)
        reason = _first_in_views(self._markup_patterns, text)
        if reason:
            return text, reason
        text = _COMMENT.sub(" ", text)
        text = _BLOCK.sub(" ", text)
        text = _IMAGE.sub(" ", text)
        text = _LINK.sub(r"\1", text)
        text = _REFERENCE.sub(" ", text)
        text = _URL.sub(" ", text)
        return _TAG.sub(" ", text), None

    def _without_quoted_markup(self, text: str) -> str:
        """`text` without the code spans that hold live-looking markup: a description QUOTING `<script>` is
        not markup. Every other pattern has read the span already; what is left is checked for markup."""

        def quoted(span: re.Match[str]) -> str:
            return " " if _first_match(self._markup_patterns, span.group()) else span.group()

        return _QUOTED_CODE.sub(quoted, text)

    def _skeleton_reason(self, text: str) -> str | None:
        skeleton = _skeleton(text)
        return _first_match(self._all_patterns, skeleton) or _first_match(
            self._squashed_patterns, _NOT_LETTER.sub("", skeleton)
        )


def _normalise(text: str) -> str:
    """NFKC, then every character that is invisible, a control, or only decorates another one is dropped."""
    if text.isascii():
        return text.translate(_ASCII_TABLE)
    out: list[str] = []
    for char in unicodedata.normalize("NFKC", text).translate(_TYPOGRAPHY):
        if char in _NEWLINES:
            out.append(_NEWLINE)
        elif char.isspace():
            out.append(" ")
        elif unicodedata.category(char) not in _DROPPED:
            out.append(char)
    return "".join(out)


def _skeleton(text: str) -> str:
    """Lower case with look-alike letters turned into the Latin ones they imitate (for checking only)."""
    return text.lower().translate(CONFUSABLES)


def _first_match(patterns: Patterns, text: str) -> str | None:
    return next((code for code, pattern in patterns if pattern.search(text)), None)


def _first_in_views(patterns: Patterns, text: str) -> str | None:
    return _first_match(patterns, text) or _first_match(patterns, _skeleton(text))


def _blob_reason(text: str) -> str | None:
    """The code of a long encoded run in `text`; a path or a hash is not one."""
    for code, pattern in BLOB_PATTERNS:
        if any(not is_plain_run(found.group()) for found in pattern.finditer(text)):
            return code
    return None


def _is_foreign_letter(char: str) -> bool:
    """A letter of another script that could pass for a Latin one (not CJK text beside "IP", not a unit)."""
    if char.isascii() or not char.isalpha() or char in TextCleaning.UNIT_LETTERS:
        return False
    name = unicodedata.name(char, "")
    return "LATIN" not in name and not name.startswith(TextCleaning.ADJACENT_SCRIPTS)


def _mixed_script_reason(text: str) -> str | None:
    """A word that mixes Latin letters with another script's is a look-alike trick, not a name."""
    if text.isascii():
        return None
    for word in _WORD.findall(text):
        if (
            not word.isascii()
            and any(c.isascii() and c.isalpha() for c in word)
            and any(_is_foreign_letter(c) for c in word)
        ):
            return _MIXED_SCRIPT
    return None


def _keep_allowed(text: str, symbol: str) -> str:
    """Plain letters, digits and punctuation only: another ASCII symbol becomes `symbol`, other scripts
    become spaces."""
    kept: list[str] = []
    for char in text:
        if char in _ALLOWED or char == "\n":
            kept.append(char)
        elif not char.isascii() and char.isalpha():
            kept.append(char if "LATIN" in unicodedata.name(char, "") else " ")
        elif not char.isascii() and not char.isspace():
            kept.append(" ")
        elif char.isascii():
            kept.append(symbol)
    return "".join(kept)


def _plain(text: str, symbol: str) -> str:
    return _SPACES.sub(" ", _keep_allowed(text, symbol)).strip()


def _cut(text: str, max_chars: int) -> str:
    """At most `max_chars`, ended at a sentence end when one is in the second half, else at a word end."""
    if len(text) <= max_chars:
        return text
    head = text[: max_chars + 1]
    end = max(head.rfind(mark) for mark in _SENTENCE_ENDS)
    if end > max_chars // 2:
        return head[: end + 1].rstrip()
    space = head.rfind(" ")
    return (head[:space] if space > 0 else head[:max_chars]).rstrip(" ,;:-")
