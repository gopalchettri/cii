"""Cleans untrusted source text: plain text out, or unsafe with the reason when it reads as instructions."""

import base64
import binascii
import re
import string
import unicodedata
from html import unescape
from typing import Any, Final

from app.core.constants import TextCleaning
from app.domain.intel.patterns import BLOB_PATTERNS, CONFUSABLES, MARKUP_PATTERNS, SQUASHED_PATTERNS, TEXT_PATTERNS
from app.schemas.intel_records import SanitisedText

_HEX = re.compile(r"[0-9a-fA-F]+")
_SEPARATORS = re.compile(r"[/_-]")
_URL_SAFE = str.maketrans("-_", "+/")
_PRINTABLE_LOW, _PRINTABLE_HIGH = 32, 127
_BASE64_BLOCK = 4


def is_plain_run(run: str) -> bool:
    """True when a long run is a path or a hash, not an encoded payload."""
    run = run.rstrip("=")
    return _is_path(run) or _is_digest(run)


def _is_path(run: str) -> bool:
    pieces = _SEPARATORS.split(run)
    short = len(pieces) > 1 and max(map(len, pieces)) <= TextCleaning.PATH_PIECE_MAX
    # Read as it stands, and with the separators taken out (a payload cut into pieces by slashes).
    return short and not any(_reads_as_text(_base64_bytes(view)) for view in (run, _SEPARATORS.sub("", run)))


def _is_digest(run: str) -> bool:
    if len(run) not in TextCleaning.DIGEST_HEX_LENGTHS or not _HEX.fullmatch(run):
        return False
    return not _reads_as_text(bytes.fromhex(run))


def _base64_bytes(run: str) -> bytes:
    text = run.translate(_URL_SAFE)
    if len(text) % _BASE64_BLOCK == 1:
        text = text[:-1]
    try:
        return base64.b64decode(text + "=" * (-len(text) % _BASE64_BLOCK))
    except (binascii.Error, ValueError):
        return b""


def _reads_as_text(data: bytes) -> bool:
    if not data:
        return False
    printable = [_PRINTABLE_LOW <= byte < _PRINTABLE_HIGH for byte in data]
    longest = current = 0
    for flag in printable:
        current = current + 1 if flag else 0
        longest = max(longest, current)
    return sum(printable) / len(data) >= TextCleaning.DECODED_TEXT_SHARE or longest >= (TextCleaning.DECODED_TEXT_RUN)


Patterns = tuple[tuple[str, re.Pattern[str]], ...]
_SENTENCE_ENDS: Final = (". ", "! ", "? ")
_NEWLINES: Final = (chr(10), chr(13))

_DROPPED = frozenset({"Cc", "Cf", "Co", "Cs", "Cn", "Mn", "Me", "Zl", "Zp"})
_ASCII_TABLE: Final = {**{code: None for code in range(32) if code not in (9, 10, 13)}, 9: " ", 13: "\n", 127: None}
_TYPOGRAPHY: Final = str.maketrans({"‘": "'", "’": "'", "“": '"', "”": '"', "–": "-", "—": "-", "•": "-"})
_ALLOWED: Final = frozenset(string.ascii_letters + string.digits + " .,;:!?'\"()[]-_/%+=<>*&#@|")

_COMMENT = re.compile(r"<!--.*?(?:-->|\Z)", re.DOTALL)
_BLOCK = re.compile(r"<(script|style)\b[^<>]*>.*?(?:</\1\s*>|\Z)", re.DOTALL | re.IGNORECASE)
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


class _Searches:
    def __init__(self) -> None:
        self._absent: set[tuple[int, str]] = set()  # (id of a pattern, a text it is not in)

    def first_match(self, patterns: Patterns, text: str) -> str | None:
        """The reason code of the first pattern found in `text`."""
        for code, pattern in patterns:
            if (id(pattern), text) in self._absent:
                continue
            if pattern.search(text):
                return code
            self._absent.add((id(pattern), text))
        return None

    def first_in_views(self, patterns: Patterns, text: str) -> str | None:
        """The reason code of the first pattern found in `text` or in its skeleton."""
        return self.first_match(patterns, text) or self.first_match(patterns, _skeleton(text))


class UntrustedTextSanitiser:
    """Stateless, so one may be shared by any thread."""

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
        """The clean text of `text`, at most `max_chars` long."""
        if not isinstance(text, str) or max_chars <= 0:
            return SanitisedText("")
        searches = _Searches()
        raw = text[: max(TextCleaning.MIN_RAW_CHARS, max_chars * TextCleaning.RAW_FACTOR)]
        for _ in range(TextCleaning.MAX_ROUNDS):
            cleaned, reason = self._normalise_and_strip(raw, searches)
            if reason:
                return SanitisedText("", True, reason)
            if cleaned == raw:
                break
            raw = cleaned
        else:  # still changing after every round: markup built to rebuild
            return SanitisedText("", True, "unstable_markup")
        reason = self._skeleton_reason(raw, searches) or _mixed_script_reason(raw)
        if reason:
            return SanitisedText("", True, reason)
        final = _plain(raw, " ")  # stored: a symbol such as a backslash separates words
        reason = (
            searches.first_match(self._all_patterns, _plain(raw, ""))  # and as the symbols glue the words
            or searches.first_match(self._all_patterns, final)
            or _blob_reason(final)
        )
        if reason:
            return SanitisedText("", True, reason)
        return SanitisedText(_cut(final, max_chars))

    def _normalise_and_strip(self, text: str, searches: _Searches) -> tuple[str, str | None]:
        text = _normalise(unescape(text))
        reason = searches.first_in_views(self._text_patterns, text)
        if reason:
            return text, reason
        text = self._without_quoted_markup(text, searches)
        reason = searches.first_in_views(self._markup_patterns, text)
        if reason:
            return text, reason
        text = _COMMENT.sub(" ", text)
        text = _BLOCK.sub(" ", text)
        text = _IMAGE.sub(" ", text)
        text = _LINK.sub(r"\1", text)
        text = _REFERENCE.sub(" ", text)
        text = _URL.sub(" ", text)
        return _TAG.sub(" ", text), None

    def _without_quoted_markup(self, text: str, searches: _Searches) -> str:

        def quoted(span: re.Match[str]) -> str:
            """A quoted span, or a space when it holds live-looking markup."""
            return " " if searches.first_match(self._markup_patterns, span.group()) else span.group()

        return _QUOTED_CODE.sub(quoted, text)

    def _skeleton_reason(self, text: str, searches: _Searches) -> str | None:
        skeleton = _skeleton(text)
        return searches.first_match(self._all_patterns, skeleton) or searches.first_match(
            self._squashed_patterns, _NOT_LETTER.sub("", skeleton)
        )


def _normalise(text: str) -> str:
    if text.isascii():
        return text.translate(_ASCII_TABLE)
    out: list[str] = []
    for char in unicodedata.normalize("NFKC", text).translate(_TYPOGRAPHY):
        if char in _NEWLINES:
            out.append("\n")
        elif char.isspace():
            out.append(" ")
        elif unicodedata.category(char) not in _DROPPED:
            out.append(char)
    return "".join(out)


def _skeleton(text: str) -> str:
    return text.lower().translate(CONFUSABLES)


def _blob_reason(text: str) -> str | None:
    for code, pattern in BLOB_PATTERNS:
        if any(not is_plain_run(found.group()) for found in pattern.finditer(text)):
            return code
    return None


def _is_foreign_letter(char: str) -> bool:
    if char.isascii() or not char.isalpha() or char in TextCleaning.UNIT_LETTERS:
        return False
    name = unicodedata.name(char, "")
    return "LATIN" not in name and not name.startswith(TextCleaning.ADJACENT_SCRIPTS)


def _mixed_script_reason(text: str) -> str | None:
    if text.isascii():
        return None
    for word in _WORD.findall(text):
        if (
            not word.isascii()
            and any(c.isascii() and c.isalpha() for c in word)
            and any(_is_foreign_letter(c) for c in word)
        ):
            return "mixed_script"
    return None


def _keep_allowed(text: str, symbol: str) -> str:
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
    if len(text) <= max_chars:
        return text
    head = text[: max_chars + 1]
    end = max(head.rfind(mark) for mark in _SENTENCE_ENDS)
    if end > max_chars // 2:
        return head[: end + 1].rstrip()
    space = head.rfind(" ")
    return (head[:space] if space > 0 else head[:max_chars]).rstrip(" ,;:-")
