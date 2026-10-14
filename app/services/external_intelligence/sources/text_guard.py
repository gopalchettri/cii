"""The one door through which source text reaches a stored record: every title, description, name, note and
link is sanitised here (engine/external_intelligence/untrusted_text.py), and a record with unsafe text is
quarantined whole, never stored and never indexed.

Stateless apart from the source it speaks for, so a source may build one per run or share one."""

import re
from collections.abc import Iterable, Sequence
from typing import Any
from urllib.parse import unquote_plus, urlparse

import structlog

from app.core.constants import IntelLimits, IntelRejection, IntelSource, LogEvent, TextCleaning, TextSafety
from app.engine.external_intelligence.name_grammar import as_name
from app.engine.external_intelligence.untrusted_text import UntrustedTextSanitiser
from app.models.external_intelligence.intel_record import IntelRecord, RejectedRecord, content_hash_of

log = structlog.get_logger(__name__)

_LINK = re.compile(r"https?://[^\s<>\"'`\\{}|^]+")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:+~%*-]*")  # a cpe field, a version, an id: no space, no phrase
_PLAIN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,79}")


class UnsafeSourceText(Exception):
    """A field reads as instructions to an AI. Carries the short reason code of the check that fired, never
    the text."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class SourceTextGuard:
    def __init__(self, source: IntelSource, sanitiser: UntrustedTextSanitiser | None = None) -> None:
        self._source = source
        self._sanitiser = sanitiser or UntrustedTextSanitiser()

    def clean(self, text: Any, max_chars: int) -> str:
        """`text` as safe plain text of at most `max_chars`; raises UnsafeSourceText when it is not."""
        result = self._sanitiser.sanitise(text, max_chars)
        if result.unsafe:
            raise UnsafeSourceText(result.reason or "")
        return result.text

    def clean_token(self, value: Any, max_chars: int = 100) -> str:
        """An identifier-like value (a vendor, a product, a version) kept as it is when it has the shape of
        one; anything else must read as a name, else it is '' (a phrase is no identifier)."""
        if isinstance(value, str) and len(value) <= TextCleaning.TOKEN_MAX_CHARS and _TOKEN.fullmatch(value):
            return value
        return as_name(self.clean(value, max_chars))

    def clean_list(
        self, values: Any, max_chars: int, max_items: int = TextSafety.MAX_DATA_ITEMS
    ) -> list[str]:
        """The non-empty cleaned texts of a list, each once, at most `max_items` of them."""
        items = values if isinstance(values, Sequence) and not isinstance(values, str) else []
        return list(dict.fromkeys(c for c in (self.clean(item, max_chars) for item in items) if c))[
            :max_items
        ]

    def clean_link(self, url: Any, hosts: Sequence[str] = ()) -> str:
        """`url` when it is a plain http(s) address that does not itself read as instructions, else ''. With
        `hosts`: only an https address whose host is one of them or a subdomain of one."""
        if not (isinstance(url, str) and len(url) <= TextSafety.MAX_URL_CHARS and _LINK.fullmatch(url)):
            return ""
        if hosts and not on_host(url, hosts):
            return ""
        return "" if self._sanitiser.sanitise(unquote_plus(url), len(url)).unsafe else url

    def screen_together(self, parts: Iterable[Any]) -> None:
        """Raises when the fields of one record, read one after another, read as orders although no field
        does alone (a sentence split across a title and a description)."""
        joined = " ".join(part for part in parts if isinstance(part, str))
        self.clean(joined, len(joined) + 1)

    def quarantine(self, external_id: Any, raw: Any, reason: str) -> RejectedRecord:
        """The rejection to store for a record with unsafe text; logs which check fired, never the text."""
        raw_hash = content_hash_of(raw)
        log.warning(
            LogEvent.EXTERNAL_INTELLIGENCE_TEXT_QUARANTINED,
            source=self._source,
            reason=reason,
            raw_hash=raw_hash,
        )
        return RejectedRecord(self._source, self.plain_id(external_id), IntelRejection.UNSAFE_TEXT, raw_hash)

    @staticmethod
    def plain_id(value: Any) -> str:
        """`value` when it looks like an id (T1059, CVE-2024-0001, ICSA-24-001-01), else ''."""
        return value if isinstance(value, str) and _PLAIN_ID.fullmatch(value) else ""


def on_host(url: str, hosts: Sequence[str]) -> bool:
    """True for an https `url` whose host is one of `hosts` or a subdomain of one (and has no credentials)."""
    try:
        parts = urlparse(url)
        host = (parts.hostname or "").lower()
    except ValueError:
        return False
    return (
        parts.scheme == "https"
        and parts.username is None
        and any(host == allowed or host.endswith("." + allowed) for allowed in hosts)
    )


def limit_rejected(rejected: Sequence[RejectedRecord]) -> tuple[RejectedRecord, ...]:
    """At most MAX_REJECTED_PER_RUN rejections are kept: one bad file cannot flood storage."""
    return tuple(rejected[: IntelLimits.MAX_REJECTED_PER_RUN])


def sort_into(
    made: IntelRecord | RejectedRecord, records: list[IntelRecord], rejected: list[RejectedRecord]
) -> None:
    """A record just read, into its list: kept, or set aside with its reason."""
    if isinstance(made, IntelRecord):
        records.append(made)
    else:
        rejected.append(made)


def flat_strings(value: Any) -> Iterable[str]:
    """Every string inside nested lists and dicts (keys excluded): what a record's `data` says in words."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from flat_strings(item)
    elif isinstance(value, list | tuple):
        for item in value:
            yield from flat_strings(item)
