"""The plain sentences a scenario writer may use from one intelligence record.

A fact is a short sentence in everyday words: who has done it, what reduces it, why CISA lists the weakness,
which versions. Facts are rebuilt here from the record's STRUCTURED fields only (never its free text),
every string in them is cleaned again (TextCleaner: sanitiser, plain words, no id, no link) and each finished
sentence is cleaned once more. A fact with any flagged string is dropped whole. A fact never holds a
technique / CVE / advisory id or a link: those live only in `Evidence.ref` and `Evidence.url`."""

from app.core.constants import EvidenceLimits, IntelKind, TextSafety
from app.engine.external_intelligence.fact_sentences import FactSentences
from app.engine.external_intelligence.text_cleaner import TextCleaner
from app.engine.external_intelligence.untrusted_text import UntrustedTextSanitiser
from app.models.external_intelligence.evidence import IntelHit

_LINK_SCHEMES = ("https://", "http://")


class PlainFactWriter:
    def __init__(self, sanitiser: UntrustedTextSanitiser | None = None) -> None:
        self._cleaner = TextCleaner(sanitiser)
        self._sentences = FactSentences(self._cleaner)

    def write_facts(self, hit: IntelHit) -> tuple[str, ...]:
        """Up to EvidenceLimits.MAX_FACTS clean sentences, none with an id or a link."""
        data = hit.data if isinstance(hit.data, dict) else {}
        builders = {
            IntelKind.TECHNIQUE: self._sentences.technique,
            IntelKind.ADVISORY: self._sentences.advisory,
            IntelKind.VULNERABILITY: self._sentences.vulnerability,
        }
        build = builders.get(hit.kind)
        if build is None:
            return ()
        cleaned = (self._cleaner.clean(sentence, TextSafety.MAX_FACT_CHARS) for sentence in build(data))
        return tuple(dict.fromkeys(sentence for sentence in cleaned if sentence))[: EvidenceLimits.MAX_FACTS]

    def safe_mitigations(self, hit: IntelHit) -> tuple[str, ...]:
        """G234: what reduces an ATT&CK technique, by the names its facts use: the control query labels them
        "MITRE ATT&CK", so an advisory's remediation (even a short one that reads as a name) never comes."""
        if hit.kind != IntelKind.TECHNIQUE or not isinstance(hit.data, dict):
            return ()
        return tuple(self._sentences.mitigation_names(hit.data))

    def safe_title(self, hit: IntelHit) -> str:
        """The record's title when it is plain words; its own id otherwise (the id is shown, not said)."""
        return self._cleaner.clean(hit.title, TextSafety.MAX_TITLE_CHARS) or hit.external_id

    def safe_reason(self, reason: str) -> str:
        """A reason for leaving a record out, which holds the record's own vendor and product names: empty
        when those are not plain words (the decision itself stays recorded)."""
        return self._cleaner.clean(reason, TextSafety.MAX_FACT_CHARS * 2) or ""

    def safe_url(self, hit: IntelHit) -> str:
        """The record's link when it is an ordinary web address of a sane length; empty otherwise."""
        url = hit.url if isinstance(hit.url, str) else ""
        ok = url.startswith(_LINK_SCHEMES) and len(url) <= TextSafety.MAX_URL_CHARS and url.isprintable()
        return url if ok and not any(char in url for char in " <>\"'`\\") else ""
