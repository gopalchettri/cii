"""The gate every stored string passes again before it becomes part of a fact."""

import re
from itertools import islice
from typing import Any

from app.core.constants import ACTOR_KIND_WORDS, EvidenceFact, EvidenceLimits, FactWordLimits, NameGrammar, TextSafety
from app.domain.intel.safety import UntrustedTextSanitiser
from app.domain.shared.names import TECHNIQUE_CODE
from app.schemas.intel_records import IntelHit

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


_SANITISER = UntrustedTextSanitiser()  # holds no state: shared by every thread


def clean(value: Any, max_chars: int) -> str | None:
    """Sanitise a string once more: it in plain words, or None when it must not be used."""
    if not isinstance(value, str):
        return None
    text = " ".join(value.split())
    if not text or len(text) > max_chars:
        return None
    result = _SANITISER.sanitise(text, max_chars)
    if result.unsafe:
        return None
    cleaned = " ".join(result.text.split())
    if not cleaned or not _PLAIN.fullmatch(cleaned) or ID_IN_TEXT.search(cleaned) or _LINK.search(cleaned):
        return None
    return cleaned


def clean_name(value: Any) -> str | None:
    """`clean` for a NAME field: None as well when it does not read as a name."""
    name = clean(value, FactWordLimits.MAX_NAME_CHARS)
    return name if name is not None and is_plain_name(name) else None


def is_plain_name(text: str) -> bool:
    """True when `text` reads as a name."""
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
    return sum(word.casefold() in NameGrammar.FUNCTION_WORDS for word in words) <= NameGrammar.MAX_FUNCTION_WORDS


def is_tactic(text: str) -> bool:
    """True when `text` has the shape of an ATT&CK tactic name."""
    return _TACTIC.fullmatch(text) is not None


_LINK_SCHEMES = ("https://", "http://")
_ANY_ACTOR_WORDS = "a known attacker"  # an actor of no kind ACTOR_KIND_WORDS names
_MAX_LIST_ITEMS = 50  # the most items of one record list a fact is built from


def write_facts(hit: IntelHit) -> tuple[str, ...]:
    """Up to EvidenceLimits.MAX_FACTS clean sentences, none with an id or a link."""
    cleaned = (clean(sentence, TextSafety.MAX_FACT_CHARS) for sentence in _technique_sentences(hit.data))
    return tuple(dict.fromkeys(sentence for sentence in cleaned if sentence))[: EvidenceLimits.MAX_FACTS]


def safe_mitigations(hit: IntelHit) -> tuple[str, ...]:
    """An ATT&CK technique's mitigations by the names its facts use."""
    return tuple(mitigation_names(hit.data))


def safe_title(hit: IntelHit) -> str:
    """The record's title when it is plain words."""
    return clean(hit.title, TextSafety.MAX_TITLE_CHARS) or hit.external_id


def safe_url(hit: IntelHit) -> str:
    """The record's link when it is an ordinary web address of a sane length."""
    url = hit.url if isinstance(hit.url, str) else ""
    ok = url.startswith(_LINK_SCHEMES) and len(url) <= TextSafety.MAX_URL_CHARS and url.isprintable()
    return url if ok and not any(char in url for char in " <>\"'`\\") else ""


def _technique_sentences(data: dict[str, Any]) -> list[str]:
    """A technique's tactics, who used it, and what mitigates it."""
    tactics = _tactics(data.get("tactics"))
    users = islice(
        filter(None, map(_used_by, _first_items(data.get("real_world_use")))), EvidenceLimits.REAL_WORLD_USERS
    )
    names = mitigation_names(data)
    return [
        *([EvidenceFact.TACTICS.format(tactics=", ".join(tactics))] if tactics else []),
        *users,
        *([EvidenceFact.MITIGATED_BY.format(mitigations=", ".join(names))] if names else []),
    ]


def mitigation_names(data: dict[str, Any]) -> list[str]:
    """The record's mitigations that read as names, at most EvidenceLimits.MITIGATIONS."""
    names = filter(None, map(clean_name, _first_items(data.get("mitigations"))))
    return list(islice(names, EvidenceLimits.MITIGATIONS))


def _tactics(values: Any) -> list[str]:
    tactics = (v.replace("-", " ") for v in _first_items(values) if isinstance(v, str) and is_tactic(v))
    cleaned = (clean(tactic, FactWordLimits.MAX_NAME_CHARS) for tactic in tactics)
    return list(islice(filter(None, cleaned), FactWordLimits.MAX_TACTICS))


def _used_by(use: Any) -> str:
    name = clean_name(use.get("name")) if isinstance(use, dict) else None
    if not name:
        return ""
    kind = use.get("kind")
    if kind == "campaign":
        label = name if name.casefold().endswith("campaign") else f"{name} campaign"  # one "campaign"
        return EvidenceFact.CAMPAIGN_USED.format(name=label)
    words = ACTOR_KIND_WORDS.get(kind, _ANY_ACTOR_WORDS) if isinstance(kind, str) else _ANY_ACTOR_WORDS
    return EvidenceFact.USED_BY.format(name=name, what=words)


def _first_items(value: Any) -> list[Any]:
    return value[:_MAX_LIST_ITEMS] if isinstance(value, list) else []
