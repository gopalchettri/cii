"""The grammar of a NAME field (a group, software, mitigation, vendor or product name).

A name is a few words, not a sentence. Free text typed into a name field (an order to the scenario writer in
the name of a group or a mitigation) is stopped by what it IS, not by what it says: too long, too many
little function words, a lower-case first word, a verb of a sentence, or an opening command. Applied when a
source stores a name and again when a fact is built from it. Pure functions of the text; nothing is shared."""

import re

from app.core.constants import FactWordLimits, NameGrammar

_NAME = re.compile(r"[\w.&'()/+@\-]+(?: [\w.&'()/+@\-]+)*")  # "@" for admin@338, an ATT&CK group
#: An ATT&CK tactic as the source writes it ("initial-access", "command-and-control").
_TACTIC = re.compile(r"[a-z][a-z0-9]{0,29}(?:-[a-z0-9]{1,30}){0,4}")


def is_plain_name(text: str) -> bool:
    """True when `text` reads as a name: APT28, Sandworm Team, SIMATIC S7-1500, Data Backup."""
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
