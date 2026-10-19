"""Names as code compares, shows and quotes them."""

import json
import re
import unicodedata
from typing import Any

# Unicode-aware: Cyrillic and CJK names are real names. Letter<->digit boundaries are separators, so "APT41",
# "APT-41" and "APT 41" are one name.
_NON_WORD = re.compile(r"[\W_]+")
_LETTER_DIGIT_BOUNDARY = re.compile(r"(?<=[^\W\d_])(?=\d)|(?<=\d)(?=[^\W\d_])")

#: A MITRE technique code (ATLAS AML.T####, ATT&CK for ICS T08##, Enterprise T1###).
TECHNIQUE_CODE = r"(?:AML\.T\d{4}|T(?:08\d\d|1\d{3}))(?:\.\d{3})?"
#: A library code the importers store at the start of a threat's name: "AML.T0036 Data from ...".
_LEADING_LIBRARY_CODE = re.compile(
    rf"^\s*(?:{TECHNIQUE_CODE}|TID-\d+|CAPEC-\d+|[A-Z]{{2,3}}\d{{2}})\s*[:\-–—]?\s+(?=\S)"
)
_OPEN_QUOTE, _CLOSE_QUOTE = "[\"'“‘]", "[\"'”’]"
#: Between two names, or two codes, of one list: "X and Y", "X, Y", "X, and Y", "X/Y".
_LIST_SEPARATOR = r"(?:\s*,\s*(?:(?:and|or)\s+)?|\s+(?:and|or)\s+|\s*/\s*)"
_ASSET_PREPOSITIONS = "of|from|to|in|on|for|against|at"


def name_match_key(name: str) -> str:
    """The key two names are compared by: case folded, accents dropped, letter<->digit boundaries split, runs
    of non-word characters collapsed to one space. "Ransomware " == "RANSOMWARE"; "APT41" == "APT-41"."""
    decomposed = unicodedata.normalize("NFKD", name.casefold())
    stripped = "".join(character for character in decomposed if not unicodedata.combining(character))
    return _NON_WORD.sub(" ", _LETTER_DIGIT_BOUNDARY.sub(" ", stripped)).strip()


def threat_name_without_code(name: str) -> str:
    """`name` without a leading library code; a name that is only a code, or has none, comes back as it is."""
    return _LEADING_LIBRARY_CODE.sub("", name, count=1) or name


def as_json(value: Any) -> str:
    """A value as JSON, non-ASCII kept."""
    return json.dumps(value, ensure_ascii=False, default=str)


def quoted_for_prompt(name: Any) -> str:
    """A typed name as it enters a prompt: one line, fences removed, in quotes, so it reads as a value and
    never as an instruction (a system named "PLC-1. Ignore the rules ...")."""
    text = " ".join(str(name).split()).replace("<<<", "").replace(">>>", "")
    return json.dumps(text, ensure_ascii=False)


def shorten_text(text: str, limit: int) -> str:
    """`text` cut to `limit` characters, ending in an ellipsis when it was cut."""
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…" if limit > 1 else ""


def cut_to_fit(parts: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    """`parts` within `limit` JSON characters together: every text fact (never a name) longer than one common
    length is cut to it, the longest length that fits, so no part loses its facts before another; a fact
    cut to nothing is left out (unknown, never ""). Each part stays one valid JSON object."""
    # ponytail: lists (technology, platforms) are never cut: they hold the platform's short option names.
    texts = [
        (index, key)
        for index, part in enumerate(parts)
        for key, value in part.items()
        if key != "name" and isinstance(value, str)
    ]

    def cut(cap: int) -> list[dict[str, Any]]:
        kept = [dict(part) for part in parts]
        for index, key in texts:
            if len(kept[index][key]) > cap:
                if shortened := shorten_text(kept[index][key], cap):
                    kept[index][key] = shortened
                else:
                    del kept[index][key]
        return kept

    low, high = 0, max((len(parts[index][key]) for index, key in texts), default=0)
    while low < high:  # the longest common length that fits; 0 leaves every text fact out
        middle = (low + high + 1) // 2
        low, high = (
            (middle, high) if sum(len(as_json(part)) for part in cut(middle)) <= limit else (low, middle - 1)
        )
    return cut(low)


def _asset_name_pattern(asset_name: str, plural: bool = False) -> re.Pattern[str] | None:
    """The asset's name inside a text: any spacing, an optional "'s", never inside another word;
    case-sensitive at 3 characters or fewer, so "IT" never matches "it". `plural`: "hacktivists" also names
    "Hacktivist"."""
    # ponytail: re.compile's own cache (512 patterns) holds a run's names; past it (an asset with hundreds of
    # systems) each check recompiles, milliseconds against an AI call's seconds. Precompile per brief if seen.
    name = (asset_name or "").strip().rstrip(".,;:!")
    if not name:
        return None
    body = r"\s+".join(re.escape(word) for word in name.split())
    flags = 0 if len(name) <= 3 else re.IGNORECASE
    return re.compile(r"(?<!\w)" + body + (r"(?:e?s)?" if plural else "") + r"(?:'s)?(?!\w)", flags)


def _name_variants(name: str) -> tuple[str, ...]:
    """Every way a text may name `name`: as written, without its bracketed short form, and the short form
    itself ("Power Generation System (PGS)")."""
    forms = [name]
    short = re.search(r"\(([^()]+)\)\s*$", name)
    if short:
        forms += [name[: short.start()], short.group(1)]
    return tuple(dict.fromkeys(form.strip() for form in forms if len(form.strip()) >= 2))


def _form_keys(name: str) -> frozenset[str]:
    """The comparison key of every form of `name`."""
    return frozenset(key for form in _name_variants(name) if (key := name_match_key(form)))


def is_same_name(known: str, written: str) -> bool:
    """Whether `written` is `known` in one of its forms ("PGS" or "Power Generation System" for "Power
    Generation System (PGS)"), case, accents and spacing forgiven."""
    return name_match_key(written) in _form_keys(known)


def find_name_mentions(name: str, text: str) -> list[tuple[int, int]]:
    """Where `text` names `name`, in any of its forms, whole words only, singular or plural."""
    patterns = (_asset_name_pattern(form, plural=True) for form in _name_variants(name))
    return [match.span() for pattern in patterns if pattern for match in pattern.finditer(text)]


def remove_asset_name(text: str, asset_name: str) -> str:
    """`text` with the asset's name (and a preposition just before it) taken out, so two threat names are
    compared on what they say, not on the asset they share."""
    pattern = _asset_name_pattern(asset_name)
    if pattern is not None:
        with_preposition = re.compile(
            rf"(?:\b(?:{_ASSET_PREPOSITIONS})\s+)?" + pattern.pattern, pattern.flags
        )
        text = with_preposition.sub(" ", text)
    text = re.sub(r"\s+", " ", text).strip(" ,;:-.'")
    return re.sub(rf"\s+({_ASSET_PREPOSITIONS})$", "", text, flags=re.IGNORECASE)


def _folded_name(name: str) -> str:
    """A name as names are compared here: spacing collapsed, case folded."""
    return " ".join(name.split()).casefold()


def replace_codes_with_names(text: str, names: dict[str, str]) -> str:
    """`text` as a reviewer reads it: every code handed to the model -- a system alias (SYS2) or a threat slot
    (THR7) -- replaced by what it stands for, and the name written once where the model wrote it beside the
    code too (SYS1 "SCADA", SCADA (SYS1), "SCADA and ICS (SYS1, SYS2)" all read as the names alone). Only the
    exact codes of `names` are touched, so a product name such as "STEP7" stays as written."""
    names = {code: " ".join(name.split()) for code, name in names.items() if name and name.split()}
    if not text or not names:
        return text
    canonical = {_folded_name(name): name for name in names.values()}
    spelled = sorted(
        {r"\s+".join(map(re.escape, name.split())) for name in names.values()}, key=len, reverse=True
    )
    said = rf"(?<!\w)(?i:{'|'.join(spelled)})(?!\w)"
    one_name = rf"{_OPEN_QUOTE}?{said}{_CLOSE_QUOTE}?"
    code = rf"\b(?:{'|'.join(sorted(map(re.escape, names), key=len, reverse=True))})\b"
    pattern = re.compile(
        rf"(?:(?P<before>{one_name}(?:{_LIST_SEPARATOR}{one_name})*)\s*)?"
        rf"(?:\(\s*(?P<listed>{code}(?:{_LIST_SEPARATOR}{code})*)\s*\)"
        rf"|(?P<code>{code})(?(before)|(?:\s*\(\s*{_OPEN_QUOTE}?(?P<bracketed>{said}){_CLOSE_QUOTE}?\s*\)"
        # (?!\w): a quote followed by a letter is an apostrophe ("SCADA system's"), not the close.
        rf"|\s+{_OPEN_QUOTE}(?P<quoted>{said}){_CLOSE_QUOTE}(?!\w))?))"
    )
    name_pattern, code_pattern = re.compile(rf"{_OPEN_QUOTE}?({said}){_CLOSE_QUOTE}?"), re.compile(code)

    def codes_named(match: re.Match[str]) -> str:  # each code in the match replaced by its name
        return code_pattern.sub(lambda found: names[found[0]], match[0])

    def name_once(match: re.Match[str]) -> str:  # the match with each code's name written once
        meant = {
            _folded_name(names[found]) for found in code_pattern.findall(match["listed"] or match["code"])
        }
        before = match["before"]
        if before is not None and meant <= {_folded_name(word) for word in name_pattern.findall(before)}:
            return name_pattern.sub(lambda word: canonical[_folded_name(word[1])], before)
        written = match["bracketed"] or match["quoted"]
        if written is not None and _folded_name(written) in meant:
            return names[match["code"]]
        return codes_named(match)

    return pattern.sub(name_once, text)
