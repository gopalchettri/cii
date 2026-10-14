"""Long runs of letters and digits that are NOT an encoded payload: a path and a hash.

The blob patterns (injection_patterns.py) find any long run made of base64 characters. Two ordinary things in
security prose look like that, and a real payload does not:
 - a path or a long name: split at "/", "_" or "-" into short pieces ("scheduler/ui/js/app",
   "HKEY_LOCAL_MACHINE_SYSTEM"); base64 has no word-sized pieces, and what a path would decode to is noise;
 - a digest: an MD5 or SHA hash given as proof in a report (exact lengths).
Whatever decodes to readable words (a share of printable bytes, or one long printable stretch, which a padded
payload still has) is hidden text, and stays a blob. Pure functions; nothing is shared."""

import base64
import binascii
import re

from app.core.constants import TextCleaning

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
    """What `run` decodes to read as base64 (the url-safe letters mapped; a stray last character dropped)."""
    text = run.translate(_URL_SAFE)
    if len(text) % _BASE64_BLOCK == 1:
        text = text[:-1]
    try:
        return base64.b64decode(text + "=" * (-len(text) % _BASE64_BLOCK))
    except (binascii.Error, ValueError):
        return b""


def _reads_as_text(data: bytes) -> bool:
    """True when `data` holds words: much of it is printable, or a stretch is (random bytes: neither)."""
    if not data:
        return False
    printable = [_PRINTABLE_LOW <= byte < _PRINTABLE_HIGH for byte in data]
    longest = current = 0
    for flag in printable:
        current = current + 1 if flag else 0
        longest = max(longest, current)
    return sum(printable) / len(data) >= TextCleaning.DECODED_TEXT_SHARE or longest >= (
        TextCleaning.DECODED_TEXT_RUN
    )
