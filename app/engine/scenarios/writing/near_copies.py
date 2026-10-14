"""Near-copy scenarios, caught in code (G229, owner 2026-10-13: "Combine text similarity with structured
comparisons of target systems, threats, attack mechanisms, and consequences ... Preserve materially distinct
scenarios even when they use similar terminology ... Reject near-duplicates without invoking an AI rewriting
pass"). A new scenario nearly copies a finished one of its run when BOTH: their statements share at least
NEAR_COPY_TEXT_SIMILARITY percent of their three-word phrases, AND they are about the same thing: the same
threat, or the same target, systems and kind with at least NEAR_COPY_PART_SIMILARITY percent of their
mechanism and consequence words shared. Measured on runs 03276384 and 82f22cc3: distinct scenarios shared at
most 3.5% of their phrases, a copy with two sentences reworded about 72%. Pure."""

import re
from collections.abc import Iterable
from typing import Any

from app.core.config import get_settings
from app.core.constants import FindingCode, FindingMessage
from app.engine.shared.names import name_match_key
from app.models.writing import Finding

_WORD = re.compile(r"[a-z0-9]+")
_MARKER = re.compile(r"\[\d+(?:\s*,\s*\d+)*\]")


def near_copy(content: dict[str, Any], finished: Iterable[dict[str, Any]]) -> Finding | None:
    """The finding when `content` (a new scenario's) nearly copies one of `finished` ({_id, content}: the
    run's finished current scenarios, its own path's versions left out by the caller), else None."""
    settings = get_settings()
    mine = _phrases(content.get("statement") or "")
    for other in finished:
        similarity = _share(mine, _phrases(other["content"].get("statement") or ""))
        if similarity >= settings.near_copy_text_similarity and _same_thing(
            content, other["content"], settings.near_copy_part_similarity
        ):
            message = FindingMessage.NEAR_DUPLICATE.format(
                scenario_id=other["_id"], similarity=round(similarity)
            )
            return Finding(FindingCode.NEAR_DUPLICATE, message)
    return None


def _same_thing(mine: dict[str, Any], theirs: dict[str, Any], part_share: float) -> bool:
    """The same threat; or the same target, systems and kind, told with largely the same mechanism and
    consequence."""
    threat = (mine.get("threat") or {}).get("key")
    if threat and threat == (theirs.get("threat") or {}).get("key"):
        return True
    own, other = mine.get("anatomy") or {}, theirs.get("anatomy") or {}
    same_target = bool(own.get("target")) and name_match_key(own["target"]) == name_match_key(
        other.get("target") or ""
    )
    same_systems = _system_ids(mine) == _system_ids(theirs)
    same_kind = mine.get("category") == theirs.get("category")
    parts = _share(_words(own), _words(other))
    return same_target and same_systems and same_kind and parts >= part_share


def _phrases(text: str) -> set[tuple[str, ...]]:
    words = _WORD.findall(_MARKER.sub("", text.casefold()))
    return {tuple(words[i : i + 3]) for i in range(len(words) - 2)}


def _words(anatomy: dict[str, Any]) -> set[str]:
    text = f"{anatomy.get('mechanism') or ''} {anatomy.get('consequence') or ''}".casefold()
    return {word for word in _WORD.findall(text) if len(word) > 3}


def _system_ids(content: dict[str, Any]) -> set[Any]:
    return {system.get("id") for system in content.get("systems") or []}


def _share(mine: set[Any], theirs: set[Any]) -> float:
    """How much two sets share, 0-100 (Jaccard); nothing at all shares nothing."""
    together = mine | theirs
    return 100 * len(mine & theirs) / len(together) if together else 0.0
