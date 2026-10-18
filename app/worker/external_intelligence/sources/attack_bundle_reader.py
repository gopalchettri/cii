"""Reads a MITRE ATT&CK STIX bundle: one pass indexes the names and relationships worth keeping, then each
live technique becomes a record, every name and description sanitised; unsafe text is quarantined."""

import re
from typing import Any, Final

from app.core.constants import (
    AttackReading,
    IntelKind,
    IntelRejection,
    IntelSource,
    SourceHosts,
    TextSafety,
)
from app.domain.external_intelligence.text_cleaner import as_name, is_tactic
from app.models.external_intelligence.intel_record import IntelRecord, RejectedRecord, content_hash_of
from app.worker.external_intelligence.sources.text_guard import (
    SourceTextGuard,
    UnsafeSourceText,
    flat_strings,
)

_ACTORS: Final = {"intrusion-set": "group", "malware": "software", "tool": "software", "campaign": "campaign"}
_NAMED: Final = {*_ACTORS, "course-of-action"}
_CITATION = re.compile(r"\s*\(Citation:[^)]*\)")
_STAMP = re.compile(r"\d{4}-\d{2}-\d{2}(?:T[0-9:.]+Z?)?")
_ATTACK_ID = re.compile(r"[A-Z]\d{4}(?:\.\d{3})?")
_BAD_NAME: Final = "bad_name"


def is_live(obj: dict[str, Any]) -> bool:
    """True for an object neither revoked nor deprecated."""
    return not (obj.get("revoked") or obj.get("x_mitre_deprecated"))


def _attack_ref(obj: dict[str, Any]) -> dict[str, Any]:
    """The object's mitre-attack external reference (its id and page); {} when it has none."""
    refs = [r for r in obj.get("external_references") or [] if isinstance(r, dict)]
    return next((r for r in refs if r.get("source_name") == "mitre-attack" and r.get("external_id")), {})


def _described(guard: SourceTextGuard, obj: dict[str, Any]) -> str:
    """The technique's description, citations gone, screened by sentence (only flagged ones go)."""
    return guard.clean_sentences(
        _CITATION.sub("", str(obj.get("description") or "")), AttackReading.TEXT_LIMIT
    )


def _shorten(description: str, room: int) -> str:
    """The description cut at the last sentence end that leaves room for the rest of the text."""
    room -= AttackReading.TAIL_ROOM
    if len(description) <= room:
        return description
    cut = description[:room]
    end = max(cut.rfind(". "), cut.rfind("! "), cut.rfind("? "))
    return cut[: end + 1] if end > 0 else cut.rstrip()


class AttackBundleIndex:
    """What the relationships say, keyed by technique stix id, built in one pass with lists capped. An actor,
    software or mitigation whose name is unsafe is quarantined itself and left out of every technique."""

    def __init__(self, guard: SourceTextGuard) -> None:
        self._guard = guard
        self._names: dict[str, tuple[str, str]] = {}  # stix id -> (name, actor kind)
        self._techniques: list[dict[str, Any]] = []
        self._relationships: list[dict[str, Any]] = []
        self._mitigations: dict[str, list[str]] = {}
        self._real_world_use: dict[str, list[dict[str, str]]] = {}
        self.rejected: list[RejectedRecord] = []

    @property
    def techniques(self) -> list[dict[str, Any]]:
        """The live techniques of the bundle."""
        return self._techniques

    def mitigations_of(self, stix_id: Any) -> list[str]:
        """The names of what mitigates a technique."""
        return self._mitigations.get(stix_id, []) if isinstance(stix_id, str) else []

    def real_world_use_of(self, stix_id: Any) -> list[dict[str, str]]:
        """Who used a technique: each group, software or campaign by name and kind."""
        return self._real_world_use.get(stix_id, []) if isinstance(stix_id, str) else []

    def add_all(self, objects: list[Any]) -> None:
        """Indexes every live object, then resolves the relationships (every name is known by then)."""
        for obj in objects:
            if isinstance(obj, dict) and is_live(obj):
                self._add(obj)
        for rel in self._relationships:
            self._link(rel)
        self._relationships = []

    def _add(self, obj: dict[str, Any]) -> None:
        """Index one live object: a technique, a relationship worth keeping, or a sanitised name."""
        kind = obj.get("type")
        if kind == "attack-pattern":
            self._techniques.append(obj)
        elif kind == "relationship" and obj.get("relationship_type") in ("uses", "mitigates"):
            self._relationships.append(obj)
        elif kind in _NAMED and obj.get("name") and isinstance(obj.get("id"), str):
            try:
                name = self._guard.clean(obj["name"], TextSafety.MAX_TITLE_CHARS)
                if name and not as_name(name):
                    raise UnsafeSourceText(_BAD_NAME)  # a sentence in a name field: quarantined, not used
                self._names[obj["id"]] = (name, _ACTORS.get(kind, ""))
            except UnsafeSourceText as unsafe:
                identifier = _attack_ref(obj).get("external_id")
                self.rejected.append(self._guard.quarantine(identifier, obj, unsafe.reason))

    def _link(self, rel: dict[str, Any]) -> None:
        """Record one "mitigates" or "uses" relationship on its target technique."""
        source_ref, target = rel.get("source_ref"), rel.get("target_ref")
        name, actor = self._names.get(source_ref, ("", "")) if isinstance(source_ref, str) else ("", "")
        if not (name and isinstance(source_ref, str) and isinstance(target, str)):
            return
        if rel["relationship_type"] == "mitigates":
            known = self._mitigations.setdefault(target, [])
            if name not in known and len(known) < TextSafety.MAX_DATA_ITEMS:
                known.append(name)
        elif actor:  # who used it: its name and kind only (the facts say them; how it was used is not read)
            use = self._real_world_use.setdefault(target, [])
            if len(use) < AttackReading.REAL_WORLD_USE_LIMIT and all(u["name"] != name for u in use):
                use.append({"name": name, "kind": actor})


def technique_record(
    obj: dict[str, Any], index: AttackBundleIndex, source: IntelSource, asset_type: str, version: str
) -> IntelRecord | RejectedRecord:
    """The record of one technique, or why it was rejected (malformed) or quarantined (unsafe text)."""
    guard = SourceTextGuard(source)
    ref = _attack_ref(obj)
    identifier = ref.get("external_id")
    if not (isinstance(identifier, str) and _ATTACK_ID.fullmatch(identifier)):
        return RejectedRecord(source, "", IntelRejection.NO_TECHNIQUE_ID, content_hash_of(obj))
    try:
        name = guard.clean(_CITATION.sub("", str(obj.get("name") or "")), TextSafety.MAX_TITLE_CHARS)
        if not name:
            return RejectedRecord(source, identifier, IntelRejection.NO_NAME, content_hash_of(obj))
        return _technique_from(obj, index, guard, (source, asset_type, version), (identifier, name, ref))
    except UnsafeSourceText as unsafe:
        return guard.quarantine(identifier, obj, unsafe.reason)


def _search_text(guard: SourceTextGuard, description: str, head: str, lists: list[list[str]]) -> str:
    """The head, the description (cut to leave room) and the tactics, platforms and mitigations in words."""
    labels = ("Tactics", "Platforms", "Mitigations")
    lists = [*lists[:2], lists[2][: AttackReading.MITIGATIONS_IN_TEXT]]
    tail = [f"{label}: {', '.join(items)}." for label, items in zip(labels, lists, strict=True) if items]
    room = _shorten(description, AttackReading.TEXT_LIMIT - len(head))
    return guard.clean(" ".join([head, room, *tail]), TextSafety.MAX_TEXT_CHARS)


def _technique_from(
    obj: dict[str, Any],
    index: AttackBundleIndex,
    guard: SourceTextGuard,
    origin: tuple[IntelSource, str, str],
    identity: tuple[str, str, dict[str, Any]],
) -> IntelRecord:
    """The technique's record: its tactics, platforms, mitigations and users, all screened together."""
    source, asset_type, version = origin
    identifier, name, ref = identity
    phases = [p.get("phase_name") for p in obj.get("kill_chain_phases") or [] if isinstance(p, dict)]
    tactics = [t for t in guard.clean_list(phases, AttackReading.LABEL_CHARS) if is_tactic(t)]
    platforms = guard.clean_list(obj.get("x_mitre_platforms"), AttackReading.LABEL_CHARS)
    mitigations = index.mitigations_of(obj.get("id"))
    description = _described(guard, obj)
    text = _search_text(guard, description, f"{identifier} {name}.", [tactics, platforms, mitigations])
    data = {
        "technique_id": identifier,
        "tactics": tactics,
        "platforms": platforms,
        "mitigations": mitigations,
        "real_world_use": index.real_world_use_of(obj.get("id")),
    }
    stamp = obj.get("modified")
    modified = stamp if isinstance(stamp, str) and _STAMP.fullmatch(stamp) else None
    guard.screen_together([name, text, *flat_strings(data)])
    return IntelRecord(
        source,
        identifier,
        IntelKind.TECHNIQUE,
        asset_type,
        name,
        text,
        guard.clean_link(ref.get("url"), SourceHosts.ATTACK_PAGES)
        or SourceHosts.ATTACK_TECHNIQUE_PAGE.format(path=identifier.replace(".", "/")),
        version,
        modified,
        data,
    )
