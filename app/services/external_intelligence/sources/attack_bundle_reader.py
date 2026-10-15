"""Reading a MITRE ATT&CK STIX 2.1 bundle (plain json): one pass indexes the names and the relationships worth
keeping, then each technique becomes a record. Revoked and deprecated objects are dropped everywhere.

Every name, description and note is sanitised as it is indexed. An actor, software or mitigation whose NAME
reads as instructions is quarantined itself and left out of every technique that mentions it (one poisoned
group name must not quarantine every technique it used); a technique with unsafe text is quarantined whole."""

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
from app.engine.external_intelligence.name_grammar import as_name, is_tactic
from app.models.external_intelligence.intel_record import IntelRecord, RejectedRecord, content_hash_of
from app.services.external_intelligence.sources.attack_groups import AttackGroups
from app.services.external_intelligence.sources.text_guard import (
    SourceTextGuard,
    UnsafeSourceText,
    flat_strings,
)

_ACTORS: Final = {"intrusion-set": "group", "malware": "software", "tool": "software", "campaign": "campaign"}
_NAMED: Final = {*_ACTORS, "course-of-action"}
_CITATION = re.compile(r"\s*\(Citation:[^)]*\)")
_SENTENCE_END = re.compile(r"(?<=[.!?])\s")
_STAMP = re.compile(r"\d{4}-\d{2}-\d{2}(?:T[0-9:.]+Z?)?")
_ATTACK_ID = re.compile(r"[A-Z]\d{4}(?:\.\d{3})?")
_BAD_NAME: Final = "bad_name"


def is_live(obj: dict[str, Any]) -> bool:
    return not (obj.get("revoked") or obj.get("x_mitre_deprecated"))


def _attack_ref(obj: dict[str, Any]) -> dict[str, Any]:
    refs = [r for r in obj.get("external_references") or [] if isinstance(r, dict)]
    return next((r for r in refs if r.get("source_name") == "mitre-attack" and r.get("external_id")), {})


def _first_sentence(text: Any) -> str:
    """The first sentence of a relationship's description, citations gone (cut before it is sanitised)."""
    plain = _CITATION.sub("", text) if isinstance(text, str) else ""
    return _SENTENCE_END.split(plain[: AttackReading.NOTE_CHARS * 4], maxsplit=1)[0]


def _described(guard: SourceTextGuard, obj: dict[str, Any]) -> str:
    """The technique's description, citations gone, screened by sentence (G237: only flagged ones go)."""
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
    """What the relationships say, keyed by technique stix id. Built in one pass; lists capped as built."""

    def __init__(self, guard: SourceTextGuard) -> None:
        self._guard = guard
        self._names: dict[str, tuple[str, str]] = {}  # stix id -> (name, actor kind)
        self._techniques: list[dict[str, Any]] = []
        self._relationships: list[dict[str, Any]] = []
        self._mitigations: dict[str, list[str]] = {}
        self._real_world_use: dict[str, list[dict[str, str]]] = {}
        self.groups = AttackGroups(guard, self._names)  # G230: the named groups behind each technique
        self.rejected: list[RejectedRecord] = []

    @property
    def techniques(self) -> list[dict[str, Any]]:
        return self._techniques

    def mitigations_of(self, stix_id: Any) -> list[str]:
        return self._mitigations.get(stix_id, []) if isinstance(stix_id, str) else []

    def real_world_use_of(self, stix_id: Any) -> list[dict[str, str]]:
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
        kind = obj.get("type")
        if kind == "attack-pattern":
            self._techniques.append(obj)
        elif kind == "relationship" and obj.get("relationship_type") in (
            "uses",
            "mitigates",
            "attributed-to",
        ):
            self._relationships.append(obj)
        elif kind in _NAMED and obj.get("name") and isinstance(obj.get("id"), str):
            try:
                name = self._guard.clean(obj["name"], TextSafety.MAX_TITLE_CHARS)
                if name and not as_name(name):
                    raise UnsafeSourceText(_BAD_NAME)  # a sentence in a name field: quarantined, not used
                self._names[obj["id"]] = (name, _ACTORS.get(kind, ""))
                if kind == "intrusion-set":
                    self.groups.add_group(obj, name, _attack_ref(obj))
            except UnsafeSourceText as unsafe:
                identifier = _attack_ref(obj).get("external_id")
                self.rejected.append(self._guard.quarantine(identifier, obj, unsafe.reason))

    def _link(self, rel: dict[str, Any]) -> None:
        source_ref, target = rel.get("source_ref"), rel.get("target_ref")
        name, actor = self._names.get(source_ref, ("", "")) if isinstance(source_ref, str) else ("", "")
        if not (name and isinstance(source_ref, str) and isinstance(target, str)):
            return
        if rel["relationship_type"] == "attributed-to":  # a campaign -> the group behind it (G230)
            self.groups.attribute(source_ref, target)
        elif rel["relationship_type"] == "mitigates":
            known = self._mitigations.setdefault(target, [])
            if name not in known and len(known) < TextSafety.MAX_DATA_ITEMS:
                known.append(name)
        elif actor:
            note = self._note(rel)
            use = self._real_world_use.setdefault(target, [])
            if len(use) < AttackReading.REAL_WORLD_USE_LIMIT and all(u["name"] != name for u in use):
                use.append({"name": name, "kind": actor, "note": note})
            self.groups.used(source_ref, actor, target, note)

    def _note(self, rel: dict[str, Any]) -> str:
        try:
            return self._guard.clean(_first_sentence(rel.get("description")), AttackReading.NOTE_CHARS)
        except UnsafeSourceText as unsafe:
            self._guard.quarantine("", rel, unsafe.reason)  # logged; the note is left out, the use is kept
            return ""


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
        return _build(obj, index, guard, (source, asset_type, version), (identifier, name, ref))
    except UnsafeSourceText as unsafe:
        return guard.quarantine(identifier, obj, unsafe.reason)


def _search_text(guard: SourceTextGuard, description: str, head: str, lists: list[list[str]]) -> str:
    """The head, the description (cut to leave room) and the tactics, platforms and mitigations in words."""
    labels = ("Tactics", "Platforms", "Mitigations")
    lists = [*lists[:2], lists[2][: AttackReading.MITIGATIONS_IN_TEXT]]
    tail = [f"{label}: {', '.join(items)}." for label, items in zip(labels, lists, strict=True) if items]
    room = _shorten(description, AttackReading.TEXT_LIMIT - len(head))
    return guard.clean(" ".join([head, room, *tail]), TextSafety.MAX_TEXT_CHARS)


def _build(
    obj: dict[str, Any],
    index: AttackBundleIndex,
    guard: SourceTextGuard,
    origin: tuple[IntelSource, str, str],
    identity: tuple[str, str, dict[str, Any]],
) -> IntelRecord:
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
        "groups": index.groups.groups_of(obj.get("id")),  # G230: every named group behind it, capped
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
