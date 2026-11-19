"""Reads a MITRE ATT&CK STIX bundle."""

import re
from operator import itemgetter
from typing import Any, Final
from urllib.parse import urlparse

from app.core.constants import (
    MITRE_STIX_FIELDS,
    MITRE_STIX_RELATIONSHIP_TYPES,
    MITRE_STIX_TYPES,
    AssetType,
    AttackLink,
    AttackReading,
    AttackRecord,
    IntelKind,
    IntelLimits,
    IntelMessage,
    IntelRejection,
    IntelSource,
    SourceDownload,
    TextSafety,
)
from app.core.exceptions import IntelFetchFailed
from app.crud.attack import attack_doc_id
from app.domain.intel.facts import is_plain_name, is_tactic
from app.domain.intel.sources.common import HttpDownloader, SourceTextGuard, UnsafeSourceText, flat_strings, load_json
from app.domain.shared.names import name_match_key
from app.schemas.intel_records import FetchResult, IntelRecord, RejectedRecord, content_hash_of

_ACTORS: Final = {"intrusion-set": "group", "malware": "software", "tool": "software", "campaign": "campaign"}
_NAMED: Final = {*_ACTORS, "course-of-action"}
_LINKS: Final = tuple(AttackLink)  # a tuple: a malformed (unhashable) relationship_type is no match, not an error
_ATTACK_HOSTS: Final = ("attack.mitre.org",)
_CITATION = re.compile(r"\s*\(Citation:[^)]*\)")
_STAMP = re.compile(r"\d{4}-\d{2}-\d{2}(?:T[0-9:.]+Z?)?")
_ATTACK_ID = re.compile(r"[A-Z]\d{4}(?:\.\d{3})?")
_BAD_NAME: Final = "bad_name"


def is_live(obj: dict[str, Any]) -> bool:
    """True for an object neither revoked nor deprecated."""
    return not (obj.get("revoked") or obj.get("x_mitre_deprecated"))


def keep_scenario_stix_objects(objects: list[Any]) -> tuple[dict[str, Any], ...]:
    """The bundle's objects the MITRE run reads (MITRE_STIX_TYPES and the MITRE_STIX_RELATIONSHIP_TYPES links),
    each with only its MITRE_STIX_FIELDS; revoked and deprecated ones are kept (a relationship may name them)."""
    kept = []
    for stix_object in objects:
        if not isinstance(stix_object, dict) or not isinstance(stix_object.get("id"), str):
            continue
        stix_type, link = stix_object.get("type"), stix_object.get("relationship_type")
        is_kept_object = isinstance(stix_type, str) and stix_type in MITRE_STIX_TYPES
        is_kept_link = stix_type == "relationship" and isinstance(link, str) and link in MITRE_STIX_RELATIONSHIP_TYPES
        if not (is_kept_object or is_kept_link):
            continue
        fields = {}
        for name in MITRE_STIX_FIELDS:
            if name in stix_object:
                fields[name] = stix_object[name]
        kept.append(fields)
    return tuple(kept)


def _attack_ref(obj: dict[str, Any]) -> dict[str, Any]:
    refs = [r for r in obj.get("external_references") or [] if isinstance(r, dict)]
    return next((r for r in refs if r.get("source_name") == "mitre-attack" and r.get("external_id")), {})


def _shorten(description: str, room: int) -> str:
    room -= AttackReading.TAIL_ROOM
    if len(description) <= room:
        return description
    cut = description[:room]
    end = max(cut.rfind(". "), cut.rfind("! "), cut.rfind("? "))
    return cut[: end + 1] if end > 0 else cut.rstrip()


def _description(guard: SourceTextGuard, obj: dict[str, Any]) -> str:
    return guard.clean_sentences(_CITATION.sub("", str(obj.get("description") or "")), AttackReading.TEXT_LIMIT)


def _citations(guard: SourceTextGuard, rel: dict[str, Any]) -> list[dict[str, str]]:
    """The reports a relationship cites, each by name and https address."""
    kept: list[dict[str, str]] = []
    for ref in (r for r in rel.get("external_references") or [] if isinstance(r, dict)):
        url = ref.get("url")
        try:
            host = urlparse(url).hostname if isinstance(url, str) else None
            name = guard.clean(ref.get("source_name"), TextSafety.MAX_TITLE_CHARS)
        except (UnsafeSourceText, ValueError):
            continue
        link = guard.clean_link(url, (host,)) if host else ""  # any host: a report is on its publisher's site
        if name and link:
            kept.append({"name": name, "url": link})
    return kept[: TextSafety.MAX_DATA_ITEMS]


class AttackBundleIndex:
    """What the relationships say, keyed by technique stix id, and the graph tsg_attack stores."""

    def __init__(self, guard: SourceTextGuard) -> None:
        self._guard = guard
        self._names: dict[str, tuple[str, str]] = {}  # stix id -> (name, actor kind)
        self._objects: dict[str, dict[str, Any]] = {}  # stix id -> its graph document
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
        """Indexes every live object, then resolves the relationships."""
        for obj in objects:
            if isinstance(obj, dict) and is_live(obj):
                self._add(obj)
        for rel in self._relationships:
            self._link(rel)

    def keep_object(self, obj: dict[str, Any], attack_id: Any, name: str, description: str, url: str) -> None:
        """Adds one live object, its texts already cleaned, to the graph; one with no ATT&CK ID is left out."""
        stix_id = obj.get("id")
        if not (name and isinstance(stix_id, str) and isinstance(attack_id, str) and _ATTACK_ID.fullmatch(attack_id)):
            return
        lists = [obj.get(key) for key in ("aliases", "x_mitre_aliases")]
        aliases: list[str] = []
        for alias in (item for items in lists if isinstance(items, list) for item in items):
            try:
                clean = self._guard.clean(alias, TextSafety.MAX_TITLE_CHARS)
            except UnsafeSourceText:  # an unsafe alias is left out; the object's own name was clean
                continue
            if clean and clean != name and clean not in aliases and is_plain_name(clean):
                aliases.append(clean)
        aliases = aliases[: TextSafety.MAX_DATA_ITEMS]
        self._objects[stix_id] = {
            "record": AttackRecord.OBJECT,
            "stix_id": stix_id,
            "type": obj["type"],
            "attack_id": attack_id,
            "name": name,
            "name_keys": list(dict.fromkeys(filter(None, map(name_match_key, (name, *aliases))))),
            "aliases": aliases,
            "description": description,
            "url": url,
        }

    def build_graph(self, source: IntelSource) -> tuple[dict[str, Any], ...]:
        """The kept objects and the relationships between two of them, as tsg_attack stores them, by `_id`."""
        docs = [doc | {"_id": attack_doc_id(source, stix_id)} for stix_id, doc in self._objects.items()]
        for rel in self._relationships:
            rel_id, ends = rel.get("id"), (rel.get("source_ref"), rel.get("target_ref"))
            if not (isinstance(rel_id, str) and all(isinstance(end, str) and end in self._objects for end in ends)):
                continue
            try:
                description = _description(self._guard, rel)
            except UnsafeSourceText as unsafe:  # the link stays, a fact of the graph; its text is not kept
                self.rejected.append(self._guard.quarantine(None, rel, unsafe.reason))
                description = ""
            doc = {
                "_id": attack_doc_id(source, rel_id),
                "record": AttackRecord.RELATIONSHIP,
                "type": rel["relationship_type"],
                "source_ref": ends[0],
                "target_ref": ends[1],
                "description": description,
                "citations": _citations(self._guard, rel),
            }
            docs.append(doc)
        return tuple(sorted(docs, key=itemgetter("_id")))

    def _add(self, obj: dict[str, Any]) -> None:
        kind = obj.get("type")
        if kind == "attack-pattern":
            self._techniques.append(obj)
        elif kind == "relationship" and obj.get("relationship_type") in _LINKS:
            self._relationships.append(obj)
        elif kind in _NAMED and obj.get("name") and isinstance(obj.get("id"), str):
            try:
                name = self._guard.clean(obj["name"], TextSafety.MAX_TITLE_CHARS)
                if name and not is_plain_name(name):
                    raise UnsafeSourceText(_BAD_NAME)  # a sentence in a name field: quarantined, not used
                self._names[obj["id"]] = (name, _ACTORS.get(kind, ""))
                ref = _attack_ref(obj)
                url = self._guard.clean_link(ref.get("url"), _ATTACK_HOSTS)
                self.keep_object(obj, ref.get("external_id"), name, _description(self._guard, obj), url)
            except UnsafeSourceText as unsafe:
                identifier = _attack_ref(obj).get("external_id")
                self.rejected.append(self._guard.quarantine(identifier, obj, unsafe.reason))

    def _link(self, rel: dict[str, Any]) -> None:
        source_ref, target = rel.get("source_ref"), rel.get("target_ref")
        name, actor = self._names.get(source_ref, ("", "")) if isinstance(source_ref, str) else ("", "")
        if not (name and isinstance(source_ref, str) and isinstance(target, str)):
            return
        if rel["relationship_type"] == AttackLink.MITIGATES:
            known = self._mitigations.setdefault(target, [])
            if name not in known and len(known) < TextSafety.MAX_DATA_ITEMS:
                known.append(name)
        elif actor and rel["relationship_type"] == AttackLink.USES:
            # who used it: its name and kind only (the facts say them; how it was used is not read)
            use = self._real_world_use.setdefault(target, [])
            if len(use) < AttackReading.REAL_WORLD_USE_LIMIT and all(u["name"] != name for u in use):
                use.append({"name": name, "kind": actor})


def technique_record(
    obj: dict[str, Any],
    index: AttackBundleIndex,
    guard: SourceTextGuard,
    source: IntelSource,
    asset_type: str,
    version: str,
) -> IntelRecord | RejectedRecord:
    """The record of one technique, or why it was rejected (malformed) or quarantined."""
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
    source, asset_type, version = origin
    identifier, name, ref = identity
    phases = [p.get("phase_name") for p in obj.get("kill_chain_phases") or [] if isinstance(p, dict)]
    tactics = [t for t in guard.clean_list(phases, AttackReading.LABEL_CHARS) if is_tactic(t)]
    platforms = guard.clean_list(obj.get("x_mitre_platforms"), AttackReading.LABEL_CHARS)
    mitigations = index.mitigations_of(obj.get("id"))
    description = _description(guard, obj)
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
    url = guard.clean_link(ref.get("url"), _ATTACK_HOSTS)
    url = url or f"https://attack.mitre.org/techniques/{identifier.replace('.', '/')}"
    index.keep_object(obj, identifier, name, description, url)
    return IntelRecord(source, identifier, IntelKind.TECHNIQUE, asset_type, name, text, url, version, modified, data)


DATASETS = {
    "mitre_attack_enterprise": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",  # noqa: E501
    "mitre_attack_ics": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json",  # noqa: E501
}
_RELEASE = re.compile(r"\d[A-Za-z0-9.+:-]{0,39}")  # no space and no "|": a version is not a sentence


class MitreAttackSource:
    """One ATT&CK bundle as a source."""

    def __init__(self, source_id: IntelSource, downloader: HttpDownloader | None = None) -> None:
        self.source_id = source_id
        self._url = DATASETS[source_id]
        self._asset_type = (AssetType.OT if source_id == IntelSource.ATTACK_ICS else AssetType.IT).value
        self._downloader = downloader or HttpDownloader()

    def download_changes(self, checkpoint: str | None) -> FetchResult | None:
        """The techniques of this bundle, or None when the file is unchanged."""
        old_release, old_etag, old_format = [*(checkpoint or "").split("|", 2), "", ""][:3]
        if old_format != AttackReading.FORMAT:  # read by another reader: read again, whatever the server says
            old_release, old_etag = "", ""
        file = self._downloader.download_if_changed(self._url, old_etag or None, SourceDownload.MAX_ATTACK_BYTES)
        if file is None:
            return None
        etag = file.etag or ""
        objects = self._bundle_objects(file.body)
        del file  # the raw bytes are released here; the parsed objects are the larger half of the memory
        version = self._release_of(objects)
        if version == old_release and not etag:  # no validator to ask with: an unchanged release is skipped
            return None
        return self._fetch_result(objects, version, etag)

    def _bundle_objects(self, body: bytes) -> list[Any]:
        try:
            objects = load_json(body, self.source_id.value).get("objects")
        except (ValueError, AttributeError):
            objects = None
        if not isinstance(objects, list):
            raise IntelFetchFailed(IntelMessage.BAD_FORMAT, source=self.source_id.value)
        return objects

    def _release_of(self, objects: list[Any]) -> str:
        live = [o for o in objects if isinstance(o, dict) and is_live(o)]
        versions = [str(o["x_mitre_version"]) for o in live if o.get("type") == "x-mitre-collection"]
        version = next((v for v in versions if v), "") or max(
            (str(o["modified"]) for o in live if o.get("modified")), default=""
        )
        if not _RELEASE.fullmatch(version):
            raise IntelFetchFailed(IntelMessage.BAD_FORMAT, source=self.source_id.value)
        return version

    def _fetch_result(self, objects: list[Any], version: str, etag: str) -> FetchResult:
        guard = SourceTextGuard(self.source_id)
        index = AttackBundleIndex(guard)
        index.add_all(objects)
        origin = (self.source_id, self._asset_type, version)
        made = [technique_record(obj, index, guard, *origin) for obj in index.techniques]
        records = tuple(item for item in made if isinstance(item, IntelRecord))
        graph = index.build_graph(self.source_id)  # after the techniques: each kept one is an end of its links
        rejected = [*index.rejected, *(item for item in made if isinstance(item, RejectedRecord))]
        checkpoint = f"{version}|{etag}|{AttackReading.FORMAT}"
        rejected_kept = tuple(rejected[: IntelLimits.MAX_REJECTED_PER_RUN])
        raw_stix = keep_scenario_stix_objects(objects)
        return FetchResult(records, rejected_kept, checkpoint, version, graph, raw_stix)
