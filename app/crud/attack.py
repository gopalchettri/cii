"""tsg_attack: the MITRE ATT&CK graph, objects and relationships; tsg_control_links: per ATT&CK mitigation, the
library controls that do what it says."""

import re
from collections.abc import Collection as Ids
from collections.abc import Iterable
from itertools import batched

from pymongo import ASCENDING, ReplaceOne
from pymongo.collection import Collection as MongoCollection

from app.core.constants import AttackLink, AttackRecord, Collection, ControlLinks, IntelLimits, IntelSource
from app.core.singletons import singleton
from app.crud.base import MongoRepository, Record, bulk_write

_OBJECT_FIELDS = ("source", "stix_id", "type", "attack_id", "name", "aliases", "name_keys", "description", "url")
_RELATIONSHIP_FIELDS = ("source", "source_ref", "target_ref", "description", "citations")


def attack_doc_id(source: str, stix_id: str) -> str:
    """The `_id` of a tsg_attack document: its source and its STIX id (an object's, or a relationship's)."""
    return f"{source}:{stix_id}"


class AttackRepository(MongoRepository):
    """tsg_attack: a source's graph is replaced whole; every read takes a whole set's ids in one query."""

    def __init__(self, collection: str | MongoCollection = Collection.ATTACK) -> None:
        """The ATT&CK collection with its indexes and field lists."""
        super().__init__(
            collection,
            indexes=(
                {"keys": [("attack_id", ASCENDING)], "name": "by_attack_id"},
                {"keys": [("name_keys", ASCENDING)], "name": "by_name_key"},
                {"keys": [("type", ASCENDING), ("source_ref", ASCENDING)], "name": "by_type_and_source_ref"},
                {"keys": [("type", ASCENDING), ("target_ref", ASCENDING)], "name": "by_type_and_target_ref"},
                {"keys": [("source", ASCENDING), ("version", ASCENDING)], "name": "by_source_and_version"},
            ),
            field_lists={
                "object": {"_id": 0} | dict.fromkeys(_OBJECT_FIELDS, 1),
                "relationship": {"_id": 0} | dict.fromkeys(_RELATIONSHIP_FIELDS, 1),
            },
            schema_version=1,
        )

    def replace_source(self, source: IntelSource, docs: Iterable[Record], version: str) -> int:
        """Writes `docs` as the source's graph at `version` (one content, one version); how many were written."""
        written = 0
        for batch in batched(docs, IntelLimits.BATCH_SIZE):
            stamp = self._stamp | {"source": source, "version": version}
            writes = [ReplaceOne({"_id": doc["_id"]}, doc | stamp, upsert=True) for doc in batch]
            bulk_write(self.collection, writes, ordered=False)
            written += len(writes)
        if written:  # only now do the other versions go: stopped half way, or loaded empty, the earlier graph stays
            self.delete(source=source, version={"$ne": version})
        return written

    def has_data(self, sources: Ids[str] = ()) -> bool:
        """Whether any ATT&CK document is stored, and one of each of `sources`."""
        if not sources:
            return self.get(("_id",)) is not None
        held = self.collection.distinct("source", {"source": {"$in": sorted(sources)}})  # by_source_and_version
        return set(sources) <= set(held)

    def is_release_stored(self, source: str, release: str) -> bool:
        """Whether the source's stored graph is of ATT&CK `release`: its version is "<release>|<content hash>"."""
        # ponytail: one document of the release is enough; a graph missing documents is rewritten by _store_graph
        version = {"$regex": f"^{re.escape(release)}\\|"}  # a prefix: by_source_and_version
        return self.get(("_id",), source=source, version=version) is not None

    def find_objects(self, attack_ids: Ids[str], name_keys: Ids[str]) -> list[Record]:
        """The objects with one of these ATT&CK IDs, or one of these match keys among their name and aliases.
        An object both sources hold comes back once per source."""
        wanted = [
            {field: {"$in": sorted(set(values))}}
            for field, values in (("attack_id", attack_ids), ("name_keys", name_keys))
            if values
        ]
        where: Record = {"record": AttackRecord.OBJECT, "$or": wanted}
        return self.list("object", **where) if wanted else []

    def find_uses(self, group_refs: Ids[str], technique_refs: Ids[str]) -> list[Record]:
        """The "uses" relationships from one of these groups to one of these techniques (STIX ids). A use ATT&CK
        records on a campaign it attributes to a group is told as that group's, unless the group has its own."""
        if not group_refs or not technique_refs:
            return []
        groups, techniques = sorted(set(group_refs)), sorted(set(technique_refs))
        owners: dict[tuple[str, str], list[str]] = {}  # (source, campaign) -> the groups it is attributed to
        for link in self.list("relationship", type=AttackLink.ATTRIBUTED_TO, target_ref={"$in": groups}):
            owners.setdefault((link["source"], link["source_ref"]), []).append(link["target_ref"])
        users = sorted({*groups, *(campaign for _, campaign in owners)})
        found = self.list(
            "relationship", type=AttackLink.USES, source_ref={"$in": users}, target_ref={"$in": techniques}
        )
        uses = {
            (use["source"], use["source_ref"], use["target_ref"]): use for use in found if use["source_ref"] in groups
        }
        # Of a group's campaigns using one technique, the first that tells how is kept.
        for use in sorted(found, key=lambda use: (not use["description"], use["source_ref"])):
            for group in owners.get((use["source"], use["source_ref"]), ()):
                uses.setdefault((use["source"], group, use["target_ref"]), use | {"source_ref": group})
        return list(uses.values())

    def find_mitigations(self, technique_refs: Ids[str]) -> list[Record]:
        """What ATT&CK records as mitigating each of these techniques (STIX ids): one row per pair, with the
        mitigation's ATT&CK ID and name; never ATT&CK's entries that mitigate nothing."""
        if not technique_refs:
            return []
        shown = {
            "_id": 0,
            "source": 1,
            "technique_ref": "$target_ref",
            "mitigation_ref": "$source_ref",
            "attack_id": "$mitigation.attack_id",
            "name": "$mitigation.name",
        }
        pipeline: list[Record] = [
            {"$match": {"type": AttackLink.MITIGATES, "target_ref": {"$in": sorted(set(technique_refs))}}},
            *self._join_mitigation(),
            {"$project": shown},
            {"$sort": {"technique_ref": 1, "attack_id": 1}},
        ]
        return list(self.collection.aggregate(pipeline))

    def list_mitigations(self) -> list[Record]:
        """Every mitigation some technique names, by ATT&CK ID; never ATT&CK's entries that mitigate nothing."""
        shown = {
            "_id": 0,
            "source": 1,
            "stix_id": "$source_ref",
            "attack_id": "$mitigation.attack_id",
            "name": "$mitigation.name",
            "description": "$mitigation.description",
        }
        pipeline: list[Record] = [
            {"$match": {"type": AttackLink.MITIGATES}},
            {"$group": {"_id": {"source": "$source", "source_ref": "$source_ref"}}},
            {"$replaceRoot": {"newRoot": "$_id"}},
            *self._join_mitigation(),
            {"$project": shown},
            {"$sort": {"attack_id": 1, "source": 1}},
        ]
        return list(self.collection.aggregate(pipeline))

    def _join_mitigation(self) -> list[Record]:
        by_id = {"from": self.collection.name, "localField": "object_id", "foreignField": "_id", "as": "mitigation"}
        return [
            {"$addFields": {"object_id": {"$concat": ["$source", ":", "$source_ref"]}}},
            {"$lookup": by_id},
            {"$unwind": "$mitigation"},
            {"$match": {"mitigation.attack_id": {"$nin": sorted(ControlLinks.NOT_MITIGATIONS)}}},
        ]


class ControlLinkRepository(MongoRepository):
    """tsg_control_links: one document per ATT&CK mitigation, `_id` its ATT&CK ID."""

    def __init__(self, collection: str | MongoCollection = Collection.CONTROL_LINKS) -> None:
        """The control links collection: read and written by `_id` alone."""
        super().__init__(collection, schema_version=1)

    def list_link_fingerprints(self) -> dict[str, str]:
        """Each prepared mitigation's fingerprint, by ATT&CK ID."""
        return {doc["_id"]: doc.get("fingerprint", "") for doc in self.list(("fingerprint",))}

    def save_link(self, link: Record) -> None:
        """Writes one mitigation's links whole: {_id, name, fingerprint, links, prepared_at}."""
        self.save(link)

    def find_links(self, mitigation_ids: Ids[str]) -> dict[str, list[Record]]:
        """The links ({control_id, effect, reason, rerank}) of each of these mitigations that has a record."""
        if not mitigation_ids:
            return {}
        found = self.list(("links",), _id={"$in": sorted(set(mitigation_ids))})
        return {doc["_id"]: doc.get("links") or [] for doc in found}

    def summarise_links(self, mitigation_ids: Ids[str]) -> Record:
        """Of these mitigations: how many are prepared, with and without a control, how many are not yet."""
        has_links = {"$gt": [{"$size": {"$ifNull": ["$links", []]}}, 0]}
        totals = {
            "_id": None,
            "mitigations": {"$sum": 1},
            "linked": {"$sum": {"$cond": [has_links, 1, 0]}},
            "prepared_at": {"$max": "$prepared_at"},
        }
        listed = sorted(set(mitigation_ids))
        pipeline: list[Record] = [{"$match": {"_id": {"$in": listed}}}, {"$group": totals}]
        found = next(iter(self.collection.aggregate(pipeline)), None) or {}
        mitigations, linked = found.get("mitigations", 0), found.get("linked", 0)
        return {
            "mitigations": mitigations,
            "linked": linked,
            "without_links": mitigations - linked,
            "not_prepared": len(listed) - mitigations,
            "prepared_at": found.get("prepared_at"),
        }


@singleton
def get_attack_repository() -> AttackRepository:
    return AttackRepository()


@singleton
def get_control_link_repository() -> ControlLinkRepository:
    return ControlLinkRepository()
