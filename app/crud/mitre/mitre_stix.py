"""tsg_mitre_enterprise_stix and tsg_mitre_ics_stix: one MITRE domain's STIX objects as imported (ADR-010), the
data the MITRE run's index is built from. One version at a time; an import replaces it whole."""

from collections.abc import Iterable
from itertools import batched

from pymongo import ASCENDING, ReplaceOne

from app.core.constants import MITRE_STIX_FIELDS, MITRE_STIX_WRITING_MARK, Collection, IntelLimits
from app.core.singletons import singleton
from app.crud.base import MongoRepository, Record, bulk_write


class MitreStixRepository(MongoRepository):
    """One MITRE domain's STIX objects, `_id` = the STIX id, each stamped with the import's version."""

    def __init__(self, collection: str) -> None:
        super().__init__(
            collection,
            indexes=({"keys": [("version", ASCENDING)], "name": "by_version"},),
            field_lists={"stix": {"_id": 0} | dict.fromkeys(MITRE_STIX_FIELDS, 1)},
            schema_version=1,
        )

    def replace_stix_objects(self, objects: Iterable[Record], version: str) -> int:
        """Writes `objects` marked as still being written, then stamps them `version` and deletes every other
        version; how many were written. A stored `version` therefore means complete: an import stopped half way
        leaves the writing mark, so the next import never trusts it. Nothing written (an empty import) deletes
        nothing: the earlier objects stay."""
        written, writing = 0, f"{version}{MITRE_STIX_WRITING_MARK}"
        for batch in batched(objects, IntelLimits.BATCH_SIZE):
            writes = []
            for stix_object in batch:
                document = stix_object | {"_id": stix_object["id"], "version": writing} | self._stamp
                writes.append(ReplaceOne({"_id": document["_id"]}, document, upsert=True))
            bulk_write(self.collection, writes, ordered=False)
            written += len(writes)
        if written:
            self.update({"version": version}, many=True, version=writing)
            self.delete(version={"$ne": version})
        return written

    def stored_versions(self) -> list[str]:
        """Every version stored (by_version): one after an import, two while one is being replaced, none before
        the first."""
        return sorted(self.collection.distinct("version"))

    def list_stix_objects(self) -> list[Record]:
        """Every stored STIX object, with only the fields the MITRE index reads."""
        return self.list("stix")


@singleton
def get_mitre_enterprise_stix_repository() -> MitreStixRepository:
    return MitreStixRepository(Collection.MITRE_ENTERPRISE_STIX)


@singleton
def get_mitre_ics_stix_repository() -> MitreStixRepository:
    return MitreStixRepository(Collection.MITRE_ICS_STIX)
