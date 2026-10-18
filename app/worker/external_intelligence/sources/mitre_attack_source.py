"""MITRE ATT&CK (Enterprise = IT, ICS = OT): one TECHNIQUE record per live technique of the STIX bundle,
checkpointed as `<release>|<etag>|<format>` so an unchanged file is not downloaded again."""

import re
from typing import Any

from app.core.constants import AssetType, AttackReading, IntelMessage, IntelSource, IntelUrl, SourceDownload
from app.core.exceptions import IntelFetchFailed
from app.models.external_intelligence.fetch_result import FetchResult
from app.models.external_intelligence.intel_record import IntelRecord, RejectedRecord
from app.worker.external_intelligence.sources.attack_bundle_reader import (
    AttackBundleIndex,
    is_live,
    technique_record,
)
from app.worker.external_intelligence.sources.http_download import HttpDownloader, load_json
from app.worker.external_intelligence.sources.text_guard import (
    SourceTextGuard,
    limit_rejected,
    sort_into,
)

_FEEDS = {
    IntelSource.ATTACK_ENTERPRISE: (IntelUrl.ATTACK_ENTERPRISE, AssetType.IT.value),
    IntelSource.ATTACK_ICS: (IntelUrl.ATTACK_ICS, AssetType.OT.value),
}
_RELEASE = re.compile(r"\d[A-Za-z0-9.+:-]{0,39}")  # no space and no "|": a version is not a sentence


class MitreAttackSource:
    """One ATT&CK bundle as a source."""

    def __init__(self, source_id: IntelSource, downloader: HttpDownloader | None = None) -> None:
        self.source_id = source_id
        self._url, self._asset_type = _FEEDS[source_id]
        self._downloader = downloader or HttpDownloader()

    def download_changes(self, checkpoint: str | None) -> FetchResult | None:
        """The techniques of this bundle, or None when the file is unchanged (a 304 to its etag, or with no
        etag the same release); a checkpoint of another reader format reads the file again."""
        old_release, old_etag, old_format = [*(checkpoint or "").split("|", 2), "", ""][:3]
        if old_format != AttackReading.FORMAT:  # read by another reader: read again, whatever the server says
            old_release, old_etag = "", ""
        file = self._downloader.download_if_changed(
            self._url, old_etag or None, SourceDownload.MAX_ATTACK_BYTES
        )
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
        """The bundle's objects; IntelFetchFailed when it is not a bundle."""
        try:
            objects = load_json(body, self.source_id.value).get("objects")
        except (ValueError, AttributeError):
            objects = None
        if not isinstance(objects, list):
            raise IntelFetchFailed(IntelMessage.BAD_FORMAT, source=self.source_id.value)
        return objects

    def _release_of(self, objects: list[Any]) -> str:
        """The collection's x_mitre_version; failing that, the newest `modified` of any live object."""
        live = [o for o in objects if isinstance(o, dict) and is_live(o)]
        versions = [str(o["x_mitre_version"]) for o in live if o.get("type") == "x-mitre-collection"]
        version = next((v for v in versions if v), "") or max(
            (str(o["modified"]) for o in live if o.get("modified")), default=""
        )
        if not _RELEASE.fullmatch(version):
            raise IntelFetchFailed(IntelMessage.BAD_FORMAT, source=self.source_id.value)
        return version

    def _fetch_result(self, objects: list[Any], version: str, etag: str) -> FetchResult:
        """The bundle's technique records and rejections, with the new checkpoint."""
        index = AttackBundleIndex(SourceTextGuard(self.source_id))
        index.add_all(objects)
        records: list[IntelRecord] = []
        rejected: list[RejectedRecord] = list(index.rejected)
        for obj in index.techniques:
            made = technique_record(obj, index, self.source_id, self._asset_type, version)
            sort_into(made, records, rejected)
        checkpoint = f"{version}|{etag}|{AttackReading.FORMAT}"
        return FetchResult(tuple(records), limit_rejected(rejected), checkpoint, version)
