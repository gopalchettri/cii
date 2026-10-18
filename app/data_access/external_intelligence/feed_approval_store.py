"""tsg_external_feed_status, approval side: a source revoked (its health blanked) or approved again.
FeedStatusStore extends this class, which extends the reader."""

from typing import Any

from app.core.constants import IntelSource, IntelUrl
from app.data_access.external_intelligence.feed_status_reader import FeedStatusReader
from app.models.external_intelligence.source_health import SourceHealth

Doc = dict[str, Any]
#: Where each source's terms are published: kept beside the registry for whoever audits an approval.
_TERMS: dict[IntelSource, str] = {
    IntelSource.CISA_KEV: IntelUrl.TERMS_KEV,
    IntelSource.FIRST_EPSS: IntelUrl.TERMS_EPSS,
    IntelSource.ATTACK_ENTERPRISE: IntelUrl.TERMS_ATTACK,
    IntelSource.ATTACK_ICS: IntelUrl.TERMS_ATTACK,
    IntelSource.CISA_ICS: IntelUrl.TERMS_CISA,
    IntelSource.NIST_NVD: IntelUrl.TERMS_NVD,
}


def _blank_health(source: IntelSource) -> Doc:
    """What a source shows before any run: no checkpoint, no count, no error. A revoked source goes back to
    it (its records are purged, so a kept checkpoint would make a later approval find 'nothing new')."""
    blank = SourceHealth(source).as_doc()
    return {
        **{name: blank[name] for name in blank if name not in ("source", "claimed_at")},
        "more_pending": False,
    }


def new_source_doc(source: IntelSource) -> Doc:
    """A source never run, without `approved`: that field has its own default (seed) or value (revocation)."""
    return {
        **SourceHealth(source).as_doc(),
        "terms_url": _TERMS[source],
        "more_pending": False,
    }


class FeedApprovalStore(FeedStatusReader):
    def revoke_source(self, source: IntelSource, *, create: bool = True) -> None:
        """Marks `source` not approved and blanks its health. Also before the seed, so a revocation is never
        undone by it. `create=False` (the master switch is off) only changes a source document that already
        exists: nothing is created."""
        self._set_approval(source, False, upsert=create)

    def approve_source(self, source: IntelSource) -> None:
        """Approves `source` again with a blank health: its next refresh loads everything from the start."""
        self._set_approval(source, True, upsert=True)

    def _set_approval(self, source: IntelSource, approved: bool, *, upsert: bool) -> None:
        """`approved` set on the source, with a blank health and no claim: a refresh in flight loses it, so a
        revoke then a re-approve never lets that run write on."""
        setting = {
            "$set": {"approved": approved, **_blank_health(source), "claimed_at": None, "claim_token": None}
        }
        setting["$setOnInsert"] = {"terms_url": _TERMS[source]}
        self._feeds.update_one({"_id": source}, setting, upsert=upsert)
