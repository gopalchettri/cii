"""tsg_external_feed_status, write side: the source registry, its claims and its checkpoints. A source that
is not approved is never fetched; the seed only adds a missing source."""

from datetime import datetime
from uuid import uuid4

from pymongo import UpdateOne

from app.core.constants import FeedStatus, IntelSource, StoreLimits
from app.data_access.external_intelligence.feed_approval_store import FeedApprovalStore, new_source_doc


class FeedStatusStore(FeedApprovalStore):
    """The registry's writes; its reads are inherited, so one object serves the refresher."""

    def seed_sources(self) -> None:
        """Adds the missing sources, approved; idempotent. A source an operator revoked stays revoked."""
        self._feeds.bulk_write(
            [
                UpdateOne(
                    {"_id": source},
                    {"$setOnInsert": {**new_source_doc(source), "approved": True}},
                    upsert=True,
                )
                for source in IntelSource
            ]
        )

    def claim_source_for_refresh(
        self, source: IntelSource, now: datetime, stale_before: datetime
    ) -> str | None:
        """The claim's unique token when this caller may refresh `source` now (it is approved and nobody else
        is refreshing it), else None. One atomic write decides both, so a revoked source is never fetched and
        two workers never fetch the same source. A claim older than `stale_before` (its worker died) is taken
        over with a new token, so the dead worker can no longer release the new claim."""
        free = {"$or": [{"claimed_at": None}, {"claimed_at": {"$lt": stale_before}}]}
        token = uuid4().hex
        claim = {"$set": {"claimed_at": now, "claim_token": token, "last_attempt_at": now}}
        matched = self._feeds.update_one({"_id": source, "approved": True, **free}, claim).matched_count
        return token if matched == 1 else None

    def record_refresh_success(
        self,
        source: IntelSource,
        claim: str,
        checkpoint: str,
        source_version: str,
        now: datetime,
        *,
        more: bool,
        records: int,
    ) -> bool:
        """Advances the checkpoint and releases the claim, only while `claim` still holds it. Called only
        after the records were committed. False (nothing changed) when the claim was taken over."""
        done = {
            "status": FeedStatus.OK,
            "checkpoint": checkpoint,
            "source_version": source_version,
            "records": records,
            "last_success_at": now,
            "last_error": None,
            "claimed_at": None,
            "claim_token": None,
            "more_pending": more,
        }
        return (
            self._feeds.update_one({"_id": source, "claim_token": claim}, {"$set": done}).matched_count == 1
        )

    def record_refresh_failure(self, source: IntelSource, claim: str, error: str, now: datetime) -> bool:
        """The checkpoint and last success stay as they were: the last good data stays usable until stale.
        Acts only while `claim` still holds the source; False (nothing changed) when it was taken over."""
        failed = {
            "status": FeedStatus.FAILED,
            "last_attempt_at": now,
            "last_error": error[: StoreLimits.MAX_ERROR_CHARS],
            "claimed_at": None,
            "claim_token": None,
        }
        return (
            self._feeds.update_one({"_id": source, "claim_token": claim}, {"$set": failed}).matched_count == 1
        )

    def renew_claim(self, source: IntelSource, claim: str, now: datetime) -> bool:
        """The heartbeat, and the check before every write: True (and the claim fresh again) only while
        `claim` still holds `source` AND the source is still approved. False: the claim was taken over (the
        worker outlived CLAIM_STALE_SECONDS) or the source was revoked, so this worker must write no more."""
        held = {"_id": source, "claim_token": claim, "approved": True}
        return self._feeds.update_one(held, {"$set": {"claimed_at": now}}).matched_count == 1

    def release_claim(self, source: IntelSource, claim: str) -> bool:
        """Gives the claim back and changes nothing else (a run that had nothing to do). False when it was
        taken over."""
        done = {"claimed_at": None, "claim_token": None}
        return (
            self._feeds.update_one({"_id": source, "claim_token": claim}, {"$set": done}).matched_count == 1
        )
