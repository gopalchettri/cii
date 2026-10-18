"""The searchable corpus of the approved sources' current records, read in one streamed pass: EPSS scores and
NVD details joined into their KEV vulnerability, rows in a fixed order and an order-free checksum."""

import dataclasses
import hashlib
from collections.abc import Iterable
from typing import Any

from app.core.constants import IntelKind, IntelMessage, IntelSource, IntelState
from app.models.external_intelligence.evidence import IntelHit
from app.models.external_intelligence.evidence_corpus import EvidenceCorpus
from app.models.external_intelligence.intel_record import content_hash_of
from app.search.external_intelligence.evidence_index import EvidenceIndexRefused, remove_indicators

Doc = dict[str, Any]
_HIT_FIELDS = ("external_id", "kind", "title", "text", "url", "source", "asset_type", "data")
#: What an NVD detail record adds to its vulnerability.
_DETAIL_FIELDS = ("affected", "cvss", "cvss_vector", "severity", "cwes")
_MODULUS = 2**256


def build_corpus(docs: Iterable[Doc], vector_space: str = "") -> EvidenceCorpus:
    """The corpus of these stored records; `vector_space` (the embedding model's name) is part of the
    checksum, so another model is another corpus. Raises EvidenceIndexRefused when nothing is searchable."""
    reading = _CorpusReading()
    for doc in docs:
        reading.add(doc)
    if not reading.hits:
        raise EvidenceIndexRefused(IntelMessage.SNAPSHOT_EMPTY)
    scores_joined, details_joined = _join(reading.hits, reading.scores, reading.details)
    hits = sorted(reading.hits, key=lambda hit: (hit.source, hit.external_id))
    checksum = content_hash_of(vector_space, reading.count, str(reading.digest_sum))
    return EvidenceCorpus(
        tuple(hits),
        tuple(remove_indicators(hit.text) for hit in hits),
        checksum,
        reading.versions,
        scores_joined,
        len(reading.scores) - scores_joined,
        details_joined,
        len(reading.details) - details_joined,
    )


class _CorpusReading:
    """The state of one pass over the records; never shared."""

    def __init__(self) -> None:
        self.hits: list[IntelHit] = []
        self.scores: dict[str, tuple[float, float]] = {}
        self.details: dict[str, Doc] = {}
        self.versions: dict[str, str] = {}
        self.count = 0
        self.digest_sum = 0

    def add(self, doc: Doc) -> None:
        """Count one stored record into the checksum and keep it as a hit, a score or a detail."""
        if doc.get("state") == IntelState.QUARANTINED:
            return
        key = f"{doc['source']}|{doc['external_id']}|{doc['content_hash']}".encode()
        # a sum of digests: the same whatever order the records arrive in, and no list of keys to hold
        self.digest_sum = (self.digest_sum + int.from_bytes(hashlib.sha256(key).digest(), "big")) % _MODULUS
        self.count += 1
        self.versions[doc["source"]] = max(self.versions.get(doc["source"], ""), str(doc["source_version"]))
        if doc["kind"] == IntelKind.EXPLOIT_SCORE:
            self._add_score(doc)
        elif doc["kind"] == IntelKind.VULNERABILITY_DETAIL:
            self._add_detail(doc)
        else:  # the record's own date and its fetch time travel with it, for the evidence's audit
            fetched = doc.get("fetched_at")
            hit = IntelHit(**{name: doc[name] for name in _HIT_FIELDS})
            dated = dataclasses.replace(
                hit, modified=doc.get("modified"), fetched_at=fetched.isoformat() if fetched else None
            )
            self.hits.append(dated)

    def _add_score(self, doc: Doc) -> None:
        """Keep an EPSS record's score and percentile by CVE, when both are numbers."""
        data = doc["data"]
        scores = (data.get("epss"), data.get("percentile"))
        if all(isinstance(score, int | float) and not isinstance(score, bool) for score in scores):
            self.scores[_cve(doc["external_id"], data)] = (float(scores[0]), float(scores[1]))

    def _add_detail(self, doc: Doc) -> None:
        """Keep an NVD detail record by CVE (of two versions, the higher content hash: a fixed pick)."""
        key = _cve(doc["external_id"], doc["data"])
        known = self.details.get(key)
        if known is None or doc["content_hash"] > known["content_hash"]:
            self.details[key] = {"content_hash": doc["content_hash"], "data": doc["data"]}


def _join(
    hits: list[IntelHit], scores: dict[str, tuple[float, float]], details: dict[str, Doc]
) -> tuple[int, int]:
    """Put each vulnerability's EPSS, NVD detail and the ids of the advisories naming it into its hit's data
    (in place in `hits`), the sources of the first two on `joined`; return how many scores and details found
    their vulnerability."""
    named_in: dict[str, list[str]] = {}
    for hit in hits:
        if hit.kind == IntelKind.ADVISORY:
            for cve in hit.data.get("cves") or []:
                named_in.setdefault(str(cve).strip().upper(), []).append(hit.external_id)
    scores_joined = details_joined = 0
    for position, hit in enumerate(hits):
        if hit.kind != IntelKind.VULNERABILITY:
            continue
        key = _cve(hit.external_id, hit.data)
        extra: dict[str, Any] = {}
        joined: list[IntelSource] = []
        if score := scores.get(key):
            scores_joined += 1
            extra |= {"epss": score[0], "percentile": score[1]}
            joined.append(IntelSource.FIRST_EPSS)
        if detail := details.get(key):
            details_joined += 1
            extra |= {name: detail["data"][name] for name in _DETAIL_FIELDS if name in detail["data"]}
            joined.append(IntelSource.NIST_NVD)
        if key in named_in:
            extra["advisories"] = sorted(set(named_in[key]))
        if extra:
            hits[position] = dataclasses.replace(hit, data={**hit.data, **extra}, joined=tuple(joined))
    return scores_joined, details_joined


def _cve(external_id: str, data: Doc) -> str:
    """The record's CVE id, upper case: its `cve` field, else its own id."""
    return str(data.get("cve") or external_id).strip().upper()
