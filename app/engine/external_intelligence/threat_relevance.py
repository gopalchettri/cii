"""How near the deployment's country the groups known for each planned threat are (G232, owner 2026-10-14:
"Prioritize candidate threats using ... intelligence documenting activity targeting UAE organizations ...
regional intelligence ... established global threats"). Each threat is matched by keywords only (BM25 over the
evidence index's technique texts: no AI or embedding call) to the techniques it reads most like; its scope is
the nearest of theirs: a group behind one attacked the country, else its region, else global. The audit keeps
the techniques and the groups that make it so. The path ranking prefers a nearer threat only after coverage
(path_ranking). Pure."""

from collections.abc import Sequence
from typing import Any

import numpy as np

from app.core.constants import SCOPE_RANK, EvidenceScope, GroupRelevance, IntelKind, KnownGroups
from app.models.external_intelligence.evidence_corpus import EvidenceCorpus
from app.models.external_intelligence.known_groups import Nearness
from app.models.threats import PlannedThreat
from app.search.indexes import KeywordIndex

#: The groups shown for a scope: those that attacked the country, or its region.
_SHOWN = {
    EvidenceScope.COUNTRY: GroupRelevance.TARGETED_COUNTRY,
    EvidenceScope.REGIONAL: GroupRelevance.TARGETED_REGION,
}


def threat_relevance(
    corpus: EvidenceCorpus, threats: Sequence[PlannedThreat], near: Nearness
) -> dict[str, dict[str, Any]]:
    """Each threat's {scope, techniques, groups} by its key; {} with no technique or no country."""
    techniques = [hit for hit in corpus.hits if hit.kind == IntelKind.TECHNIQUE]
    if not techniques or not near.country:
        return {}
    texts = dict(zip((hit.external_id for hit in corpus.hits), corpus.search_texts, strict=True))
    index = KeywordIndex([texts[hit.external_id] for hit in techniques])
    found: dict[str, dict[str, Any]] = {}
    for threat in threats:
        scores = index.score(f"{threat.type_name} {threat.name}")
        best = np.argsort(-scores, kind="stable")[: KnownGroups.TECHNIQUES_PER_THREAT]
        refs = [techniques[position].external_id for position in best if scores[position] > 0]
        found[threat.key] = _nearness(refs, corpus, near)
    return found


def _nearness(refs: list[str], corpus: EvidenceCorpus, near: Nearness) -> dict[str, Any]:
    uses = {ref: corpus.groups.by_technique.get(ref, ()) for ref in refs}
    scopes = {ref: near.scope(uses[ref]) for ref in refs}
    scope = max(scopes.values(), key=lambda found: SCOPE_RANK[found], default=EvidenceScope.GLOBAL)
    level = _SHOWN.get(scope)
    groups = sorted({use.name for ref in refs for use in uses[ref] if level and level in near.of(use)})
    return {"scope": str(scope), "techniques": refs, "groups": groups}
