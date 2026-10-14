"""Threat finding (v1 threat_identification/planner.plan_threats): the library
first, the AI judging relevance.

1. LANDSCAPE  the asset and every supporting system as one text within half the model input
              (asset_landscape.py).
2. SEARCH     every STRIDE category's library threats, found by ONE hybrid search over all categories' queries
              (one embedding call); a threat shortlisted under one category joins every category it maps to.
3. CATEGORIES the six categories at once: every threat of each judged by the relevance gate in small batches
              sent at once; a threat refused for a need under one category refused under all; then at most
              one AI gap-fill per category where none applies (category_check.py).
4. FOLD       one threat per threat: same key, same name, same wording, then the AI same-attack check; never
              across two library types.
5. ACTORS     every surviving threat's actors, ranked at once (attacker_assignment.py), after the fold.
6. CHECK      closest-match attackers checked by the AI; every alias in a reason turned back into a name.
An outage (Unavailable, a store down) is raised and the job retries; an unusable AI answer never fails the
run: its check is noted on the plan instead."""

import dataclasses
from concurrent.futures import ThreadPoolExecutor

import structlog

from app.ai import (
    ChatModel,
    EmbeddingModel,
    RerankModel,
    get_chat_model,
    get_embedding_model,
    get_rerank_model,
)
from app.core.constants import (
    ErrorCode,
    LogEvent,
    PlanMessage,
    Search,
    StrideCategory,
    ThreatFinding,
)
from app.core.exceptions import PlanRefused
from app.core.singletons import singleton
from app.core.tracing import ranked, record_detail, step_detail_enabled, traced
from app.engine.scenarios.finding.ai_gap_fill import GapFiller, refused_threat_names
from app.engine.scenarios.finding.asset_landscape import describe_asset_for_ai, library_search_queries
from app.engine.scenarios.finding.category_check import CategoryChecker
from app.engine.scenarios.finding.library_matcher import LibraryMatcher
from app.engine.scenarios.finding.relevance_gate import RelevanceGate, accepted_library_threat
from app.engine.scenarios.finding.verdict_checks import (
    keep_on_matching_systems,
    place_on_matching_systems,
    refuse_unrecorded_needs_everywhere,
    run_asset_types,
    threats_that_fit,
)
from app.engine.scenarios.threat_list.attacker_assignment import AttackerAssigner, vetted_attackers
from app.engine.scenarios.threat_list.attacker_choice import unranked_notes
from app.engine.scenarios.threat_list.duplicate_merge import merge_reworded_threats, merge_same_threats
from app.engine.scenarios.threat_list.same_attack_check import SameAttackCheck
from app.engine.shared.names import replace_codes_with_names
from app.engine.shared.parallel import run_in_shared_pool
from app.models.asset_context import FrozenContext
from app.models.library import LibraryThreat, ThreatLibrary
from app.models.threats import (
    CategoryAudit,
    CategoryFindings,
    FoldedThreat,
    Landscape,
    PlannedThreat,
    ThreatFindings,
)
from app.search.service import LibrarySearch, get_library_search
from app.search.snapshot import LibrarySnapshot

log = structlog.get_logger(__name__)


class ThreatFinder:
    def __init__(
        self, chat: ChatModel, search: LibrarySearch, rerank: RerankModel, embeddings: EmbeddingModel
    ) -> None:
        self._chat = chat
        self._search = search
        self._rerank = rerank
        self._embeddings = embeddings

    @traced("threats.find")
    def find_threats(self, context: FrozenContext, country: str = "") -> ThreatFindings:
        """Every threat that applies to the asset, one per threat, each with its acting library actor. One
        library snapshot serves the whole run: an edit made meanwhile never mixes two library versions."""
        snapshot = self._search.snapshot()
        library = snapshot.library.threat_library
        if not library.actors:  # never blank (owner, 2026-10-05): refused before any AI call is bought
            raise PlanRefused(ErrorCode.ACTOR_LIBRARY_EMPTY, PlanMessage.ACTOR_LIBRARY_EMPTY)
        landscape = describe_asset_for_ai(context, self._chat.max_prompt_chars // 2, country)  # G232
        if landscape.facts_shortened_note:
            log.warning(LogEvent.PLANNER_FACTS_SHORTENED, note=landscape.facts_shortened_note)
        fitting, type_notes = threats_that_fit(library.threats, context)  # G211: AssetType fits the run
        by_category = {
            category: [threat for threat in fitting if category in threat.categories]
            for category in StrideCategory
        }
        shortlists = self._search_library_per_category(snapshot, context, by_category)
        found = self._check_categories(snapshot, context, landscape, by_category, shortlists)
        threats, folded, notes = self._merge_and_assign_attackers(snapshot, found, landscape, context)
        notes = [
            *([landscape.facts_shortened_note] if landscape.facts_shortened_note else []),
            *_library_data_notes(library),
            *type_notes,
            *notes,
            *[PlanMessage.NOT_STRIDE.format(category=name) for name in library.other_categories],
        ]
        audits = [_named_audit(result.audit, landscape) for result in found]
        stamp = {table: digest.hex() if digest else None for table, digest in snapshot.library.stamp}
        category_ids = {name.strip().lower(): row_id for row_id, name in library.category_ids}
        return ThreatFindings(
            threats, audits, folded, notes, landscape, library_stamp=stamp, category_ids=category_ids
        )

    @traced("threats.search_shortlists")
    def _search_library_per_category(
        self,
        snapshot: LibrarySnapshot,
        context: FrozenContext,
        by_category: dict[StrideCategory, list[LibraryThreat]],
    ) -> dict[StrideCategory, list[LibraryThreat]]:
        """Each category's threats any of its queries found, best score first, from ONE search; then every
        threat joins each other category it maps to (a top-k miss under one category never decides it)."""
        asked = [
            (query, category)
            for category in StrideCategory
            if by_category[category]
            for query in library_search_queries(context, category)
        ]
        hits_per_query = snapshot.find_threats(asked, Search.THREATS_PER_QUERY, run_asset_types(context))
        best: dict[StrideCategory, dict[int, tuple[float, LibraryThreat]]] = {c: {} for c in StrideCategory}
        for (_, category), hits in zip(asked, hits_per_query, strict=True):
            for threat, score in hits:
                if score > best[category].get(threat.catalogue_id, (-1.0, threat))[0]:
                    best[category][threat.catalogue_id] = (score, threat)
        shortlists = {
            category: [
                threat for _, threat in sorted(found.values(), key=lambda b: (-b[0], b[1].catalogue_id))
            ]
            for category, found in best.items()
        }
        extended = {category: list(threats) for category, threats in shortlists.items()}
        for threats in shortlists.values():
            for threat in threats:
                for category in threat.categories:
                    if threat not in extended[category]:
                        extended[category].append(threat)
        if step_detail_enabled():
            _trace_shortlists(best, extended)
        return extended

    @traced("threats.check_categories")
    def _check_categories(
        self,
        snapshot: LibrarySnapshot,
        context: FrozenContext,
        landscape: Landscape,
        by_category: dict[StrideCategory, list[LibraryThreat]],
        shortlists: dict[StrideCategory, list[LibraryThreat]],
    ) -> list[CategoryFindings]:
        """The six categories at once (v1: one after another took 525 s), their gate batches in ONE shared
        pool (G121), each in its own copy of the log context, so every AI call record still names the run.
        Then code's checks on the verdicts (verdict_checks.py), then any gap-fill. Results in STRIDE order."""
        with ThreadPoolExecutor(
            ThreatFinding.AI_BATCHES_AT_ONCE, thread_name_prefix="gate-batch"
        ) as gate_pool:
            vetted = sorted(actor.name for actor in vetted_attackers(snapshot.library.threat_library))
            gate = RelevanceGate(self._chat, landscape, gate_pool, vetted)
            matcher = LibraryMatcher(snapshot, self._rerank, run_asset_types(context))
            gap_filler = GapFiller(
                self._chat, gate, matcher, landscape, refused_threat_names(snapshot.library.threat_library)
            )
            checker = CategoryChecker(gate, gap_filler, by_category)

            def check_one_category(category: StrideCategory) -> CategoryFindings:
                # Typed, not a lambda: a lambda's parameter type is the checker's guess (one guessed str)
                return checker.check_category(category, shortlists[category])

            with ThreadPoolExecutor(
                ThreatFinding.CATEGORIES_AT_ONCE, thread_name_prefix="category-check"
            ) as pool:
                found = run_in_shared_pool(pool, check_one_category, list(StrideCategory))
                place_on_matching_systems(found, context)  # before any gap-fill: these may empty a category
                refuse_unrecorded_needs_everywhere(found)
                return run_in_shared_pool(pool, checker.fill_gap_if_empty, found)

    @traced("threats.fold_and_assign")
    def _merge_and_assign_attackers(
        self,
        snapshot: LibrarySnapshot,
        found: list[CategoryFindings],
        landscape: Landscape,
        context: FrozenContext,
    ) -> tuple[list[PlannedThreat], list[FoldedThreat], list[str]]:
        accepted = [
            accepted_library_threat(result.audit.category, threat, verdict)
            for result in found
            for threat, verdict in result.accepted
        ]
        ai_threats = [result.ai_threat for result in found if result.ai_threat is not None]
        # Duplicates first, attackers once, on the survivors only (G110, spec v4.0 §7.2.2 step 8): no actor
        # search is spent on a threat folded away, and no attacker decides which twin survives.
        threats, folded, type_notes = merge_same_threats(accepted + ai_threats)
        threats, reworded = merge_reworded_threats(threats, self._embeddings, context.asset["name"])
        threats, folded, same_attack_notes = SameAttackCheck(self._chat, landscape).merge_same_attacks(
            threats, folded + reworded
        )
        # A fold unites systems: each library threat keeps only those its AssetType fits (G211 review).
        threats = keep_on_matching_systems(threats, snapshot.library.threat_library.threats, context)
        threats = AttackerAssigner(snapshot, self._rerank).assign_attackers(threats, landscape.sector, True)
        attacker_notes = unranked_notes(threats)  # G229: the gate named the attacker, no AI call of its own
        return (
            [_named_threat(threat, landscape) for threat in threats],
            folded,
            type_notes + same_attack_notes + attacker_notes,
        )


def _trace_shortlists(
    best: dict[StrideCategory, dict[int, tuple[float, LibraryThreat]]],
    extended: dict[StrideCategory, list[LibraryThreat]],
) -> None:
    """Each category's best fused score per threat, then what joining the other categories added."""
    for category, found in best.items():
        scored = sorted(found.values(), key=lambda b: (-b[0], b[1].catalogue_id))
        record_detail(
            "best score per category",
            category,
            given={"threats_found": len(found)},
            produced=ranked((f"{threat.catalogue_id} {threat.name}", score) for score, threat in scored),
        )
    for category, threats in extended.items():
        shortlisted = len(best[category])
        record_detail(
            "cross-category extension",
            category,
            given={"shortlisted": shortlisted},
            produced={"added_from_other_categories": len(threats) - shortlisted},
        )


def _library_data_notes(library: ThreatLibrary) -> list[str]:
    """Bad library data, named on the plan for a curator: threats left out for no category link (G119), and
    threats whose AssetType is not a value, used as if untyped (G211)."""
    notes = []
    for threat_ids, message in (
        (library.threats_without_category, PlanMessage.LIBRARY_DATA_INVALID),
        (library.threats_unknown_asset_type, PlanMessage.ASSET_TYPE_UNKNOWN),
    ):
        if threat_ids:
            ids = ", ".join(str(threat_id) for threat_id in threat_ids[: ThreatFinding.NOTE_MAX_IDS])
            notes.append(message.format(count=len(threat_ids), ids=ids))
    return notes


def _named_threat(threat: PlannedThreat, landscape: Landscape) -> PlannedThreat:
    """T8: a reason (the attacker's too) names systems as a reviewer reads them; an AI threat's names too."""
    names = landscape.system_names
    threat = dataclasses.replace(
        threat,
        reason=replace_codes_with_names(threat.reason, names),
        attacker_check_reason=replace_codes_with_names(threat.attacker_check_reason, names),  # G229
    )
    if threat.from_library:
        return threat
    return dataclasses.replace(
        threat,
        name=replace_codes_with_names(threat.name, names),
        type_name=replace_codes_with_names(threat.type_name, names),
    )


def _named_audit(audit: CategoryAudit, landscape: Landscape) -> CategoryAudit:
    names = landscape.system_names
    audit.note = replace_codes_with_names(audit.note, names) if audit.note else audit.note
    audit.rejected = [
        rejected | {key: replace_codes_with_names(rejected[key], names) for key in ("threat", "reason")}
        for rejected in audit.rejected
    ]
    return audit


@singleton
def get_threat_finder() -> ThreatFinder:
    """One per process: it holds no run's state (every run builds its own landscape, gate and checks)."""
    return ThreatFinder(get_chat_model(), get_library_search(), get_rerank_model(), get_embedding_model())
