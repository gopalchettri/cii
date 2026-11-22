"""The MITRE run's index (ADR-010): every MITRE lookup a run needs, built once per process from the stored
Enterprise and ICS STIX objects, and rebuilt when an import stores a new version."""

import re
import threading
from collections import defaultdict
from typing import Any

from app.core.config import Settings, get_settings
from app.core.constants import AiLimits
from app.crud.mitre.mitre_stix import get_mitre_enterprise_stix_repository, get_mitre_ics_stix_repository

#: One MITRE index: a dict of lookups (build_mitre_index lists them).
MitreIndex = dict[str, Any]

ACTOR_TYPES = ("intrusion-set", "campaign")
SOFTWARE_TYPES = ("malware", "tool")
MITRE_SOURCE_NAMES = ("mitre-attack", "mitre-ics-attack")
CITATION_LABEL = re.compile(r"\s*\(Citation:[^)]*\)")
MARKDOWN_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")  # "[Triton](https://attack.mitre.org/software/S1009)" -> "Triton"
SENTENCE_END = re.compile(r"(?<=[.!?])\s")
#: Typographic characters MITRE uses, and the plain characters a model writes for them.
PLAIN_CHARACTERS = str.maketrans(
    {
        "‘": "'",
        "’": "'",
        "‚": "'",
        "‛": "'",
        "′": "'",
        "“": '"',
        "”": '"',
        "„": '"',
        "″": '"',
        "‐": "-",
        "‑": "-",
        "‒": "-",
        "–": "-",
        "—": "-",
        "―": "-",
        "−": "-",
        " ": " ",
        "…": "...",
    }
)

# ponytail: one index per process behind one lock; the build runs once per stored version pair.
_index_lock = threading.Lock()
_current_index: dict[str, Any] = {}  # "versions": the (enterprise, ics) stored versions, "index": built from them


def get_mitre_id(stix_object: dict[str, Any]) -> str | None:
    """The ATT&CK ID of a STIX object (T1566, G0035, M1017, ...), or None."""
    for reference in stix_object.get("external_references") or []:
        if reference.get("source_name") in MITRE_SOURCE_NAMES and reference.get("external_id"):
            return str(reference["external_id"])
    return None


def get_mitre_url(stix_object: dict[str, Any]) -> str | None:
    """The object's page on attack.mitre.org, as MITRE's own reference gives it, or None."""
    for reference in stix_object.get("external_references") or []:
        if reference.get("source_name") in MITRE_SOURCE_NAMES and reference.get("url"):
            return str(reference["url"])
    return None


def clean_mitre_text(text: str) -> str:
    """MITRE text as a reader sees it: no citation labels, link text without its URL, plain quotes and dashes,
    single spaces. Used for every stored description and every quote the model returns, so both compare fairly."""
    text = CITATION_LABEL.sub("", text)
    text = MARKDOWN_LINK.sub(r"\1", text)
    text = text.translate(PLAIN_CHARACTERS)
    return " ".join(text.split())


def shorten_at_word_boundary(text: str, character_limit: int) -> str:
    """The text cut to at most character_limit characters, ending at a whole word."""
    if len(text) <= character_limit:
        return text
    return text[:character_limit].rsplit(" ", 1)[0]


def is_active(stix_object: dict[str, Any]) -> bool:
    """Neither revoked nor deprecated (an empty dict, a missing object, counts as active: callers check type)."""
    return not stix_object.get("revoked") and not stix_object.get("x_mitre_deprecated")


def get_current_mitre_index() -> MitreIndex:
    """The index of the stored MITRE data, built on first use and rebuilt when an import stores a new version.
    A domain never imported counts as empty; while an import replaces a domain (two versions stored) the index
    already built is kept."""
    enterprise, ics = get_mitre_enterprise_stix_repository(), get_mitre_ics_stix_repository()
    versions = (tuple(enterprise.stored_versions()), tuple(ics.stored_versions()))
    with _index_lock:
        replacing = len(versions[0]) > 1 or len(versions[1]) > 1
        if _current_index and (_current_index["versions"] == versions or replacing):
            return _current_index["index"]
        documents_by_domain = {"enterprise": enterprise.list_stix_objects(), "ics": ics.list_stix_objects()}
        _current_index["index"] = build_mitre_index(documents_by_domain, get_settings())
        _current_index["versions"] = versions
        return _current_index["index"]


def build_mitre_index(documents_by_domain: dict[str, list[dict[str, Any]]], settings: Settings) -> MitreIndex:
    """Every MITRE lookup a run needs, from the stored Enterprise and ICS documents.

    Keys: objects, domains, relationships_from, techniques, techniques_by_actor ({actor_id: {technique_id:
    software name or None}}), technique_catalogue, catalogue_legend, procedures_by_technique,
    mitigations_by_technique, technique_by_mitre_id, group_by_mitre_id, known_mitre_ids, software_descriptions,
    dataset_snapshot, actor_profiles (one line per group and campaign with its call tokens), campaign_groups
    ({campaign_id: [attributed group ids]}), ics_assets, asset_by_mitre_id and asset_mitre_ids_by_technique."""
    index: MitreIndex = {}
    _add_newest_objects(index, documents_by_domain)
    _add_relationships_and_techniques(index)
    _add_techniques_used_by_each_actor(index)
    _add_actor_profiles(index, settings)
    _add_ics_assets(index, settings)
    _add_technique_catalogue(index, settings)
    _add_procedures_and_mitigations(index, settings)
    _add_lookups_by_mitre_id(index, settings)
    return index


def _add_newest_objects(index: MitreIndex, documents_by_domain: dict[str, list[dict[str, Any]]]) -> None:
    """objects: the newest version of every object, descriptions cleaned; domains: where each comes from."""
    objects: dict[str, dict[str, Any]] = {}
    domains: defaultdict[str, set[str]] = defaultdict(set)
    for domain, documents in documents_by_domain.items():
        for stix_object in documents:
            if stix_object.get("type") == "x-mitre-ingestion" or not stix_object.get("id"):
                continue  # an import manifest, not MITRE data
            domains[stix_object["id"]].add(domain)
            description = stix_object.get("description")
            if isinstance(description, str):
                stix_object = {**stix_object, "description": clean_mitre_text(description)}
            existing = objects.get(stix_object["id"])
            if existing is None or (stix_object.get("modified") or "") > (existing.get("modified") or ""):
                objects[stix_object["id"]] = stix_object
    index["objects"], index["domains"] = objects, domains


def _add_relationships_and_techniques(index: MitreIndex) -> None:
    """Active objects only: relationships indexed both ways, and the techniques in MITRE ID order."""
    active_objects = []
    for stix_object in index["objects"].values():
        if is_active(stix_object):
            active_objects.append(stix_object)
    relationships_from: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    relationships_to: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    techniques = {}
    for stix_object in active_objects:
        if stix_object["type"] == "relationship":
            relationships_from[stix_object["source_ref"]].append(stix_object)
            relationships_to[stix_object["target_ref"]].append(stix_object)
        elif stix_object["type"] == "attack-pattern" and get_mitre_id(stix_object):
            techniques[stix_object["id"]] = stix_object
    mitre_id_and_technique_id = []
    for technique_id, technique in techniques.items():
        mitre_id_and_technique_id.append((get_mitre_id(technique), technique_id))
    mitre_id_and_technique_id.sort()
    technique_ids_in_id_order = []
    for _, technique_id in mitre_id_and_technique_id:
        technique_ids_in_id_order.append(technique_id)
    index["active_objects"], index["techniques"] = active_objects, techniques
    index["relationships_from"], index["relationships_to"] = relationships_from, relationships_to
    index["technique_ids_in_id_order"] = technique_ids_in_id_order


def _add_techniques_used_by_each_actor(index: MitreIndex) -> None:
    """techniques_by_actor: each actor's techniques, used directly or through active software (direct wins)."""
    objects, techniques, relationships_from = index["objects"], index["techniques"], index["relationships_from"]
    techniques_by_actor = {}
    for actor in index["active_objects"]:
        if actor["type"] not in ACTOR_TYPES or not get_mitre_id(actor):
            continue
        used_techniques: dict[str, str | None] = {}
        uses_relationships = []
        for relationship in relationships_from[actor["id"]]:
            if relationship["relationship_type"] == "uses":
                uses_relationships.append(relationship)
        for relationship in uses_relationships:
            if relationship["target_ref"] in techniques:
                used_techniques[relationship["target_ref"]] = None
        for relationship in uses_relationships:
            software = objects.get(relationship["target_ref"], {})
            if software.get("type") not in SOFTWARE_TYPES or not is_active(software):
                continue
            for software_relationship in relationships_from[software["id"]]:
                if (
                    software_relationship["relationship_type"] == "uses"
                    and software_relationship["target_ref"] in techniques
                ):
                    used_techniques.setdefault(software_relationship["target_ref"], software.get("name"))
        techniques_by_actor[actor["id"]] = used_techniques
    index["techniques_by_actor"] = techniques_by_actor


def _add_actor_profiles(index: MitreIndex, settings: Settings) -> None:
    """actor_profiles: one line per group and campaign for actor selection (MITRE ID, name, kind, other names,
    the start of its description, its active software), with its call tokens counted once here;
    campaign_groups: the indexed groups each campaign is attributed to."""
    objects, techniques_by_actor = index["objects"], index["techniques_by_actor"]
    actor_profiles = []
    campaign_groups: defaultdict[str, list[str]] = defaultdict(list)
    for actor_id in sorted(techniques_by_actor):
        actor = objects[actor_id]
        software_names = set()
        for relationship in index["relationships_from"][actor_id]:
            target = objects.get(relationship["target_ref"], {})
            kind = relationship["relationship_type"]
            if kind == "uses" and target.get("type") in SOFTWARE_TYPES and is_active(target) and target.get("name"):
                software_names.add(target["name"])
            target_is_indexed_group = target.get("type") == "intrusion-set" and target.get("id") in techniques_by_actor
            if actor["type"] == "campaign" and kind == "attributed-to" and target_is_indexed_group:
                campaign_groups[actor_id].append(target["id"])
        line = _actor_profile_line(actor, sorted(software_names), settings)
        tokens = len(line) // AiLimits.PROMPT_CHARS_PER_TOKEN
        actor_profiles.append({"actor_id": actor_id, "mitre_id": get_mitre_id(actor), "line": line, "tokens": tokens})
    index["actor_profiles"], index["campaign_groups"] = actor_profiles, dict(campaign_groups)


def _actor_profile_line(actor: dict[str, Any], software_names: list[str], settings: Settings) -> str:
    """'G0101 | Zeta | intrusion-set | also known as: ... | description | software: ...'."""
    other_names: list[str] = []
    for alias in actor.get("aliases") or []:
        if isinstance(alias, str) and alias != actor["name"] and alias not in other_names:
            other_names.append(alias)
    actor_kind = actor["type"]
    if actor["type"] == "campaign" and actor.get("first_seen"):
        last_seen = str(actor.get("last_seen") or "unknown")[:7]
        actor_kind = f"campaign, active {str(actor['first_seen'])[:7]} to {last_seen}"
    description = shorten_at_word_boundary(
        actor.get("description") or "", settings.actor_profile_description_characters
    )
    return (
        f"{get_mitre_id(actor)} | {actor['name']} | {actor_kind} | also known as: {', '.join(other_names) or 'none'} | "
        f"{description} | software: {', '.join(software_names) or 'none'}"
    )


def _add_ics_assets(index: MitreIndex, settings: Settings) -> None:
    """ics_assets: one planner line per MITRE ICS asset type; asset_by_mitre_id; asset_mitre_ids_by_technique:
    the asset types each technique targets."""
    asset_objects = []
    for stix_object in index["active_objects"]:
        if stix_object["type"] == "x-mitre-asset" and get_mitre_id(stix_object):
            asset_objects.append((get_mitre_id(stix_object), stix_object))
    asset_objects.sort()
    ics_assets, asset_by_mitre_id = [], {}
    for asset_mitre_id, asset in asset_objects:
        asset_by_mitre_id[asset_mitre_id] = asset["id"]
        related_names: list[str] = []
        for related_asset in asset.get("x_mitre_related_assets") or []:
            if (
                isinstance(related_asset, dict)
                and related_asset.get("name")
                and related_asset["name"] not in related_names
            ):
                related_names.append(related_asset["name"])
        description = shorten_at_word_boundary(
            asset.get("description") or "", settings.ics_asset_description_characters
        )
        ics_assets.append(
            f"{asset_mitre_id} | {asset['name']} | also called: {', '.join(related_names) or 'none'} | "
            f"sectors: {', '.join(asset.get('x_mitre_sectors') or []) or 'none'} | "
            f"platforms: {', '.join(asset.get('x_mitre_platforms') or []) or 'none'} | {description}"
        )
    asset_mitre_ids_by_technique = {}
    for technique_id in index["technique_ids_in_id_order"]:
        targeted_asset_ids: set[str] = set()
        for relationship in index["relationships_from"][technique_id]:
            asset_mitre_id = get_mitre_id(index["objects"].get(relationship["target_ref"], {})) or ""
            if relationship["relationship_type"] == "targets" and asset_mitre_id in asset_by_mitre_id:
                targeted_asset_ids.add(asset_mitre_id)
        asset_mitre_ids_by_technique[technique_id] = sorted(targeted_asset_ids)
    index["ics_assets"], index["asset_by_mitre_id"] = ics_assets, asset_by_mitre_id
    index["asset_mitre_ids_by_technique"] = asset_mitre_ids_by_technique


def _numbered_codes(names: set[str]) -> dict[str, str]:
    """'1', '2', ... for each name in sorted order."""
    codes = {}
    for code, name in enumerate(sorted(names), 1):
        codes[name] = str(code)
    return codes


def _add_technique_catalogue(index: MitreIndex, settings: Settings) -> None:
    """technique_catalogue: 'ID|name|domain|tactic codes|platform codes|targeted asset codes|summary' per
    technique (a summary for ICS techniques only), and catalogue_legend for its codes."""
    tactic_names, platform_names = set(), set()
    for technique in index["techniques"].values():
        for phase in technique.get("kill_chain_phases") or []:
            tactic_names.add(phase["phase_name"])
        for platform in technique.get("x_mitre_platforms") or []:
            platform_names.add(platform)
    tactic_codes, platform_codes = _numbered_codes(tactic_names), _numbered_codes(platform_names)
    asset_codes = _numbered_codes(set(index["asset_by_mitre_id"]))
    catalogue = []
    for technique_id in index["technique_ids_in_id_order"]:
        technique, technique_domains = index["techniques"][technique_id], index["domains"][technique_id]
        domain_codes = []
        if "enterprise" in technique_domains:
            domain_codes.append("E")
        if "ics" in technique_domains:
            domain_codes.append("I")
        tactics, platforms, targets = [], [], []
        for phase in technique.get("kill_chain_phases") or []:
            tactics.append(tactic_codes[phase["phase_name"]])
        for platform in technique.get("x_mitre_platforms") or []:
            platforms.append(platform_codes[platform])
        for asset_mitre_id in index["asset_mitre_ids_by_technique"][technique_id]:
            targets.append(asset_codes[asset_mitre_id])
        summary = ""
        if "ics" in technique_domains:  # one sentence for every technique would crowd planner actors out
            sentences = SENTENCE_END.split(" ".join((technique.get("description") or "").split()))
            opening = " ".join(sentences[: settings.catalogue_summary_sentences])
            summary = opening[: settings.catalogue_summary_characters].replace("|", "/")
        fields = [str(get_mitre_id(technique)), technique["name"], "+".join(domain_codes), ",".join(tactics)]
        catalogue.append("|".join([*fields, ",".join(platforms), ",".join(targets), summary]))
    index["technique_catalogue"] = catalogue
    index["catalogue_legend"] = {
        "domains": {"E": "enterprise", "I": "ics"},
        "tactics": _codes_to_names(tactic_codes),
        "platforms": _codes_to_names(platform_codes),
        "targeted_ics_assets": _codes_to_names(asset_codes),
    }


def _codes_to_names(codes: dict[str, str]) -> dict[str, str]:
    legend = {}
    for name, code in codes.items():
        legend[code] = name
    return legend


def _add_procedures_and_mitigations(index: MitreIndex, settings: Settings) -> None:
    """procedures_by_technique: MITRE procedure examples, newest first; mitigations_by_technique."""
    objects = index["objects"]
    procedures_by_technique: dict[str, list[dict[str, Any]]] = {}
    mitigations_by_technique: dict[str, list[dict[str, Any]]] = {}
    for technique_id in index["technique_ids_in_id_order"]:
        dated_procedures: list[tuple[str, int, dict[str, Any]]] = []
        mitigations: dict[str, dict[str, Any]] = {}
        for relationship in index["relationships_to"][technique_id]:
            source = objects.get(relationship["source_ref"], {})
            if not source or not is_active(source):
                continue
            is_procedure = (
                relationship["relationship_type"] == "uses" and source["type"] in ACTOR_TYPES + SOFTWARE_TYPES
            )
            if is_procedure and relationship.get("description"):
                text = shorten_at_word_boundary(relationship["description"], settings.procedure_text_characters)
                procedure = {
                    "technique": get_mitre_id(index["techniques"][technique_id]),
                    "actor": source.get("name"),
                    "actor_mitre_id": get_mitre_id(source),
                    "actor_stix_id": source["id"],
                    "actor_type": source["type"],
                    "via_software": source.get("name") if source["type"] in SOFTWARE_TYPES else None,
                    "text": text,
                }
                dated_procedures.append((relationship.get("modified") or "", len(dated_procedures), procedure))
            elif relationship["relationship_type"] == "mitigates" and source["type"] == "course-of-action":
                mitigations[str(get_mitre_id(source))] = {"mitre_id": get_mitre_id(source), "name": source.get("name")}
        dated_procedures.sort(reverse=True)  # newest first; the position breaks ties, procedures are never compared
        procedures_by_technique[technique_id] = []
        for _, _, procedure in dated_procedures:
            procedures_by_technique[technique_id].append(procedure)
        mitigations_by_technique[technique_id] = []
        for mitre_id in sorted(mitigations):
            mitigations_by_technique[technique_id].append(mitigations[mitre_id])
    index["procedures_by_technique"], index["mitigations_by_technique"] = (
        procedures_by_technique,
        mitigations_by_technique,
    )


def _add_lookups_by_mitre_id(index: MitreIndex, settings: Settings) -> None:
    """technique_by_mitre_id, group_by_mitre_id, known_mitre_ids (retired IDs count as invented; the names and
    aliases count too, as a group named TA2541 (G1018) looks like an ID), software_descriptions and
    dataset_snapshot (the collection versions of each domain)."""
    group_by_mitre_id, software_descriptions, known_mitre_ids = {}, {}, set()
    for stix_object in index["active_objects"]:
        mitre_id = get_mitre_id(stix_object)
        if mitre_id:
            known_mitre_ids.add(mitre_id)
        known_mitre_ids.update([stix_object.get("name") or "", *(stix_object.get("aliases") or [])])
        if stix_object["type"] == "intrusion-set" and mitre_id:
            group_by_mitre_id[mitre_id] = stix_object["id"]
        if stix_object["type"] in SOFTWARE_TYPES:
            description = stix_object.get("description") or ""
            limit = settings.software_description_characters
            software_descriptions[stix_object.get("name")] = shorten_at_word_boundary(description, limit)
    technique_by_mitre_id = {}
    for technique_id in index["technique_ids_in_id_order"]:
        technique_by_mitre_id[get_mitre_id(index["techniques"][technique_id])] = technique_id
    dataset_snapshot = {}
    for domain in ("enterprise", "ics"):
        versions = set()
        for stix_object in index["objects"].values():
            if stix_object["type"] == "x-mitre-collection" and domain in index["domains"][stix_object["id"]]:
                versions.add(stix_object.get("modified"))
        dataset_snapshot[domain] = sorted(versions)
    index["technique_by_mitre_id"], index["group_by_mitre_id"] = technique_by_mitre_id, group_by_mitre_id
    index["known_mitre_ids"], index["software_descriptions"] = known_mitre_ids, software_descriptions
    index["dataset_snapshot"] = dataset_snapshot
