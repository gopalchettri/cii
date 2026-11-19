"""The MITRE run's index (ADR-010), from synthetic STIX documents: what it keeps, the lookups it builds, and
when the process copy is rebuilt."""

import json
from typing import Any

import pytest

from app.core.constants import AiLimits
from app.search.mitre import mitre_index
from tests.mitre.mitre_samples import (
    ALPHA,
    BETA,
    CAMPAIGN,
    CONTROL_LOGIC,
    DENIAL_OF_CONTROL,
    GAMMA,
    LOSS_OF_AVAILABILITY,
    PHISHING,
    VALID_ACCOUNTS,
    ZETA,
    documents,
    index_with_delta,
    index_with_ics_assets,
    mitre_reference,
    relationship,
    sample_index,
    settings,
)


def catalogue_fields(index: dict[str, Any]) -> dict[str, list[str]]:
    fields = {}
    for line in index["technique_catalogue"]:
        fields[line.split("|")[0]] = line.split("|")
    return fields


def test_index_keeps_active_objects_and_builds_the_lookups() -> None:
    index = sample_index()
    assert set(index["techniques"]) == {
        PHISHING,
        CONTROL_LOGIC,
        VALID_ACCOUNTS,
        DENIAL_OF_CONTROL,
        LOSS_OF_AVAILABILITY,
    }
    assert "__ingestion__" not in index["objects"]  # the manifest is skipped
    assert index["objects"][PHISHING]["description"] == "Phishing for access"  # citation stripped
    catalogue = catalogue_fields(index)
    assert (
        catalogue["T0813"][2] == "I"
        and catalogue["T0813"][6] == "Temporarily prevent operators from controlling the process."
    )
    assert catalogue["T1566"][6] == ""  # summaries only for ICS techniques
    assert catalogue_fields(sample_index(catalogue_summary_characters=11))["T0813"][6] == "Temporarily"
    assert "initial-access" in json.dumps(index["catalogue_legend"])
    assert index["techniques_by_actor"][ZETA] == {PHISHING: None, CONTROL_LOGIC: None}
    assert index["techniques_by_actor"][ALPHA] == {PHISHING: "Tool"}  # through its software
    assert index["techniques_by_actor"][BETA] == {}  # its only software is deprecated
    newest_first = []
    for procedure in index["procedures_by_technique"][PHISHING]:
        newest_first.append(procedure["actor"])
    assert newest_first == ["Gamma", "Own op", "Tool", "Zeta"]
    assert index["mitigations_by_technique"][PHISHING] == [{"mitre_id": "M1017", "name": "User Training"}]
    assert index["group_by_mitre_id"]["G0101"] == ZETA and "T1566" in index["known_mitre_ids"]
    assert "T1001" not in index["known_mitre_ids"]  # a revoked ID counts as invented


def test_index_has_one_actor_profile_per_group_and_campaign() -> None:
    index = sample_index()
    profiles = {}
    for profile in index["actor_profiles"]:
        profiles[profile["actor_id"]] = profile
    assert set(profiles) == {ZETA, ALPHA, BETA, GAMMA, CAMPAIGN}
    assert profiles[ALPHA]["line"] == (
        "G0102 | Alpha | intrusion-set | also known as: none | Alpha steals payment card data from retail companies. "
        "| software: Tool"
    )
    assert profiles[BETA]["line"].endswith("software: none")  # its only software is deprecated
    assert profiles[ZETA]["tokens"] == len(profiles[ZETA]["line"]) // AiLimits.PROMPT_CHARS_PER_TOKEN
    assert index["campaign_groups"] == {CAMPAIGN: [ZETA]}


def test_campaign_groups_hold_only_active_indexed_groups() -> None:
    samples = documents()
    samples["enterprise"] += [
        {
            "type": "intrusion-set",
            "id": "intrusion-set--retired",
            "name": "Retired",
            "revoked": True,
            "description": "A revoked group record kept for history",
            "external_references": mitre_reference("G0199"),
        },
        relationship("r2", CAMPAIGN, "intrusion-set--retired", "attributed-to"),
    ]
    index = mitre_index.build_mitre_index(samples, settings())
    assert index["campaign_groups"][CAMPAIGN] == [ZETA]


def test_mitre_text_is_cleaned_once_so_the_model_and_the_check_read_the_same_words() -> None:
    index = index_with_delta()
    assert index["objects"]["intrusion-set--delta"]["description"] == (
        "Delta compromised the local government's wastewater control system using Triton - a safety-system malware."
    )
    profile_line = ""
    for profile in index["actor_profiles"]:
        if profile["mitre_id"] == "G0105":
            profile_line = profile["line"]
    assert "https://" not in profile_line and "government's wastewater" in profile_line
    assert mitre_index.shorten_at_word_boundary("one two three", 9) == "one two"  # never ends mid-word


def test_actor_profiles_carry_other_names_and_campaign_dates() -> None:
    lines = {}
    for profile in index_with_ics_assets()["actor_profiles"]:
        lines[profile["mitre_id"]] = profile["line"]
    assert "| also known as: Water Bear |" in lines["G0101"]
    assert "| campaign, active 2022-06 to 2022-10 |" in lines["C0101"]


def test_ics_asset_types_and_their_techniques_are_indexed() -> None:
    index = index_with_ics_assets()
    assert index["asset_mitre_ids_by_technique"][CONTROL_LOGIC] == ["A0003"]
    assert index["asset_mitre_ids_by_technique"][PHISHING] == []
    assert index["ics_assets"] == [
        "A0003 | Programmable Logic Controller (PLC) | also called: Field Controller | sectors: General | "
        "platforms: Embedded | A PLC controls an industrial process. More text follows here."
    ]
    assert index["catalogue_legend"]["targeted_ics_assets"][catalogue_fields(index)["T0831"][5]] == "A0003"


class FakeStixStore:
    """A MITRE STIX repository's read surface: versions and objects set by the test, reads counted."""

    def __init__(self, versions: list[str], objects: list[dict[str, Any]]) -> None:
        self.versions, self.objects, self.reads = versions, objects, 0

    def itself(self) -> "FakeStixStore":
        """Stands in for the repository's getter."""
        return self

    def stored_versions(self) -> list[str]:
        return list(self.versions)

    def list_stix_objects(self) -> list[dict[str, Any]]:
        self.reads += 1
        return list(self.objects)


@pytest.fixture
def stores(monkeypatch: pytest.MonkeyPatch) -> tuple[FakeStixStore, FakeStixStore]:
    samples = documents()
    enterprise, ics = FakeStixStore(["v1"], samples["enterprise"]), FakeStixStore([], [])
    monkeypatch.setattr(mitre_index, "get_mitre_enterprise_stix_repository", enterprise.itself)
    monkeypatch.setattr(mitre_index, "get_mitre_ics_stix_repository", ics.itself)
    monkeypatch.setattr(mitre_index, "_current_index", {})
    return enterprise, ics


def test_the_process_index_is_built_once_per_stored_version(stores: tuple[FakeStixStore, FakeStixStore]) -> None:
    enterprise, ics = stores
    first = mitre_index.get_current_mitre_index()
    assert first["techniques"] and CONTROL_LOGIC not in first["techniques"]  # ICS never imported: empty, not refused
    assert mitre_index.get_current_mitre_index() is first and enterprise.reads == 1
    ics.versions, ics.objects = ["v1", "v2"], documents()["ics"]
    assert mitre_index.get_current_mitre_index() is first  # an import replacing ICS: the built index is kept
    ics.versions = ["v2"]
    rebuilt = mitre_index.get_current_mitre_index()
    assert rebuilt is not first and CONTROL_LOGIC in rebuilt["techniques"] and enterprise.reads == 2
