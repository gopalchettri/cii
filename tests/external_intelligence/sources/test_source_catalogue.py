"""The catalogue: the two ATT&CK sources, Enterprise first, at the owner's URLs."""

from app.core.constants import IntelSource
from app.domain.intel.sources.attack import DATASETS, MitreAttackSource


def test_both_attack_sources_are_built_enterprise_first() -> None:
    assert list(IntelSource) == [IntelSource.ATTACK_ENTERPRISE, IntelSource.ATTACK_ICS] == list(DATASETS)
    assert all(MitreAttackSource(source).source_id == source for source in IntelSource)


def test_the_datasets_are_the_owners_urls() -> None:
    base = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    assert {
        "mitre_attack_enterprise": base + "enterprise-attack/enterprise-attack.json",
        "mitre_attack_ics": base + "ics-attack/ics-attack.json",
    } == DATASETS
