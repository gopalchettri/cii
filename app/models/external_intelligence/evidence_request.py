"""What the engine is asked for evidence, and what it answers. Neutral: no planner or asset-context type, so
the evidence engine never imports the code that finds threats."""

from dataclasses import dataclass, field

from app.models.external_intelligence.evidence import Evidence, EvidenceSearchRecord


@dataclass(frozen=True)
class RecordedProduct:
    """What one record of the asset (the asset itself, or one system) says about its products, as written."""

    vendors: tuple[str, ...] = ()  # the vendor names recorded (vendor_name)
    products: tuple[str, ...] = ()  # the technologies and operating systems recorded (technology_used, ...)
    # every product version recorded beside them (ContextProperties.VERSION_KEYS)
    versions: tuple[str, ...] = ()


@dataclass(frozen=True)
class RecordedProducts:
    """The vendors, products and versions the asset and the threat's systems record, one entry per record, so
    a version is only ever read with the product recorded beside it. Empty: the asset records none."""

    rows: tuple[RecordedProduct, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class EvidenceRequest:
    """One threat's evidence search."""

    text: str  # the threat's search text, already cut to EvidenceLimits.QUERY_MAX_CHARS
    asset_types: frozenset[str]  # the IT / OT filter: the asset's and the threat's systems' types
    recorded_products: RecordedProducts


@dataclass(frozen=True)
class EvidenceResult:
    evidence: tuple[Evidence, ...]  # best first, at most EvidenceLimits.PER_THREAT
    search: EvidenceSearchRecord
