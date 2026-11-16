"""Library duplicate check: the threat library's look-alike threats, for the curators to merge once. Every
library threat name is embedded with the app's own embedding model, and each pair of the same threat type
and asset type at or above --cosine is listed, closest first (an attack's IT and OT variants are no copies).
A run joins a pair at ThreatFinding.LIBRARY_DUPLICATE_COSINE or more; this report also shows the near misses.
Reads the library (SQL Server) and writes nothing.

From the project folder:
  .venv\\Scripts\\python scripts\\library_duplicate_check.py [--cosine 0.75]"""

import argparse
import itertools
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.container import get_embedding_model, get_library_search  # noqa: E402
from app.core.constants import ThreatFinding  # noqa: E402
from app.domain.shared.names import threat_name_without_code  # noqa: E402
from app.models.library.library import LibraryThreat  # noqa: E402


def find_look_alikes(
    threats: Sequence[LibraryThreat], vectors: Any, floor: float
) -> list[tuple[float, LibraryThreat, LibraryThreat]]:
    """Each pair of one threat type and asset type at or above `floor`, closest first: (cosine, first,
    second)."""
    pairs = [
        (float(vectors[first] @ vectors[second]), threats[first], threats[second])
        for first, second in itertools.combinations(range(len(threats)), 2)
        if (threats[first].type_id, threats[first].asset_type)
        == (threats[second].type_id, threats[second].asset_type)
    ]
    return sorted((pair for pair in pairs if pair[0] >= floor), key=lambda pair: -pair[0])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cosine", type=float, default=0.75, help="the lowest similarity listed (0-1)")
    args = parser.parse_args(argv)
    threats = get_library_search().snapshot(wait=True).library.threat_library.threats
    vectors = get_embedding_model().embed_texts_to_compare(
        [threat_name_without_code(t.name) for t in threats]
    )
    pairs = find_look_alikes(threats, vectors, args.cosine)
    joined = ThreatFinding.LIBRARY_DUPLICATE_COSINE
    print(f"{len(threats)} library threats; {len(pairs)} pairs of one type and asset type at {args.cosine}+")
    print(f"(a run joins a pair at {joined} or more)")
    for cosine, first, second in pairs:
        both = f"#{first.catalogue_id} {first.name}  <->  #{second.catalogue_id} {second.name}"
        print(f"  {cosine:.2f}  {first.type_name} ({first.asset_type}): {both}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
