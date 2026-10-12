"""Search results."""

from dataclasses import dataclass


@dataclass(frozen=True)
class SearchHit:
    position: int  # row in the searched list
    score: float  # fused rank score; 1.0 for an exact name match
