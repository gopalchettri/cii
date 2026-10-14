"""What cleaning one piece of untrusted source text gave: the clean text, or the verdict that it reads as
instructions to an AI system."""

from dataclasses import dataclass


@dataclass(frozen=True)
class SanitisedText:
    """`unsafe` text is returned EMPTY: the payload is never carried on, only a short `reason` code (which
    check fired), so a log line or a stored rejection can say why without repeating the attack."""

    text: str
    unsafe: bool = False
    reason: str | None = None
