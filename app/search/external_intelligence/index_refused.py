"""A build that must not replace the index in use."""

from app.core.constants import IntelMessage


class EvidenceIndexRefused(Exception):
    """No current record, or rows and vectors out of step."""

    def __init__(self, message: IntelMessage, **facts: object) -> None:
        super().__init__(message.format(**facts))
