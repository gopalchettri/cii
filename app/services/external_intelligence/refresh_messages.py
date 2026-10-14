"""The words a failed source refresh is recorded in (the sources' own failures use IntelMessage)."""

from enum import StrEnum


class RefreshMessage(StrEnum):
    UNEXPECTED = "The refresh stopped with an unexpected {error}."
    REVOKED = "{source} was revoked during the refresh: nothing was stored."
    CUT_SHORT = (
        "{source} delivered only {kept} of its {current} current records: the feed looks cut short, so "
        "nothing was stored or retired and the last good data stays."
    )
