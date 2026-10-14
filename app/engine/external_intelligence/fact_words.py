"""The words and limits of the plain facts that the shared EvidenceFact enum does not hold."""

from enum import StrEnum


class PlainFactWords(StrEnum):
    TACTICS = "It is used for these attacker goals: {tactics}."
