"""Reviewing, cancelling and deleting an organisation's own work (G214, owner 2026-10-12: "if anything which
required deletion or canceling, I can do it"; "list of in progress or in queue jobs such that I can review
them")."""

from enum import StrEnum
from typing import Final


class JobKind(StrEnum):
    """What a job in the list does."""

    THREATS = "threats"  # finding a run's threats and freezing its plan
    SCENARIOS = "scenarios"  # writing a run's scenarios (a set, or a regenerate)
    CONTROLS = "controls"  # matching controls to a run's written scenarios
    REMEDIATION = "remediation"  # writing one version of a remediation plan


class JobControl:
    LIST_MAX: Final = 200  # the jobs list's length: an organisation's own work in progress, oldest first


class JobControlMessage(StrEnum):
    NOTHING_TO_CANCEL = "Session '{session_id}' has no job queued or running and no controls being matched."
    PLAN_NOTHING_TO_CANCEL = "Remediation plan '{remediation_id}' is not being written."
    BEING_DELETED = (
        "Session '{session_id}' is being deleted: nothing more can start on it (if a delete was cut short, "
        "delete it again to finish)."
    )
    CANCEL_FIRST = (
        "Session '{session_id}' still has work queued or running (a job, controls or a remediation plan): "
        "cancel it first, then delete."
    )
