"""The curator's queue (BLUEPRINT M05 L5, #23 and #24): library threats a person promoted (#27) or a
hand-written scenario proposed (#11), inactive until a curator approves them (scripts/sql/
tsg_ListPendingThreats.sql and tsg_DecidePendingThreats.sql)."""

import json
from datetime import UTC
from typing import Any

from app.core.constants import StoredProcedure
from app.core.database import StoredProcedureClient

Row = dict[str, Any]


class PendingThreats:
    def __init__(self, procedures: StoredProcedureClient) -> None:
        self._procedures = procedures

    def list_page(self, offset: int, limit: int) -> tuple[list[Row], int]:
        """One page of pending threats, oldest first, and how many wait in all: one procedure call."""
        page, total = self._procedures.execute_procedure(
            StoredProcedure.LIST_PENDING_THREATS, Offset=offset, Limit=limit
        )
        return [_listed(row) for row in page], total[0]["total"]

    def decide(self, approve: list[int], reject: list[int], decided_by: str) -> list[Row]:
        """`{catalogue_id, outcome}` per id, all decided in one transaction (a pending type goes live with its
        first approved threat)."""
        (outcomes,) = self._procedures.execute_procedure(
            StoredProcedure.DECIDE_PENDING_THREATS,
            ApproveIDs=json.dumps(approve),
            RejectIDs=json.dumps(reject),
            DecidedBy=decided_by,
        )
        return outcomes


def _listed(row: Row) -> Row:
    """A pending row as the API names it: its type as `type`, its categories as a list of names."""
    return {
        "catalogue_id": row["catalogue_id"],
        "threat": row["threat"],
        "type": row["threat_type"],
        "type_pending": bool(row["type_pending"]),
        "categories": [category["name"] for category in json.loads(row["categories"] or "[]")],
        "source": row["source"],
        "created_by": row["created_by"],
        # DATETIME2 holds UTC (SYSUTCDATETIME) without saying so: said here, as every API time says it.
        "created_at": row["created_at"].replace(tzinfo=UTC) if row["created_at"] else None,
    }
