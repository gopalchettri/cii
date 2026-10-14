"""The on/off switch of external intelligence: the env master switch and the admin's run-time switch."""

from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class SwitchState:
    env_enabled: bool  # EXTERNAL_INTELLIGENCE_ENABLED: the master switch
    runtime_enabled: bool = True  # the admin's switch; on until an admin turns it off
    changed_at: datetime | None = None
    changed_by: str | None = None

    @property
    def effective(self) -> bool:
        """On only when both are on: the run-time switch can turn intelligence off, never on past the env."""
        return self.env_enabled and self.runtime_enabled

    def as_doc(self) -> dict[str, Any]:
        return {
            "env_enabled": self.env_enabled,
            "runtime_enabled": self.runtime_enabled,
            "effective": self.effective,
            "changed_at": self.changed_at,
            "changed_by": self.changed_by,
        }
