"""The service-layer pieces the worker's intelligence code calls, as the worker sees them. The worker layer
imports no service (BLUEPRINT section 5), so the composition
(services/external_intelligence/worker_runtime.py, loaded with the task modules) installs them in
IntelAccess. Providers, not objects: nothing is built, and no store is touched, until the first call."""

from collections.abc import Callable
from datetime import datetime
from typing import Any, Protocol

from app.core.constants import IntelSource


class SwitchPort(Protocol):
    def is_enabled(self) -> bool: ...


class RefresherPort(Protocol):
    def refresh_due_sources(self, now: datetime) -> Any: ...

    def refresh_one_source(self, source: IntelSource, now: datetime) -> Any: ...


class IntelRuntime:
    def __init__(self, switch: Callable[[], SwitchPort], refresher: Callable[[], RefresherPort]) -> None:
        self.switch, self.refresher = switch, refresher
