"""The side effects a service is given through its constructor, so services never import the worker."""

from collections.abc import Callable

from app.core.constants import TaskName

#: Queue a leased job: (task, record id, epoch).
SendJob = Callable[[TaskName, str, int], None]
#: Queue an admin job: (task, job id); False when the broker is unreachable.
SendAdminJob = Callable[[TaskName, str], bool]
#: Tell live-update streams that a record changed: (record id).
Publish = Callable[[str], None]
