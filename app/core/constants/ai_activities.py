"""What AI usage reports call each API, part and activity, with a one-line description: added when a report is
built, never stored on a usage row, so the wording can change with no data to migrate."""

from typing import Final

from app.core.constants.ai_usage import AiApi, AiBucket
from app.core.constants.common import AiTask
from app.core.constants.job_modules import Module

#: (module, api) -> (label, description).
API_INFO: Final[dict[tuple[str, str], tuple[str, str]]] = {
    (Module.THREAT_SCENARIOS, AiApi.CREATE_SCENARIO): (
        "Create scenario",
        "Starts a run: finds threats, writes the first set, picks controls",
    ),
    (Module.THREAT_SCENARIOS, AiApi.NEXT_SET): ("Next set", "Writes the next set of scenarios for the run"),
    (Module.THREAT_SCENARIOS, AiApi.REGENERATE): ("Regenerate scenarios", "Rewrites the chosen scenarios"),
    (Module.REMEDIATION, AiApi.CREATE_PLAN): (
        "Create remediation plan",
        "Writes a treatment plan for one scenario",
    ),
    (Module.REMEDIATION, AiApi.REGENERATE): ("Regenerate plan", "Writes a new version of the plan"),
    (Module.SERVICE_MAPPER, AiApi.CREATE_MAPPING): (
        "Map services",
        "Finds upstream and downstream services for a service",
    ),
    (Module.SERVICE_MAPPER, AiApi.REGENERATE): (
        "Regenerate mapping",
        "Runs the mapping again to add new services",
    ),
}

#: part -> (label, description).
BUCKET_INFO: Final[dict[str, tuple[str, str]]] = {
    AiBucket.THREATS: ("Finding threats", "Deciding which threats apply to the asset"),
    AiBucket.SCENARIO: ("Writing scenarios", "Writing and checking each attack scenario"),
    AiBucket.CONTROLS: ("Picking controls", "Finding and ranking the controls for each scenario"),
    AiBucket.REMEDIATION: ("Writing the plan", "Writing the treatment plan for a scenario's controls"),
    AiBucket.SERVICE_MAPPER: ("Mapping services", "Finding a service's upstream and downstream services"),
    AiBucket.SHARED: ("Shared work", "Library and evidence indexing that no single request asked for"),
}

#: (part, task) -> (activity, description): embed and rerank do a different job in each part.
ACTIVITY_INFO: Final[dict[tuple[str, str], tuple[str, str]]] = {
    (AiBucket.THREATS, AiTask.RELEVANCE_GATE): (
        "Relevance check",
        "AI picks which library threats apply to the asset (one call per batch of up to 10 threats)",
    ),
    (AiBucket.THREATS, AiTask.GAP_FILL): (
        "New threat suggestion",
        "AI suggests a threat for a category where no library threat applies",
    ),
    (AiBucket.THREATS, AiTask.EMBED): (
        "Threat search",
        "Turns the asset text into vectors to search the library",
    ),
    (AiBucket.THREATS, AiTask.RERANK): (
        "Threat match ranking",
        "Ranks library threats against a suggested one",
    ),
    (AiBucket.SCENARIO, AiTask.THREAT_ACTIONS): (
        "Threat action split",
        "AI lists the attacker actions a threat's name describes",
    ),
    (AiBucket.SCENARIO, AiTask.WRITE_SCENARIO): (
        "Write scenario",
        "AI writes one attack scenario for an attack path",
    ),
    (AiBucket.SCENARIO, AiTask.REPAIR_SCENARIO): (
        "Repair scenario",
        "AI rewrites a draft that missed planned actions",
    ),
    (AiBucket.SCENARIO, AiTask.PLAN_CHECK): (
        "Plan check",
        "AI checks the written scenario carries out its plan",
    ),
    (AiBucket.SCENARIO, AiTask.EMBED): (
        "Evidence search",
        "Searches threat intelligence for a scenario's evidence",
    ),
    (AiBucket.SCENARIO, AiTask.RERANK): ("Evidence ranking", "Ranks the evidence found for a scenario"),
    (AiBucket.CONTROLS, AiTask.EMBED): (
        "Control search",
        "Turns the scenario into a vector to search the controls",
    ),
    (AiBucket.CONTROLS, AiTask.RERANK): ("Control ranking", "Ranks candidate controls by how well they fit"),
    (AiBucket.REMEDIATION, AiTask.REMEDIATION_PLAN): (
        "Write remediation plan",
        "AI writes the treatment plan for the scenario's controls",
    ),
    (AiBucket.SERVICE_MAPPER, AiTask.SERVICE_MAPPER): (
        "Map services",
        "AI lists upstream and downstream services for a service",
    ),
    (AiBucket.SERVICE_MAPPER, AiTask.EMBED): (
        "Service search",
        "Searches the service catalog for candidates",
    ),
    (AiBucket.SHARED, AiTask.EMBED): ("Library indexing", "Embeds new or changed library and evidence rows"),
    (AiBucket.SHARED, AiTask.RERANK): ("Shared ranking", "A ranking no single request asked for"),
}


def api_info(module: str | None, api: str | None) -> tuple[str, str]:
    """(label, description) of an API; its raw name when the catalogue has no entry."""
    return API_INFO.get((module or "", api or ""), (api or "", ""))


def activity_info(bucket: str, task: str) -> tuple[str, str]:
    """(activity, description) of a task in a part; the task's name when the catalogue has no entry."""
    return ACTIVITY_INFO.get((bucket, task), (task, ""))
