"""AI calls: tasks, outcomes, temperatures, limits and embedding corpora."""

from enum import StrEnum
from typing import Final


class AiOutcome(StrEnum):
    """tsg_ai_calls_total{outcome}: AiErrorRateHigh fires on the share that is not OK."""

    OK = "ok"
    UNAVAILABLE = "unavailable"  # the provider busy or unreachable, after the retries
    UNREADABLE = "unreadable"  # an answer that cannot be used: short, of the wrong size, not the JSON asked
    ERROR = "error"  # anything else: a refused key, a bad request, a local model that would not load


class AiTask(StrEnum):
    """Why an AI model is called (metrics label and tsg_ai_calls field)."""

    RELEVANCE_GATE = "relevance_gate"
    GAP_FILL = "gap_fill"
    SAME_ATTACK = "same_attack"
    ATTACKER_FIT = "attacker_fit"
    BEST_THREAT = "best_threat"  # which threat each scenario is built on (G209)
    SAME_SCENARIO = "same_scenario"  # which scenarios are one attack through different systems (G213)
    WRITE_SCENARIO = "write_scenario"
    REWRITE_SCENARIO = "rewrite_scenario"  # the one rewrite, in the same conversation, listing every problem
    PLAN_CHECK = "plan_check"  # does the written scenario carry out its plan (judged by meaning)
    REMEDIATION_PLAN = "remediation_plan"  # one version of a scenario's remediation plan (Step 16)
    EMBED = "embed"
    RERANK = "rerank"


#: Temperature per chat task (BLUEPRINT R-2, as v1): 0.0 where the same input must give the same answer;
#: None = not sent (the provider's default), so a regenerated scenario really reads differently.
CHAT_TEMPERATURES: Final[dict[AiTask, float | None]] = {
    AiTask.RELEVANCE_GATE: 0.0,
    AiTask.GAP_FILL: 0.0,
    AiTask.SAME_ATTACK: 0.0,
    AiTask.ATTACKER_FIT: 0.0,
    AiTask.BEST_THREAT: 0.0,
    AiTask.SAME_SCENARIO: 0.0,
    AiTask.PLAN_CHECK: 0.0,
    AiTask.REMEDIATION_PLAN: 0.0,
    AiTask.WRITE_SCENARIO: None,
    AiTask.REWRITE_SCENARIO: None,
}


class AiLimits:
    """Same for every model. Per-model values (tokens, timeout, vector size…) live in app/ai/profiles.py."""

    RETRIES: Final = 3  # a busy or unreachable provider is retried this many times, with back-off
    RETRY_FIRST_WAIT_SECONDS: Final = 0.5  # then 1 s, 2 s: doubling, as the OpenAI client itself waits
    CALL_RECORD_DAYS: Final = 14  # tsg_ai_calls retention
    # The AI call limiter (app/ai/slots.py): one Redis sorted set shared by every pod.
    SLOTS_KEY: Final = "tsg:ai_slots"
    API_SLOT_WAIT_SECONDS: Final = 30  # the API answers a caller: it waits briefly for a free slot
    WORKER_SLOT_WAIT_SECONDS: Final = 300  # a worker's job would otherwise only be retried after a back-off
    SLOT_GRACE_SECONDS: Final = 30  # a slot outlives its call's longest run by this much
    SLOT_FIRST_PAUSE_SECONDS: Final = 0.05  # polls for a free slot start this often, doubling ...
    SLOT_MAX_PAUSE_SECONDS: Final = 1.0  # ... up to this
    # The one corrective re-ask (§9): the previous reply's problems, each cut short, then the instruction.
    REASK_MAX_PROBLEMS: Final = 20
    REASK_PROBLEM_CHARS: Final = 200
    REASK_MESSAGE: Final = (
        "Your previous reply was rejected:\n{problems}\n"
        "Return the corrected JSON object only, in exactly the requested format."
    )


class EmbeddingCorpus(StrEnum):
    """What a library vector was made from (tsg_embeddings.corpus): each kind is embedded, searched and
    retired on its own. The external technique and threat-intel corpora come with Step 15, in
    tsg_external_embeddings."""

    CONTROL = "control"
    THREAT = "threat"
    THREAT_ACTOR = "threat_actor"
    THREAT_TYPE = "threat_type"


#: Each corpus by the name the embeddings API (#19) reports it under.
LIBRARY_OF_CORPUS: Final = {
    EmbeddingCorpus.THREAT: "threats",
    EmbeddingCorpus.THREAT_TYPE: "threat_types",
    EmbeddingCorpus.THREAT_ACTOR: "actors",
    EmbeddingCorpus.CONTROL: "controls",
}


#: The SQL table each corpus's rows come from (tsg_embeddings.sources[].table).
EMBEDDING_SOURCE_TABLE: Final[dict[EmbeddingCorpus, str]] = {
    EmbeddingCorpus.CONTROL: "Control_Library",
    EmbeddingCorpus.THREAT: "Threat_Catalogue",
    EmbeddingCorpus.THREAT_ACTOR: "Threat_Actor",
    EmbeddingCorpus.THREAT_TYPE: "Threat_Type",
}
