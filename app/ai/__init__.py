"""AI model gateways via litellm — the only door to AI models. One module per kind of model:
chat (JSON answers), embeddings (cached vectors) and rerank (relevance scores); `common` holds what they
share.
Retries, fallback, timeouts, metrics and call records live here and nowhere else."""

import logging
import os

# Before litellm is first imported (here, the only door to it): its model table comes from the installed
# package. Otherwise every process start fetches it from GitHub: an outside call that waits up to 15 s when
# egress is closed, and a table that changes which options litellm sends without any release.
os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")

import litellm  # noqa: E402

# Every retry is ours (common.call_with_retries): litellm reads a 0 we send as "use the default" (2) and would
# add its retries on top of ours (12 requests per embedding batch), and its own retry helper needs tenacity
# (not installed).
litellm.DEFAULT_MAX_RETRIES = 0  # type: ignore[misc]  # typed Final, but read from the module at each call
litellm.suppress_debug_info = True  # its coloured help lines would break the JSON log lines Loki reads
# Its own tracing is not ours (G221): with CII_LOG_LEVEL=DEBUG it logged every request in full and a failed
# price lookup per call ("This model isn't mapped yet": our models are not on its price list, and no price
# is used). Our ai.call lines record every call; its warnings and errors still show. The OpenAI client
# under it logs each request's headers at DEBUG, the AI key among them (UAT, 2026-10-15): capped the same way.
for _library_logger in ("LiteLLM", "LiteLLM Router", "LiteLLM Proxy", "openai"):
    logging.getLogger(_library_logger).setLevel(logging.WARNING)

from app.ai.chat import (  # noqa: E402
    CORRECTION_MESSAGE_MAX_CHARS,
    ChatModel,
    TruncatedAiAnswer,
    UnreadableAiAnswer,
    get_chat_model,
)
from app.ai.embeddings import (  # noqa: E402
    EmbeddingModel,
    EmbeddingNotFinite,
    EmbeddingSizeMismatch,
    get_embedding_model,
)
from app.ai.local_turns import background_reranks, reranks_in_background  # noqa: E402
from app.ai.rerank import RerankModel, get_rerank_model  # noqa: E402

__all__ = [
    "background_reranks",
    "reranks_in_background",
    "CORRECTION_MESSAGE_MAX_CHARS",
    "ChatModel",
    "EmbeddingModel",
    "EmbeddingNotFinite",
    "EmbeddingSizeMismatch",
    "RerankModel",
    "TruncatedAiAnswer",
    "UnreadableAiAnswer",
    "get_chat_model",
    "get_embedding_model",
    "get_rerank_model",
]
