"""AI model gateways via litellm, the only door to AI models: chat, embeddings and rerank."""

import logging
import os

# Before litellm's first import: its bundled model table (no GitHub fetch), no ./.env copy into the environment (G263).
os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")
os.environ.setdefault("LITELLM_MODE", "PRODUCTION")

import litellm  # noqa: E402

litellm.DEFAULT_MAX_RETRIES = 0  # type: ignore[misc]  # every retry is ours; litellm reads 0 as its default (2)
litellm.suppress_debug_info = True  # its coloured help lines would break the JSON log lines
for _library_logger in ("LiteLLM", "LiteLLM Router", "LiteLLM Proxy", "openai"):  # whole requests, key header (G221)
    logging.getLogger(_library_logger).setLevel(logging.WARNING)

from app.ai import chat, embeddings, rerank  # noqa: E402
from app.ai.chat import ChatModel, TruncatedAiAnswer, UnreadableAiAnswer  # noqa: E402
from app.ai.embeddings import EmbeddingModel  # noqa: E402
from app.ai.rerank import RerankModel  # noqa: E402

__all__ = ["ChatModel", "EmbeddingModel", "RerankModel", "TruncatedAiAnswer", "UnreadableAiAnswer"]


def build_ai_gateways() -> None:
    """Every AI gateway, each module's chat model included: one whose model has no profile stops start-up."""
    chat.get_scenario_chat_model()
    chat.get_remediation_chat_model()
    chat.get_service_mapper_chat_model()
    embeddings.get_embedding_model()
    rerank.get_rerank_model()
