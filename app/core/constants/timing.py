"""How long things wait and are remembered, and how each pod's clock is kept to MongoDB's."""

from typing import Final


class Timeouts:
    """Every network wait is bounded, so a hung store never holds a worker thread for ever."""

    MONGO_MS: Final = 5_000  # find a server / open a connection
    MONGO_SOCKET_MS: Final = 30_000  # one network wait inside an operation
    MONGO_MAJORITY_WRITE_MS: Final = 10_000  # a write waits this long for a majority to confirm it
    SQL_CONNECT_SECONDS: Final = 5  # short, so an outage answers 503 quickly
    SQL_QUERY_SECONDS: Final = 30  # one procedure call
    REDIS_SECONDS: Final = 5  # connect and each command
    REDIS_HEALTH_CHECK_SECONDS: Final = 30  # a pooled connection idle this long is PINGed before use
    READY_CHECK_SECONDS: Final = 5  # /ready waits at most this for its checks; a slower one counts as down
    READY_CHECK_REUSE_SECONDS: Final = 2  # a finished check is reused this long (below the probe period)
    RECORD_WRITE_SECONDS: Final = 5  # an audit or AI-call record write never holds an answer longer


class Cache:
    SERVICE_MAPPER_CATALOG_SECONDS: Final = 60
    API_KEY_TTL_SECONDS: Final = 60  # an API key is checked again after this
    LIBRARY_STAMP_EVERY_SECONDS: Final = 60  # the library stamp is read again after this
    LIBRARY_INDEXES_EVERY_SECONDS: Final = 1_800  # the maintenance worker embeds new library rows this often
    QUERY_VECTOR_DAYS: Final = 14  # a search query's vector expires after this
    RETIRED_VECTOR_DAYS: Final = 365  # a library vector no row uses is kept this long, then deleted


class Clock:
    CHECK_EVERY_SECONDS: Final = 60  # each process asks MongoDB its time this often (app/core/clock.py)
    WARN_OVER_SECONDS: Final = 5  # a pod clock further off than this is logged (and alerted: ClockSkew)
