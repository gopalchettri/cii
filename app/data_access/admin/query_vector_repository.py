"""tsg_query_vectors: search queries' vectors, each expiring at its own expires_at."""

from pymongo.collection import Collection as MongoCollection

from app.core.constants import Collection
from app.data_access.base import VectorRepository


class QueryVectorRepository(VectorRepository):
    """tsg_query_vectors: a query's vector by its key."""

    def __init__(self, collection: str | MongoCollection = Collection.QUERY_VECTORS) -> None:
        """tsg_query_vectors with the vector expiry."""
        super().__init__(collection, schema_version=1)
