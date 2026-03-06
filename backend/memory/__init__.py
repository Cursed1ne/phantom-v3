"""PHANTOM AI v3 — Memory layer package.

Four complementary stores, each optimised for a different access pattern:
  Redis      → microsecond key/value, live scan state, rate limiting
  Chroma     → vector embeddings for semantic "what have I seen before?"
  Neo4j      → graph database for attack paths and privilege escalation
  PostgreSQL → relational store for findings, sessions, compliance reports
  Manager    → unified facade that agents call — picks the right store
"""
from .redis_store    import RedisStore
from .chroma_store   import ChromaStore
from .neo4j_store    import Neo4jStore
from .postgres_store import PostgresStore
from .manager        import MemoryManager

__all__ = [
    "RedisStore", "ChromaStore", "Neo4jStore",
    "PostgresStore", "MemoryManager",
]
