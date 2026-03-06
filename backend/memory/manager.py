"""
PHANTOM AI v3 — Memory Manager
────────────────────────────────
The MemoryManager is the single façade that all agents and API endpoints
talk to. It owns all four stores, initialises them at startup, and
exposes a clean unified API that hides which backend actually handles each call.

Think of it like a "memory router" — agents don't need to know whether
semantic search is backed by Chroma or a simple SQLite full-text index;
they just call manager.find_similar() and get results.

Graceful degradation is built-in: if Redis is down, state still works
(in-memory). If Chroma is missing, semantic search is skipped. If
Neo4j is absent, the graph tab just shows placeholder data. The core
scan + finding pipeline always works regardless of which optional
services are running.
"""

import logging
import os
from typing import Any, Dict, List, Optional

from .redis_store    import RedisStore
from .chroma_store   import ChromaStore
from .neo4j_store    import Neo4jStore
from .postgres_store import PostgresStore

log = logging.getLogger(__name__)


class MemoryManager:

    def __init__(
        self,
        redis_url:   str = "redis://localhost:6379/0",
        chroma_dir:  str = "./chroma_db",
        neo4j_uri:   str = "bolt://localhost:7687",
        neo4j_user:  str = "neo4j",
        neo4j_pass:  str = "phantom123",
        postgres_dsn: str = "postgresql://phantom:phantom123@localhost:5432/phantom",
    ):
        self.redis    = RedisStore(url=redis_url)
        self.chroma   = ChromaStore(persist_dir=chroma_dir)
        self.neo4j    = Neo4jStore(uri=neo4j_uri, user=neo4j_user, password=neo4j_pass)
        self.postgres = PostgresStore(dsn=postgres_dsn)

        # Track which stores are actually available
        self._available: Dict[str, bool] = {
            "redis": False, "chroma": False, "neo4j": False, "postgres": False
        }

    async def initialise(self):
        """Connect to all four stores concurrently. Log what worked."""
        import asyncio
        results = await asyncio.gather(
            self.redis.connect(),
            self.chroma.connect(),
            self.neo4j.connect(),
            self.postgres.connect(),
            return_exceptions=True,
        )
        self._available["redis"]    = results[0] is True
        self._available["chroma"]   = results[1] is True
        self._available["neo4j"]    = results[2] is True
        self._available["postgres"] = results[3] is True

        available = [k for k, v in self._available.items() if v]
        missing   = [k for k, v in self._available.items() if not v]
        log.info(f"Memory layer ready — available: {available}, unavailable: {missing}")
        return self._available

    async def shutdown(self):
        """Cleanly close all store connections."""
        await self.redis.disconnect()
        await self.neo4j.disconnect()
        await self.postgres.disconnect()

    # ── Status ────────────────────────────────────────────────────────

    def status(self) -> Dict[str, Any]:
        """Return the health/availability of all four data stores."""
        return {
            "redis":    {"available": self._available["redis"],    "type": "Short-term state cache"},
            "chroma":   {"available": self._available["chroma"],   "type": "Vector semantic memory",
                         "count": self.chroma.count()},
            "neo4j":    {"available": self._available["neo4j"],    "type": "Attack graph (privilege paths)"},
            "postgres": {"available": self._available["postgres"], "type": "Findings + sessions + compliance"},
        }

    # ── Unified finding persist ────────────────────────────────────────
    # This is the most important method — every agent calls it once
    # per extracted finding. It fans the write out to all stores.

    async def persist_finding(self, finding: Dict, target_host: str = ""):
        """
        Save a finding to all available stores simultaneously.
        Postgres = relational source of truth
        Chroma   = semantic searchability
        Neo4j    = attack graph node + edge
        """
        # 1. Postgres — primary persistent store
        if self._available["postgres"]:
            await self.postgres.save_finding(finding)

        # 2. Chroma — embed description for semantic recall
        if self._available["chroma"]:
            # Attach the target so we can filter by host in future queries
            finding_with_target = {**finding, "target": target_host}
            self.chroma.add_finding(finding_with_target)

        # 3. Neo4j — add as a graph node
        if self._available["neo4j"] and target_host:
            await self.neo4j.add_finding(finding, target_host)

    async def persist_findings_batch(self, findings: List[Dict], target_host: str = ""):
        """Bulk persist — more efficient for large tool outputs."""
        import asyncio
        tasks = [self.persist_finding(f, target_host) for f in findings]
        await asyncio.gather(*tasks, return_exceptions=True)

    # ── Semantic recall ────────────────────────────────────────────────

    def find_similar(self, query: str, k: int = 5) -> List[Dict]:
        """
        Find semantically similar past findings using Chroma vector search.
        Falls back to empty list if Chroma is unavailable.
        """
        if not self._available["chroma"]:
            return []
        return self.chroma.find_similar(query, k=k)

    # ── Agent state (delegated to Redis) ──────────────────────────────

    async def set_agent_state(self, session_id: str, agent_id: str, state: Dict):
        await self.redis.set_agent_state(session_id, agent_id, state)

    async def get_all_agent_states(self, session_id: str) -> Dict[str, Dict]:
        return await self.redis.get_all_agent_states(session_id)

    # ── Attack graph (delegated to Neo4j) ─────────────────────────────

    async def get_attack_graph(self, host: str) -> Dict[str, List]:
        if not self._available["neo4j"]:
            return {"nodes": [], "edges": []}
        return await self.neo4j.export_graph(host)

    async def get_attack_paths(self, host: str) -> List[Dict]:
        if not self._available["neo4j"]:
            return []
        return await self.neo4j.get_attack_paths(host)

    # ── PostgreSQL analytics ───────────────────────────────────────────

    async def get_stats(self) -> Dict[str, Any]:
        if not self._available["postgres"]:
            return {}
        return await self.postgres.get_stats()

    async def get_findings_with_compliance(self, session_id: str) -> List[Dict]:
        if not self._available["postgres"]:
            return []
        return await self.postgres.get_findings_with_compliance(session_id)
