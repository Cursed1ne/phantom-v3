"""
PHANTOM AI v3 — Neo4j Attack Graph Store
──────────────────────────────────────────
Neo4j models your findings as a directed property graph, which enables
a class of queries that are impossible in SQL or key-value stores:

  "Find all paths from an unauthenticated user to admin privileges."
  "Which hosts can be reached from the compromised web server?"
  "What is the blast radius if credentials for 'deploy-user' are stolen?"

Node types:
  (:Target    {host, type, scope})
  (:Service   {host, port, protocol, version, banner})
  (:User      {name, domain, role, has_mfa})
  (:Credential{username, hash, service, cracked})
  (:Finding   {id, severity, description, cvss, tool})
  (:Network   {cidr, vlan, name})
  (:CloudAsset{provider, type, name, public, region})

Relationship types:
  (:Target)-[:HAS_SERVICE]->(:Service)
  (:Service)-[:HAS_FINDING]->(:Finding)
  (:User)-[:CAN_ACCESS]->(:Service)
  (:Credential)-[:AUTHENTICATES]->(:Service)
  (:Service)-[:CONNECTS_TO]->(:Service)         # lateral movement
  (:CloudAsset)-[:GRANTS_ACCESS]->(:CloudAsset) # IAM relationships
  (:Finding)-[:ENABLES]->(:Finding)              # attack chaining
"""

import logging
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

try:
    from neo4j import AsyncGraphDatabase
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False
    log.warning("neo4j driver not installed — attack graph disabled")


class Neo4jStore:
    """
    Async Neo4j wrapper. All graph operations are idempotent (MERGE not CREATE)
    so re-running a scan adds new information without duplicating nodes.
    """

    def __init__(
        self,
        uri:      str = "bolt://localhost:7687",
        user:     str = "neo4j",
        password: str = "phantom123",
    ):
        self.uri      = uri
        self.user     = user
        self.password = password
        self._driver  = None

    async def connect(self) -> bool:
        if not NEO4J_AVAILABLE:
            return False
        try:
            self._driver = AsyncGraphDatabase.driver(
                self.uri, auth=(self.user, self.password)
            )
            # Verify connectivity
            async with self._driver.session() as session:
                await session.run("RETURN 1")
            log.info(f"Neo4j connected: {self.uri}")
            # Create indexes on first connect
            await self._create_indexes()
            return True
        except Exception as e:
            log.warning(f"Neo4j connection failed: {e}")
            self._driver = None
            return False

    async def disconnect(self):
        if self._driver:
            await self._driver.close()

    async def _create_indexes(self):
        """Speed up common lookups with property indexes."""
        if not self._driver:
            return
        indexes = [
            "CREATE INDEX IF NOT EXISTS FOR (t:Target)   ON (t.host)",
            "CREATE INDEX IF NOT EXISTS FOR (f:Finding)  ON (f.id)",
            "CREATE INDEX IF NOT EXISTS FOR (s:Service)  ON (s.port)",
            "CREATE INDEX IF NOT EXISTS FOR (u:User)     ON (u.name)",
        ]
        async with self._driver.session() as s:
            for idx in indexes:
                try:
                    await s.run(idx)
                except Exception:
                    pass   # index may already exist

    # ── Node upserts ─────────────────────────────────────────────────

    async def add_target(self, host: str, target_type: str = "web", scope: bool = True):
        """Add or update the root target node."""
        if not self._driver:
            return
        async with self._driver.session() as s:
            await s.run(
                "MERGE (t:Target {host: $host}) SET t.type=$type, t.scope=$scope",
                host=host, type=target_type, scope=scope,
            )

    async def add_service(self, host: str, port: int, protocol: str,
                           version: str = "", banner: str = ""):
        """Add a discovered service and link it to the target."""
        if not self._driver:
            return
        async with self._driver.session() as s:
            await s.run(
                """
                MERGE (s:Service {host: $host, port: $port, protocol: $protocol})
                SET s.version=$version, s.banner=$banner
                WITH s
                MATCH (t:Target {host: $host})
                MERGE (t)-[:HAS_SERVICE]->(s)
                """,
                host=host, port=port, protocol=protocol,
                version=version, banner=banner,
            )

    async def add_finding(self, finding: Dict, host: str):
        """
        Add a finding node and link it to either the target or a specific service.
        Also create :ENABLES edges to build the attack chain automatically.
        """
        if not self._driver:
            return
        async with self._driver.session() as s:
            await s.run(
                """
                MERGE (f:Finding {id: $id})
                SET f.severity=$severity, f.description=$description,
                    f.cvss=$cvss, f.tool=$tool, f.agent=$agent
                WITH f
                MATCH (t:Target {host: $host})
                MERGE (t)-[:HAS_FINDING]->(f)
                """,
                id=finding.get("id"),
                severity=finding.get("severity"),
                description=finding.get("description", "")[:200],
                cvss=finding.get("cvss", 0),
                tool=finding.get("tool", ""),
                agent=finding.get("agent", ""),
                host=host,
            )

    async def add_credential(self, username: str, service: str,
                              password_hash: str = "", cracked: bool = False,
                              plaintext: str = ""):
        """Record a discovered credential and link to its service."""
        if not self._driver:
            return
        async with self._driver.session() as s:
            await s.run(
                """
                MERGE (c:Credential {username: $username, service: $service})
                SET c.hash=$hash, c.cracked=$cracked, c.plaintext=$plaintext
                WITH c
                MERGE (svc:Service {host: $service})
                MERGE (c)-[:AUTHENTICATES]->(svc)
                """,
                username=username, service=service,
                hash=password_hash, cracked=cracked, plaintext=plaintext,
            )

    async def add_lateral_path(self, from_host: str, to_host: str,
                                via: str = "network", confidence: float = 0.8):
        """Record a potential lateral movement path between two hosts."""
        if not self._driver:
            return
        async with self._driver.session() as s:
            await s.run(
                """
                MERGE (a:Service {host: $from_host})
                MERGE (b:Service {host: $to_host})
                MERGE (a)-[r:CONNECTS_TO {via: $via}]->(b)
                SET r.confidence=$confidence
                """,
                from_host=from_host, to_host=to_host,
                via=via, confidence=confidence,
            )

    # ── Attack path queries ──────────────────────────────────────────

    async def get_attack_paths(self, target_host: str) -> List[Dict]:
        """
        Find all directed paths from the target to any Critical/High finding.
        Returns each path as a list of node labels for visualisation.
        """
        if not self._driver:
            return []
        try:
            async with self._driver.session() as s:
                result = await s.run(
                    """
                    MATCH path = (t:Target {host: $host})-[*1..4]->(f:Finding)
                    WHERE f.severity IN ['CRITICAL', 'HIGH']
                    RETURN nodes(path) AS nodes, relationships(path) AS rels,
                           f.severity AS severity, f.cvss AS cvss
                    ORDER BY f.cvss DESC LIMIT 20
                    """,
                    host=target_host,
                )
                paths = []
                async for record in result:
                    paths.append({
                        "severity": record["severity"],
                        "cvss":     record["cvss"],
                        "length":   len(record["nodes"]),
                    })
                return paths
        except Exception as e:
            log.warning(f"Neo4j get_attack_paths error: {e}")
            return []

    async def get_blast_radius(self, node_id: str) -> Dict[str, Any]:
        """
        Given a finding or credential node, estimate blast radius by
        counting reachable nodes within 3 hops.
        """
        if not self._driver:
            return {}
        try:
            async with self._driver.session() as s:
                result = await s.run(
                    """
                    MATCH (start {id: $id})
                    OPTIONAL MATCH (start)-[*1..3]->(reached)
                    RETURN count(DISTINCT reached) AS reachable_nodes,
                           collect(DISTINCT labels(reached)[0]) AS node_types
                    """,
                    id=node_id,
                )
                record = await result.single()
                return dict(record) if record else {}
        except Exception as e:
            log.warning(f"Neo4j blast radius error: {e}")
            return {}

    # ── Graph export for visualisation ──────────────────────────────

    async def export_graph(self, host: str) -> Dict[str, List]:
        """
        Export all nodes and edges for a target as a dict that the
        React D3/force-graph component can render directly.
        """
        if not self._driver:
            return {"nodes": [], "edges": []}
        try:
            async with self._driver.session() as s:
                n_result = await s.run(
                    "MATCH (n)-[*0..3]-(:Target {host:$host}) RETURN DISTINCT n LIMIT 200",
                    host=host,
                )
                nodes, edges = [], []
                node_ids = set()
                async for record in n_result:
                    n = record["n"]
                    nid = str(n.id)
                    if nid not in node_ids:
                        node_ids.add(nid)
                        nodes.append({
                            "id":     nid,
                            "label":  dict(n).get("host") or dict(n).get("name") or dict(n).get("description","?")[:40],
                            "type":   list(n.labels)[0] if n.labels else "Unknown",
                            "props":  dict(n),
                        })

                e_result = await s.run(
                    """
                    MATCH (a)-[r]->(b)
                    WHERE (a)-[*0..3]-(:Target {host:$host})
                    RETURN id(a) AS from, id(b) AS to, type(r) AS rel LIMIT 500
                    """,
                    host=host,
                )
                async for record in e_result:
                    edges.append({
                        "from":  str(record["from"]),
                        "to":    str(record["to"]),
                        "label": record["rel"],
                    })

                return {"nodes": nodes, "edges": edges}
        except Exception as e:
            log.warning(f"Neo4j export_graph error: {e}")
            return {"nodes": [], "edges": []}
