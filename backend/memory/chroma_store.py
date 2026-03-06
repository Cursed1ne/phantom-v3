"""
PHANTOM AI v3 — Chroma Vector Store
─────────────────────────────────────
Chroma gives PHANTOM semantic memory — the ability to ask "have I seen
something *like* this before?" rather than just exact-match lookups.

How it works in practice:
  1. After each scan, every finding's description is embedded (turned into
     a 384-dimensional vector) using a local sentence-transformer model.
  2. That vector is stored in Chroma alongside the metadata (severity, tool,
     target, session_id).
  3. Before the next scan, the Planner agent queries: "what findings are
     semantically similar to what we already know about this target?"
  4. Chroma does an approximate-nearest-neighbour search and returns the
     top-k most similar past findings.
  5. Those findings are injected into the agent's system prompt as
     "SIMILAR PAST FINDINGS", giving the LLM institutional memory.

Why this matters: SQL injection in a login form and SQL injection in a
search box are *semantically* the same vulnerability even though the
exact strings are different. Chroma catches that; a simple keyword
search wouldn't.
"""

import json
import logging
from typing import Dict, List, Optional

log = logging.getLogger(__name__)

try:
    import chromadb
    from chromadb.config import Settings
    CHROMA_AVAILABLE = True
except ImportError:
    CHROMA_AVAILABLE = False
    log.warning("chromadb not installed — vector memory disabled")

try:
    from sentence_transformers import SentenceTransformer
    ST_AVAILABLE = True
except ImportError:
    ST_AVAILABLE = False
    log.warning("sentence-transformers not installed — using hash-based IDs")


class ChromaStore:
    """
    Semantic vector store wrapping ChromaDB.
    Degrades gracefully: if Chroma isn't installed, all methods are no-ops
    that return empty results, so the agents work fine without it.
    """

    COLLECTION = "phantom_findings"
    EMBED_MODEL = "all-MiniLM-L6-v2"   # fast, 384-dim, runs on CPU

    def __init__(self, persist_dir: str = "./chroma_db"):
        self.persist_dir = persist_dir
        self._client     = None
        self._collection = None
        self._embedder   = None

    async def connect(self) -> bool:
        if not CHROMA_AVAILABLE:
            return False
        try:
            self._client = chromadb.PersistentClient(
                path=self.persist_dir,
                settings=Settings(anonymized_telemetry=False),
            )
            self._collection = self._client.get_or_create_collection(
                name=self.COLLECTION,
                metadata={"hnsw:space": "cosine"},
            )
            if ST_AVAILABLE:
                self._embedder = SentenceTransformer(self.EMBED_MODEL)
                log.info(f"Chroma + SentenceTransformer ready ({self.EMBED_MODEL})")
            else:
                log.info("Chroma ready (no embedder — using Chroma's default)")
            return True
        except Exception as e:
            log.warning(f"Chroma connection failed: {e}")
            return False

    # ── Store a finding in the vector DB ────────────────────────────

    def _embed(self, text: str) -> Optional[List[float]]:
        """Embed a string using the local sentence-transformer model."""
        if self._embedder:
            return self._embedder.encode(text).tolist()
        return None   # Chroma will use its built-in embedder as fallback

    def add_finding(self, finding: Dict) -> bool:
        """
        Add a finding to the vector store so it can be semantically
        searched in future scans. Each finding is stored with:
          - its embedding (the 'content' being the description)
          - metadata: severity, tool, agent, session_id, cvss
        """
        if not self._collection:
            return False
        try:
            text = finding.get("description", "")
            fid  = finding.get("id", "")
            if not text or not fid:
                return False

            embedding = self._embed(text)
            kwargs = {
                "ids":       [fid],
                "documents": [text],
                "metadatas": [{
                    "severity":   finding.get("severity", ""),
                    "tool":       finding.get("tool", ""),
                    "agent":      finding.get("agent", ""),
                    "session_id": finding.get("session_id", ""),
                    "cvss":       str(finding.get("cvss", 0)),
                    "target":     finding.get("target", ""),
                }],
            }
            if embedding:
                kwargs["embeddings"] = [embedding]

            self._collection.add(**kwargs)
            return True
        except Exception as e:
            log.warning(f"Chroma add_finding error: {e}")
            return False

    def add_findings_batch(self, findings: List[Dict]) -> int:
        """Bulk-add findings. Returns the number successfully stored."""
        return sum(1 for f in findings if self.add_finding(f))

    # ── Query for similar past findings ─────────────────────────────

    def find_similar(self, query: str, k: int = 5,
                     severity_filter: Optional[str] = None) -> List[Dict]:
        """
        Find the k most semantically similar past findings to a query string.
        Optionally filter to only a specific severity level.

        Returns a list of dicts with: description, severity, tool, agent,
        session_id, cvss, distance (0=identical, 2=opposite).
        """
        if not self._collection:
            return []
        try:
            where = {"severity": severity_filter} if severity_filter else None
            embedding = self._embed(query)

            kwargs = {
                "n_results":       k,
                "include":         ["documents", "metadatas", "distances"],
            }
            if embedding:
                kwargs["query_embeddings"] = [embedding]
            else:
                kwargs["query_texts"] = [query]
            if where:
                kwargs["where"] = where

            results = self._collection.query(**kwargs)

            docs  = results.get("documents",  [[]])[0]
            metas = results.get("metadatas",  [[]])[0]
            dists = results.get("distances",  [[]])[0]

            return [
                {**meta, "description": doc, "distance": round(dist, 3)}
                for doc, meta, dist in zip(docs, metas, dists)
            ]
        except Exception as e:
            log.warning(f"Chroma find_similar error: {e}")
            return []

    def find_by_target(self, target: str, k: int = 20) -> List[Dict]:
        """Retrieve all stored findings for a specific target domain."""
        if not self._collection:
            return []
        try:
            results = self._collection.query(
                query_texts=[target],
                n_results=k,
                where={"target": target},
                include=["documents", "metadatas"],
            )
            docs  = results.get("documents",  [[]])[0]
            metas = results.get("metadatas",  [[]])[0]
            return [{**meta, "description": doc} for doc, meta in zip(docs, metas)]
        except Exception as e:
            log.warning(f"Chroma find_by_target error: {e}")
            return []

    # ── Stats ────────────────────────────────────────────────────────

    def count(self) -> int:
        """Total number of embeddings stored."""
        if not self._collection:
            return 0
        try:
            return self._collection.count()
        except Exception:
            return 0
