"""
PHANTOM AI v3 — Redis Store
────────────────────────────
Redis is used for anything that needs sub-millisecond access and
doesn't need to survive a server restart:

  • Live agent state (which iteration is each agent on right now?)
  • Scan-in-progress flag per target (prevents accidental double-scans)
  • Rate-limit counters for aggressive tools
  • Short-lived credential cache during a scan session
  • Pub/Sub channel for inter-agent messaging (future: parallel agents)

Why Redis and not just a Python dict?
Because in production you may run multiple backend workers, and a
shared Redis instance lets them all read/write the same state.
In single-process mode (Electron dev), it still works — just faster
than SQLite for these transient write-heavy workloads.
"""

import json
import logging
from typing import Any, Dict, Optional

log = logging.getLogger(__name__)

# Redis is optional — gracefully degrade to in-memory if not available
try:
    import redis.asyncio as aioredis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    log.warning("redis package not installed — using in-memory fallback")


class RedisStore:
    """
    Async wrapper around Redis with a transparent in-memory fallback.
    Agents call this without knowing whether real Redis is running.
    """

    # Default TTLs (seconds)
    TTL_AGENT_STATE  = 3600   # 1 hour — enough for any scan
    TTL_SCAN_LOCK    = 7200   # 2 hours — prevents stuck locks
    TTL_RATE_COUNTER = 60     # 1 minute window for rate limiting
    TTL_CRED_CACHE   = 1800   # 30 minutes — short credential lifetime

    KEY_PREFIX = "phantom:v3:"

    def __init__(self, url: str = "redis://localhost:6379/0"):
        self.url  = url
        self._r   = None          # real Redis client
        self._mem: Dict[str, Any] = {}  # in-memory fallback

    async def connect(self) -> bool:
        """
        Try to connect to Redis. Returns True on success, False on failure.
        On failure, all subsequent calls transparently use the in-memory dict.
        """
        if not REDIS_AVAILABLE:
            log.info("Redis unavailable — using in-memory state store")
            return False
        try:
            self._r = aioredis.from_url(self.url, decode_responses=True)
            await self._r.ping()
            log.info(f"Redis connected: {self.url}")
            return True
        except Exception as e:
            log.warning(f"Redis connection failed ({e}) — using in-memory fallback")
            self._r = None
            return False

    async def disconnect(self):
        if self._r:
            await self._r.close()

    # ── Agent state ─────────────────────────────────────────────────

    async def set_agent_state(self, session_id: str, agent_id: str, state: Dict):
        """Store the current status of an agent: iteration, tool, findings count."""
        key = f"{self.KEY_PREFIX}agent:{session_id}:{agent_id}"
        val = json.dumps(state)
        if self._r:
            await self._r.setex(key, self.TTL_AGENT_STATE, val)
        else:
            self._mem[key] = val

    async def get_agent_state(self, session_id: str, agent_id: str) -> Optional[Dict]:
        key = f"{self.KEY_PREFIX}agent:{session_id}:{agent_id}"
        raw = (await self._r.get(key) if self._r else self._mem.get(key))
        return json.loads(raw) if raw else None

    async def get_all_agent_states(self, session_id: str) -> Dict[str, Dict]:
        """Fetch state for every agent in a session — used by the dashboard."""
        if self._r:
            pattern = f"{self.KEY_PREFIX}agent:{session_id}:*"
            keys    = await self._r.keys(pattern)
            result  = {}
            for k in keys:
                agent_id = k.split(":")[-1]
                raw = await self._r.get(k)
                if raw:
                    result[agent_id] = json.loads(raw)
            return result
        else:
            prefix = f"{self.KEY_PREFIX}agent:{session_id}:"
            return {
                k[len(prefix):]: json.loads(v)
                for k, v in self._mem.items()
                if k.startswith(prefix)
            }

    # ── Scan lock — prevents the same target being scanned twice ────

    async def acquire_scan_lock(self, target: str) -> bool:
        """
        Returns True if the lock was acquired (scan can start),
        False if the target is already being scanned.
        Uses SET NX (set-if-not-exists) for atomic compare-and-set.
        """
        key = f"{self.KEY_PREFIX}lock:{target}"
        if self._r:
            ok = await self._r.set(key, "1", nx=True, ex=self.TTL_SCAN_LOCK)
            return bool(ok)
        else:
            if key in self._mem:
                return False
            self._mem[key] = "1"
            return True

    async def release_scan_lock(self, target: str):
        key = f"{self.KEY_PREFIX}lock:{target}"
        if self._r:
            await self._r.delete(key)
        else:
            self._mem.pop(key, None)

    # ── Credential cache — store discovered creds during scan session

    async def cache_credential(self, session_id: str, service: str,
                                username: str, password: str):
        key = f"{self.KEY_PREFIX}creds:{session_id}:{service}"
        val = json.dumps({"username": username, "password": password,
                          "service": service})
        if self._r:
            await self._r.setex(key, self.TTL_CRED_CACHE, val)
        else:
            self._mem[key] = val

    async def get_credentials(self, session_id: str) -> Dict[str, Dict]:
        """Return all cached credentials for a session."""
        if self._r:
            prefix = f"{self.KEY_PREFIX}creds:{session_id}:"
            keys   = await self._r.keys(f"{prefix}*")
            result = {}
            for k in keys:
                raw = await self._r.get(k)
                if raw:
                    service = k[len(prefix):]
                    result[service] = json.loads(raw)
            return result
        else:
            prefix = f"{self.KEY_PREFIX}creds:{session_id}:"
            return {
                k[len(prefix):]: json.loads(v)
                for k, v in self._mem.items()
                if k.startswith(prefix)
            }

    # ── Pub/Sub — inter-agent messaging (used by planner) ───────────

    async def publish(self, channel: str, message: Dict):
        """Broadcast a structured message to all agents listening on a channel."""
        if self._r:
            await self._r.publish(
                f"{self.KEY_PREFIX}chan:{channel}",
                json.dumps(message)
            )
        # In-memory mode: no-op (single-process, direct calls suffice)

    # ── Stats counter ────────────────────────────────────────────────

    async def increment_stat(self, stat_key: str, amount: int = 1) -> int:
        key = f"{self.KEY_PREFIX}stat:{stat_key}"
        if self._r:
            return await self._r.incrby(key, amount)
        else:
            val = int(self._mem.get(key, 0)) + amount
            self._mem[key] = str(val)
            return val

    async def get_stat(self, stat_key: str) -> int:
        key = f"{self.KEY_PREFIX}stat:{stat_key}"
        if self._r:
            val = await self._r.get(key)
            return int(val) if val else 0
        return int(self._mem.get(key, 0))

    # ── Cleanup ──────────────────────────────────────────────────────

    async def clear_session(self, session_id: str):
        """Remove all keys associated with a finished scan session."""
        prefix = f"{self.KEY_PREFIX}.*:{session_id}:"
        if self._r:
            keys = await self._r.keys(f"{self.KEY_PREFIX}*{session_id}*")
            if keys:
                await self._r.delete(*keys)
        else:
            to_delete = [k for k in self._mem if session_id in k]
            for k in to_delete:
                del self._mem[k]
