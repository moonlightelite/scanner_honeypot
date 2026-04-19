"""Admin Unix domain socket server for runtime plugin management.

Example usage (from the shell)::

    echo '{"cmd": "list"}' | socat - UNIX-CONNECT:/tmp/honeypot-admin.sock
    echo '{"cmd": "load", "module": "honeypot.plugins.http_netgear"}' | socat - UNIX-CONNECT:/tmp/honeypot-admin.sock
    echo '{"cmd": "status"}' | socat - UNIX-CONNECT:/tmp/honeypot-admin.sock
"""

from __future__ import annotations

import asyncio
import collections
import json
import os
import stat
import time
from dataclasses import dataclass, field
from typing import Optional

from honeypot.log import get_logger

logger = get_logger(__name__)

# Allowed plugin module paths - prevents arbitrary code execution
ALLOWED_PLUGIN_PREFIXES = (
    "honeypot.plugins.",
    "plugins.",
)


# ---------------------------------------------------------------------------
# Server statistics
# ---------------------------------------------------------------------------


# Maximum number of unique IPs to track (prevents OOM on busy honeypot)
_MAX_IPS_TRACKED = 10000


@dataclass
class ServerStats:
    """Mutable statistics container shared between the TCP server and admin."""

    start_time: float = field(default_factory=time.time)
    connections_total: int = 0
    connections_active: int = 0

    # Extended stats (task 007)
    connections_by_protocol: dict[str, int] = field(default_factory=dict)
    _connections_by_ip_raw: dict[str, int] = field(default_factory=dict)
    _ip_lru_order: collections.deque = field(
        default_factory=lambda: collections.deque(maxlen=_MAX_IPS_TRACKED)
    )
    recent_events: collections.deque = field(
        default_factory=lambda: collections.deque(maxlen=200)
    )

    def connection_started(self, src_ip: str) -> None:
        """Record a new connection being accepted."""
        self.connections_total += 1
        self.connections_active += 1

        # Track IP with LRU eviction to prevent OOM
        if src_ip not in self._connections_by_ip_raw:
            # Evict oldest IP if at capacity
            if len(self._connections_by_ip_raw) >= _MAX_IPS_TRACKED:
                oldest_ip = self._ip_lru_order.popleft()
                if oldest_ip in self._connections_by_ip_raw:
                    del self._connections_by_ip_raw[oldest_ip]
            self._ip_lru_order.append(src_ip)
            self._connections_by_ip_raw[src_ip] = 0
        self._connections_by_ip_raw[src_ip] += 1

    @property
    def connections_by_ip(self) -> dict[str, int]:
        """Return connections by IP, sorted by count descending."""
        return self._connections_by_ip_raw

    def connection_finished(self) -> None:
        """Record a connection being closed."""
        self.connections_active = max(0, self.connections_active - 1)

    def record_protocol(self, protocol: str) -> None:
        """Record which protocol was detected for a connection."""
        self.connections_by_protocol[protocol] = (
            self.connections_by_protocol.get(protocol, 0) + 1
        )

    def add_event(self, event: dict) -> None:
        """Append an event to the recent events ring buffer."""
        self.recent_events.append(event)

    @property
    def uptime(self) -> float:
        return time.time() - self.start_time


# ---------------------------------------------------------------------------
# Admin server
# ---------------------------------------------------------------------------


class AdminServer:
    """
    Listens on a Unix domain socket and processes JSON management commands.

    The socket is line-oriented: one JSON object per line in, one JSON object
    per line out.
    """

    def __init__(self, config, registry) -> None:
        """
        Args:
            config: HoneypotConfig instance.
            registry: PluginRegistry instance.
        """
        self._config = config
        self._registry = registry
        self._stats: Optional[ServerStats] = None
        self._server: Optional[asyncio.AbstractServer] = None
        self._start_time = time.time()

    def set_stats(self, stats: ServerStats) -> None:
        """Attach a ServerStats instance so the status command can report it."""
        self._stats = stats

    async def start(self) -> None:
        path = self._config.admin_socket_path

        # Clean up stale socket from a previous run or crash.
        if os.path.exists(path):
            try:
                os.unlink(path)
                logger.info("Removed stale admin socket at %s", path)
            except OSError as exc:
                logger.warning("Could not remove stale admin socket: %s", exc)

        self._server = await asyncio.start_unix_server(
            self._handle_connection,
            path=path,
        )
        # Set permissions: owner rw, group rw (0o660)
        # Allow admin group members to access the socket
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP)  # 0o660

        # Try to set group to 'honeypot-admin' if it exists
        import grp
        try:
            group_info = grp.getgrnam("honeypot-admin")
            os.chown(path, -1, group_info.gr_gid)
            logger.info("Admin socket group set to 'honeypot-admin'")
        except KeyError:
            logger.debug("Group 'honeypot-admin' not found; socket group unchanged")
        except OSError as exc:
            logger.warning("Could not set socket group: %s", exc)

        logger.info("Admin socket listening at %s (permissions 0o660, admin group accessible)", path)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

        path = self._config.admin_socket_path
        if os.path.exists(path):
            try:
                os.unlink(path)
            except OSError as exc:
                logger.warning("Could not remove admin socket on shutdown: %s", exc)

        logger.info("Admin server stopped")

    # ------------------------------------------------------------------
    # Connection handler
    # ------------------------------------------------------------------

    # Max line size for admin commands (prevents OOM attacks)
    MAX_LINE_SIZE = 4096

    async def _readline_with_limit(self, reader: asyncio.StreamReader) -> bytes:
        """Read a line with a maximum size limit to prevent OOM attacks."""
        line = bytearray()
        while len(line) < self.MAX_LINE_SIZE:
            chunk = await reader.read(1)
            if not chunk:
                break
            line.extend(chunk)
            if chunk == b'\n':
                break
        if len(line) > self.MAX_LINE_SIZE:
            raise asyncio.IncompleteReadError(partial=bytes(line), expected=len(line))
        return bytes(line)

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            while True:
                try:
                    line = await self._readline_with_limit(reader)
                except asyncio.IncompleteReadError:
                    response = {"ok": False, "error": f"Line exceeds maximum size of {self.MAX_LINE_SIZE} bytes"}
                    writer.write(json.dumps(response).encode() + b"\n")
                    await writer.drain()
                    break
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                response = await self._dispatch(line)
                writer.write(json.dumps(response).encode() + b"\n")
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _dispatch(self, raw: bytes) -> dict:
        try:
            cmd = json.loads(raw)
        except json.JSONDecodeError as exc:
            return {"ok": False, "error": f"Invalid JSON: {exc}"}

        if not isinstance(cmd, dict) or "cmd" not in cmd:
            return {"ok": False, "error": "Missing 'cmd' key"}

        name = cmd["cmd"]

        if name == "list":
            return self._cmd_list()
        if name == "load":
            return await self._cmd_load(cmd)
        if name == "unload":
            return await self._cmd_unload(cmd)
        if name == "reload":
            return await self._cmd_reload(cmd)
        if name == "status":
            return self._cmd_status()

        return {"ok": False, "error": "unknown command"}

    # ------------------------------------------------------------------
    # Commands
    # ------------------------------------------------------------------

    def _cmd_list(self) -> dict:
        handlers = [
            {
                "name": cls.name,
                "protocols": cls.protocols,
                "is_fallback": getattr(cls, "is_fallback", False),
                "priority": cls.priority,
            }
            for cls in self._registry.get_all()
        ]
        return {"ok": True, "handlers": handlers}

    async def _cmd_load(self, cmd: dict) -> dict:
        module = cmd.get("module")
        if not module:
            return {"ok": False, "error": "Missing 'module' field"}
        # Validate module path against allowlist
        if not any(module.startswith(prefix) for prefix in ALLOWED_PLUGIN_PREFIXES):
            return {
                "ok": False,
                "error": f"Module path '{module}' not allowed; must start with one of: {', '.join(ALLOWED_PLUGIN_PREFIXES)}"
            }
        try:
            handler_name = await self._registry.load(module)
            return {"ok": True, "name": handler_name}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    async def _cmd_unload(self, cmd: dict) -> dict:
        name = cmd.get("name")
        if not name:
            return {"ok": False, "error": "Missing 'name' field"}
        # Validate that the handler being unloaded is already registered
        if name not in self._registry._module_paths:
            return {"ok": False, "error": f"No handler named '{name}' is registered"}
        try:
            await self._registry.unload(name)
            return {"ok": True}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    async def _cmd_reload(self, cmd: dict) -> dict:
        name = cmd.get("name")
        if not name:
            return {"ok": False, "error": "Missing 'name' field"}
        # Validate that the handler being reloaded is already registered (not arbitrary code)
        if name not in self._registry._module_paths:
            return {"ok": False, "error": f"No handler named '{name}' is registered"}
        try:
            await self._registry.reload(name)
            return {"ok": True}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def _cmd_status(self) -> dict:
        if self._stats is None:
            return {
                "ok": True,
                "uptime": time.time() - self._start_time,
                "connections_total": 0,
                "connections_active": 0,
            }
        return {
            "ok": True,
            "uptime": round(self._stats.uptime, 2),
            "connections_total": self._stats.connections_total,
            "connections_active": self._stats.connections_active,
        }
