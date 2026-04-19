"""Asyncio TCP server with IP_TRANSPARENT support and protocol-aware dispatch."""

from __future__ import annotations

import asyncio
import datetime
import socket
import time
import traceback
import uuid
from typing import Optional

from honeypot.config import HoneypotConfig
from honeypot.detector import ProtocolDetector
from honeypot.log import get_logger, log_connection
from honeypot.registry import PluginRegistry

logger = get_logger(__name__)

# Linux socket option for transparent proxying.
_IP_TRANSPARENT = 19
_SOL_IP = socket.SOL_IP


def _create_transparent_socket(host: str, port: int) -> socket.socket:
    """
    Create a TCP socket with IP_TRANSPARENT set, falling back to a plain
    socket when IP_TRANSPARENT is not available (non-Linux / insufficient
    privileges).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        sock.setsockopt(_SOL_IP, _IP_TRANSPARENT, 1)
        logger.info("IP_TRANSPARENT enabled on TCP socket")
    except OSError as exc:
        logger.warning(
            "Could not set IP_TRANSPARENT (%s). Running without transparent proxy "
            "support (OK for local development, not for production).",
            exc,
        )

    sock.bind((host, port))
    sock.listen()
    sock.setblocking(False)
    return sock


class HoneypotServer:
    """
    Asyncio TCP server.

    Accepts connections, reads the preamble (with timeout), detects the
    protocol via ``ProtocolDetector``, and dispatches to the appropriate
    ``BaseHandler`` plugin.
    """

    def __init__(
        self,
        config: HoneypotConfig,
        registry: PluginRegistry,
        stats=None,  # Optional[ServerStats] -- avoid circular import
    ) -> None:
        self._config = config
        self._registry = registry
        self._stats = stats
        self._server: Optional[asyncio.AbstractServer] = None
        self._detector = ProtocolDetector(
            registry,
            preamble_size=config.preamble_size,
            preamble_timeout=config.preamble_timeout,
        )
        # Wire up registry to detector for cache invalidation
        self._registry.set_detector(self._detector)

    def set_stats(self, stats) -> None:
        """Attach a ServerStats instance (may be called after __init__)."""
        self._stats = stats

    async def start(self) -> None:
        """Bind the socket and start accepting connections."""
        sock = _create_transparent_socket(self._config.listen_host, self._config.listen_port)
        self._server = await asyncio.start_server(
            self._handle_connection,
            sock=sock,
        )
        logger.info(
            "Honeypot TCP server listening on %s:%d",
            self._config.listen_host,
            self._config.listen_port,
        )

    async def stop(self) -> None:
        """Gracefully close the server (waits for in-flight handlers)."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        logger.info("Honeypot TCP server stopped")

    # ------------------------------------------------------------------
    # Connection handler
    # ------------------------------------------------------------------

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peername = writer.get_extra_info("peername") or ("?", 0)
        sockname = writer.get_extra_info("sockname") or ("?", 0)

        src_ip, src_port = peername[0], peername[1]
        dst_ip, dst_port = sockname[0], sockname[1]
        connection_id = uuid.uuid4().hex[:16]
        timestamp = time.time()

        metadata = {
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "timestamp": timestamp,
            "connection_id": connection_id,
            "config": self._config,
            "stats": self._stats,  # Pass stats for handlers to record events
        }

        if self._stats is not None:
            self._stats.connection_started(src_ip)

        try:
            await self._process_connection(reader, writer, metadata)
        finally:
            if self._stats is not None:
                self._stats.connection_finished()
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _process_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        metadata: dict,
    ) -> None:
        connection_id = metadata["connection_id"]
        src_ip = metadata["src_ip"]
        src_port = metadata["src_port"]
        dst_ip = metadata["dst_ip"]
        dst_port = metadata["dst_port"]

        # --- Read preamble ---
        preamble = await self._detector.read_preamble(reader)

        if not preamble:
            # Empty-connection probes are high-value intel (SNY-only scanners)
            logger.info(
                "[%s] %s:%d -> %s:%d: no data received (scanner/probe), closing",
                connection_id,
                src_ip,
                src_port,
                dst_ip,
                dst_port,
            )
            if self._stats is not None:
                self._stats.record_protocol("empty")
                self._stats.add_event(
                    {
                        "timestamp": _iso(metadata["timestamp"]),
                        "src_ip": src_ip,
                        "dst_port": dst_port,
                        "protocol": "empty",
                        "connection_id": connection_id,
                        "event_type": "scanner_probe",
                    }
                )
            return

        # --- Log the connection ---
        raw_hex = preamble.hex()
        if len(raw_hex) > 4096:
            raw_hex = raw_hex[:4096] + "...(truncated)"
        log_connection(logger, metadata, "detecting", raw_hex)

        # --- Detect protocol ---
        handler_cls = await self._detector.detect(preamble)
        fallback_cls = self._registry.get_fallback()

        if handler_cls is None:
            if fallback_cls is not None:
                handler_cls = fallback_cls
                protocol_name = getattr(fallback_cls, "name", "llm_fallback")
            else:
                logger.info(
                    "[%s] %s:%d -> %s:%d: unhandled protocol, no fallback configured",
                    connection_id,
                    src_ip,
                    src_port,
                    dst_ip,
                    dst_port,
                )
                if self._stats is not None:
                    self._stats.record_protocol("unhandled")
                    self._stats.add_event(
                        {
                            "timestamp": _iso(metadata["timestamp"]),
                            "src_ip": src_ip,
                            "dst_port": dst_port,
                            "protocol": "unhandled",
                            "connection_id": connection_id,
                        }
                    )
                return
        else:
            protocol_name = getattr(handler_cls, "name", "unknown")

        # --- Record stats ---
        if self._stats is not None:
            self._stats.record_protocol(protocol_name)
            self._stats.add_event(
                {
                    "timestamp": _iso(metadata["timestamp"]),
                    "src_ip": src_ip,
                    "dst_port": dst_port,
                    "protocol": protocol_name,
                    "connection_id": connection_id,
                }
            )

        # --- Dispatch to handler ---
        handler_instance = handler_cls()
        try:
            await handler_instance.handle(reader, writer, preamble, metadata)
        except Exception:
            logger.error(
                "[%s] Handler '%s' raised an exception:\n%s",
                connection_id,
                handler_cls.name,
                traceback.format_exc(),
            )


def _iso(ts: float) -> str:
    """Format a Unix timestamp as a simple ISO-8601 UTC string."""
    return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
