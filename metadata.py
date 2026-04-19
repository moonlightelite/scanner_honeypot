"""Connection metadata capture utility for honeypot handlers.

Provides a shared mechanism for capturing detailed connection metadata
including timing, commands executed, and protocol-specific data.

Usage in handlers::

    from honeypot.metadata import capture_metadata

    async def handle(self, reader, writer, preamble, metadata):
        with capture_metadata(metadata) as cm:
            cm.record_event("connection_start", {"preamble_hex": preamble.hex()[:100]})
            # ... handle connection ...
            cm.record_event("command", {"type": "query", "data": query})
            # metadata is automatically saved on exit
"""

from __future__ import annotations

import asyncio
import json
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from collections import deque

from honeypot.log import get_logger

logger = get_logger(__name__)

# Default metadata storage directory
DEFAULT_STORAGE_DIR = Path("/var/log/honeypot")

# Maximum events to buffer per connection (prevents OOM)
MAX_EVENTS_PER_CONNECTION = 1000

# Flush interval for batch writes (seconds)
FLUSH_INTERVAL = 5.0

# Maximum batch size for writes
MAX_BATCH_SIZE = 100


@dataclass
class ConnectionMetadata:
    """Captures all metadata for a single connection."""

    connection_id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    events: list[dict] = field(default_factory=list)
    commands: list[dict] = field(default_factory=list)
    bytes_received: int = 0
    bytes_sent: int = 0
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "connection_id": self.connection_id,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "start_time": self.start_time,
            "start_iso": datetime.fromtimestamp(self.start_time, tz=timezone.utc).isoformat(),
            "end_time": self.end_time,
            "end_iso": datetime.fromtimestamp(self.end_time, tz=timezone.utc).isoformat() if self.end_time else None,
            "duration_seconds": round(self.end_time - self.start_time, 3) if self.end_time else None,
            "events": self.events,
            "commands": self.commands,
            "bytes_received": self.bytes_received,
            "bytes_sent": self.bytes_sent,
            "extra": self.extra,
        }

    def record_event(self, event_type: str, data: dict) -> None:
        """Record a timestamped event."""
        self.events.append({
            "type": event_type,
            "timestamp": time.time(),
            "timestamp_iso": datetime.now(timezone.utc).isoformat(),
            "data": data,
        })
        if len(self.events) > MAX_EVENTS_PER_CONNECTION:
            self.events = self.events[-MAX_EVENTS_PER_CONNECTION:]

    def record_command(self, command_type: str, command_data: Any) -> None:
        """Record a command/query/request executed by the client."""
        self.commands.append({
            "type": command_type,
            "timestamp": time.time(),
            "timestamp_iso": datetime.now(timezone.utc).isoformat(),
            "data": command_data,
        })
        if len(self.commands) > MAX_EVENTS_PER_CONNECTION:
            self.commands = self.commands[-MAX_EVENTS_PER_CONNECTION:]

    def finish(self) -> None:
        """Mark the connection as ended."""
        self.end_time = time.time()


class MetadataCapture:
    """
    Async metadata capture system with batched writes.

    Captures connection metadata and writes to JSONL files asynchronously.
    """

    def __init__(
        self,
        storage_dir: Optional[Path] = None,
        flush_interval: float = FLUSH_INTERVAL,
        max_batch_size: int = MAX_BATCH_SIZE,
        enabled: bool = True,
    ) -> None:
        self.storage_dir = storage_dir or DEFAULT_STORAGE_DIR
        self.flush_interval = flush_interval
        self.max_batch_size = max_batch_size
        self.enabled = enabled

        # Buffer for pending writes
        self._buffer: deque[dict] = deque()
        self._buffer_lock = asyncio.Lock()

        # Background flush task
        self._flush_task: Optional[asyncio.Task] = None
        self._running = False

        # Ensure storage directory exists. Capture must fail open: the honeypot
        # should still run if persistent metadata is unavailable.
        if self.enabled:
            try:
                self.storage_dir.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                self.enabled = False
                logger.warning(
                    "Metadata storage directory %s is unavailable (%s); capture disabled",
                    self.storage_dir,
                    exc,
                )

        # Per-protocol files
        self._files: dict[str, Any] = {}

    async def start(self) -> None:
        """Start the background flush task."""
        if not self.enabled:
            return
        self._running = True
        self._flush_task = asyncio.create_task(self._flush_loop())
        logger.info("Metadata capture started, writing to %s", self.storage_dir)

    async def stop(self) -> None:
        """Stop the background flush task and flush remaining data."""
        if not self.enabled:
            return
        self._running = False
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        # Final flush
        await self._flush_now()
        logger.info("Metadata capture stopped")

    async def _flush_loop(self) -> None:
        """Background task that periodically flushes the buffer."""
        try:
            while self._running:
                await asyncio.sleep(self.flush_interval)
                await self._flush_now()
        except asyncio.CancelledError:
            pass

    async def _flush_now(self) -> None:
        """Flush buffered writes to disk."""
        if not self.enabled:
            return
        async with self._buffer_lock:
            if not self._buffer:
                return

            # Group by protocol for efficient file writes
            by_protocol: dict[str, list[dict]] = {}
            while self._buffer:
                record = self._buffer.popleft()
                protocol = record.get("protocol", "unknown")
                if protocol not in by_protocol:
                    by_protocol[protocol] = []
                by_protocol[protocol].append(record)

            # Write each protocol to its own file
            for protocol, records in by_protocol.items():
                await self._write_to_file(protocol, records)

    async def _write_to_file(self, protocol: str, records: list[dict]) -> None:
        """Write records to a protocol-specific JSONL file."""
        # Rotate by date
        date_str = datetime.now().strftime("%Y%m%d")
        filename = f"{protocol}_{date_str}.jsonl"
        filepath = self.storage_dir / filename

        try:
            # Use async file writing via executor
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                self._append_jsonl,
                filepath,
                records,
            )
            logger.debug("Wrote %d metadata records to %s", len(records), filepath)
        except Exception as e:
            logger.error("Failed to write metadata: %s", e)

    def _append_jsonl(self, filepath: Path, records: list[dict]) -> None:
        """Append records to a JSONL file (runs in executor)."""
        with open(filepath, "a") as f:
            for record in records:
                f.write(json.dumps(record, default=_json_default) + "\n")

    async def record(self, metadata) -> None:
        """Record connection metadata (called when connection ends)."""
        if not self.enabled:
            return
        record = metadata.to_dict()
        async with self._buffer_lock:
            self._buffer.append(record)
            # Flush immediately if buffer is large
            if len(self._buffer) >= self.max_batch_size:
                asyncio.create_task(self._flush_now())

    async def record_live(self, record: dict) -> None:
        """Record a live event immediately (for real-time dashboards)."""
        if not self.enabled:
            return
        async with self._buffer_lock:
            self._buffer.append(record)


# Global instance (eagerly initialized in start_capture; fallback for tests)
_capture: Optional[MetadataCapture] = None
_capture_lock: Optional[asyncio.Lock] = None


def get_capture() -> MetadataCapture:
    """Get the global MetadataCapture instance, creating one if needed."""
    global _capture
    if _capture is not None:
        return _capture
    # Fallback: create a disabled instance so callers never get None.
    # The real instance is set by start_capture() before the event loop runs.
    _capture = MetadataCapture(enabled=False)
    return _capture


def _json_default(value: Any) -> Any:
    """Make captured protocol metadata JSON-safe."""
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, Path):
        return str(value)
    return str(value)


async def get_recent_connections(
    limit: int = 50,
    storage_dir: Optional[Path] = None,
) -> list[dict]:
    """
    Read recent connection records from JSONL files.

    Args:
        limit: Maximum number of records to return (newest first).

    Returns:
        List of connection records sorted by end_time descending.
    """
    path = storage_dir or DEFAULT_STORAGE_DIR
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _get_recent_connections_sync, path, limit)


def _get_recent_connections_sync(storage_dir: Path, limit: int) -> list[dict]:
    """Read recent connection records from disk without blocking the event loop."""
    if not storage_dir.exists():
        return []

    all_records = []

    for fname in sorted(storage_dir.glob("*.jsonl"), reverse=True):
        try:
            with open(fname, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            record = json.loads(line)
                            all_records.append(record)
                        except json.JSONDecodeError:
                            continue
        except (IOError, OSError):
            continue

        # Stop if we have enough records
        if len(all_records) >= limit:
            break

    # Sort by end_time descending (most recent first)
    all_records.sort(
        key=lambda x: x.get("end_time", x.get("start_time", 0)),
        reverse=True,
    )
    return all_records[:limit]


async def start_capture(
    storage_dir: Optional[Path] = None,
    *,
    enabled: bool = True,
) -> MetadataCapture:
    """Start the global metadata capture system."""
    global _capture
    _capture = MetadataCapture(storage_dir, enabled=enabled)
    await _capture.start()
    return _capture


async def stop_capture() -> None:
    """Stop the global metadata capture system."""
    if _capture is not None:
        await _capture.stop()


@asynccontextmanager
async def connection_context(metadata: dict, protocol: str):
    """
    Async context manager for capturing connection metadata.

    Usage::

        async with connection_context(metadata, "postgresql") as cm:
            cm.record_command("startup", {"user": "postgres"})
            # ... handle connection ...
    """
    conn_meta = ConnectionMetadata(
        connection_id=metadata.get("connection_id", "unknown"),
        src_ip=metadata.get("src_ip", "unknown"),
        src_port=metadata.get("src_port", 0),
        dst_ip=metadata.get("dst_ip", "unknown"),
        dst_port=metadata.get("dst_port", 0),
        protocol=protocol,
    )

    try:
        yield conn_meta
    finally:
        conn_meta.finish()
        capture = get_capture()
        await capture.record(conn_meta)


class ConnectionCapture:
    """
    Per-connection metadata capture helper.

    Use this in handler classes to track metadata throughout
    the connection lifecycle.
    """

    def __init__(self, metadata: dict, protocol: str) -> None:
        self.connection_id = metadata.get("connection_id", "unknown")
        self.src_ip = metadata.get("src_ip", "unknown")
        self.src_port = metadata.get("src_port", 0)
        self.dst_ip = metadata.get("dst_ip", "unknown")
        self.dst_port = metadata.get("dst_port", 0)
        self.protocol = protocol
        self.start_time = time.time()
        self.events: list[dict] = []
        self.commands: list[dict] = []
        self.bytes_received = 0
        self.bytes_sent = 0
        self.extra: dict = {}

    def record_event(self, event_type: str, data: dict) -> None:
        """Record a timestamped event."""
        self.events.append({
            "type": event_type,
            "timestamp": time.time(),
            "timestamp_iso": datetime.now(timezone.utc).isoformat(),
            "data": data,
        })
        if len(self.events) > MAX_EVENTS_PER_CONNECTION:
            self.events = self.events[-MAX_EVENTS_PER_CONNECTION:]

    def record_command(self, command_type: str, command_data: Any) -> None:
        """Record a command/query/request."""
        self.commands.append({
            "type": command_type,
            "timestamp": time.time(),
            "timestamp_iso": datetime.now(timezone.utc).isoformat(),
            "data": command_data,
        })
        if len(self.commands) > MAX_EVENTS_PER_CONNECTION:
            self.commands = self.commands[-MAX_EVENTS_PER_CONNECTION:]

    def add_bytes_received(self, count: int) -> None:
        """Track bytes received from client."""
        self.bytes_received += count

    def add_bytes_sent(self, count: int) -> None:
        """Track bytes sent to client."""
        self.bytes_sent += count

    def set_extra(self, key: str, value: Any) -> None:
        """Set extra protocol-specific metadata."""
        self.extra[key] = value

    def to_dict(self) -> dict:
        """Convert to dictionary for storage."""
        end_time = time.time()
        return {
            "connection_id": self.connection_id,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "start_time": self.start_time,
            "start_iso": datetime.fromtimestamp(self.start_time, tz=timezone.utc).isoformat(),
            "end_time": end_time,
            "end_iso": datetime.fromtimestamp(end_time, tz=timezone.utc).isoformat(),
            "duration_seconds": round(end_time - self.start_time, 3),
            "events": self.events,
            "commands": self.commands,
            "bytes_received": self.bytes_received,
            "bytes_sent": self.bytes_sent,
            "extra": self.extra,
        }

    async def save(self) -> None:
        """Save the captured metadata."""
        capture = get_capture()
        await capture.record(self)
