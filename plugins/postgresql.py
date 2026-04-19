"""PostgreSQL database honeypot plugin.

Simulates a PostgreSQL server to attract database scanners and credential
harvesting attempts. Supports protocol v3 startup and MD5 authentication.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import random
import struct
from typing import Optional

from honeypot.base_handler import BaseHandler
from honeypot.log import get_logger
from honeypot.metadata import ConnectionCapture

logger = get_logger(__name__)

# Control character translation table for log sanitization
_CONTROL_CHAR_TABLE = str.maketrans(
    {c: f"\\x{c:02x}" for c in range(0x20) if c not in (0x09,)}
    | {0x7F: "\\x7f"}
)


def _sanitize_log_str(s: str) -> str:
    """Replace control characters in attacker-supplied strings to prevent log injection."""
    return s.translate(_CONTROL_CHAR_TABLE)

# PostgreSQL message types
MSG_AUTHENTICATION = b'R'
MSG_BACKEND_KEY_DATA = b'K'
MSG_COMMAND_COMPLETE = b'C'
MSG_DATA_ROW = b'D'
MSG_ERROR_RESPONSE = b'E'
MSG_NOTICE_RESPONSE = b'N'
MSG_NOTIFICATION = b'A'
MSG_PARAMETER_DESCRIPTION = b't'
MSG_PARAMETER_STATUS = b'S'
MSG_PARSE_COMPLETE = b'1'
MSG_READY_FOR_QUERY = b'Z'
MSG_ROW_DESCRIPTION = b'T'
MSG_TERMINATE = b'X'

# Authentication types
AUTH_OK = 0
AUTH_MD5_PASSWORD = 5

# Protocol versions
PROTO_V3 = 0x00030000
PROTO_V2 = 0x00020000

# Fake table names pool for randomization
_FAKE_TABLE_NAMES = ["users", "orders", "sessions", "accounts", "logs", "config", "cache", "tokens"]


class PostgreSQLHandler(BaseHandler):
    """Fake PostgreSQL server."""

    name = "postgresql"
    protocols = ["postgresql", "postgres", "psql"]
    priority = 25
    is_fallback = False

    # Fake server info
    SERVER_VERSION = "13.4.0"
    SERVER_ENCODING = "UTF8"
    DATE_STYLE = "ISO, MDY"

    # Fake database info
    DATABASE_NAME = "postgres"
    DEFAULT_USER = "postgres"

    @classmethod
    def match(cls, preamble: bytes) -> bool:
        """Detect PostgreSQL startup packet."""
        if len(preamble) < 8:
            return False

        try:
            msg_len = struct.unpack('>I', preamble[0:4])[0]
            proto_code = struct.unpack('>I', preamble[4:8])[0]

            # Check for SSL request (special case)
            if msg_len == 8 and proto_code == 0x04D2162F:
                return True

            # Check for V3 startup
            if proto_code == PROTO_V3:
                if 8 <= msg_len <= 4096:
                    return True

            # Check for V2 startup (high byte = 2)
            if (proto_code >> 16) == 2:
                return True

            return False
        except struct.error:
            return False

    async def handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        preamble: bytes,
        metadata: dict,
    ) -> None:
        """Handle PostgreSQL connection."""
        # Initialize metadata capture
        capture = ConnectionCapture(metadata, "postgresql")
        capture.record_event("connection_start", {"preamble_hex": preamble.hex()[:100]})

        try:
            conn_id = metadata.get("connection_id", "?")
            src_ip = metadata.get("src_ip", "?")
            dst_port = metadata.get("dst_port", 0)

            # Parse startup packet
            startup_info = self._parse_startup(preamble, conn_id)

            # Record startup info
            capture.set_extra("user", startup_info.get("user"))
            capture.set_extra("database", startup_info.get("database"))
            capture.set_extra("protocol_version", startup_info.get("protocol_version"))
            capture.set_extra("ssl_requested", startup_info.get("is_ssl", False))
            capture.record_command("startup", startup_info)

            is_ssl = startup_info.get("is_ssl", False)

            logger.info(
                "[%s] PostgreSQL connection from %s:%d - user=%s, db=%s, ssl=%s",
                conn_id,
                src_ip,
                dst_port,
                startup_info.get("user", "?"),
                startup_info.get("database", self.DATABASE_NAME),
                is_ssl,
            )

            # Handle SSL request
            if is_ssl:
                # This handler does not terminate TLS, so reject SSL and wait for
                # the client's plaintext startup packet, matching PostgreSQL's flow.
                writer.write(b'N')
                await writer.drain()
                capture.record_event("ssl_rejected", {})
                logger.debug("[%s] SSL requested; rejected and awaiting plaintext startup", conn_id)
                try:
                    preamble = await asyncio.wait_for(reader.read(4096), timeout=10.0)
                    capture.add_bytes_received(len(preamble))
                except asyncio.TimeoutError:
                    capture.record_event("timeout", {"stage": "startup_after_ssl", "waited_seconds": 10.0})
                    return
                if not preamble:
                    capture.record_event("client_disconnected", {"stage": "startup_after_ssl"})
                    return
                startup_info = self._parse_startup(preamble, conn_id)
                capture.set_extra("user", startup_info.get("user"))
                capture.set_extra("database", startup_info.get("database"))
                capture.set_extra("protocol_version", startup_info.get("protocol_version"))
                capture.record_command("startup_after_ssl", startup_info)

            # Send MD5 authentication challenge
            salt = os.urandom(4)
            capture.record_event("auth_challenge_sent", {"salt": salt.hex(), "method": "MD5"})
            await self._send_message(
                writer,
                MSG_AUTHENTICATION,
                struct.pack('>I', AUTH_MD5_PASSWORD) + salt,
            )

            logger.debug("[%s] Sent MD5 auth challenge with salt %s", conn_id, salt.hex())

            # Wait for password response
            try:
                response = await asyncio.wait_for(reader.read(4096), timeout=30.0)
                capture.add_bytes_received(len(response))
            except asyncio.TimeoutError:
                capture.record_event("timeout", {"stage": "password_wait", "waited_seconds": 30.0})
                logger.debug("[%s] Timeout waiting for password", conn_id)
                writer.close()
                return
            except (ConnectionResetError, BrokenPipeError):
                capture.record_event("client_disconnected", {"stage": "password_wait"})
                logger.debug("[%s] Client disconnected during auth", conn_id)
                return

            # Parse password message
            if len(response) >= 5 and response[0] == b'p'[0]:
                pwd_len = struct.unpack('>I', response[1:5])[0]
                if pwd_len < 4 or 1 + pwd_len > len(response):
                    capture.record_event("invalid_password_message", {"length": pwd_len})
                    return
                password_data = response[5:1 + pwd_len]
                password_str = password_data.decode('utf-8', errors='replace').rstrip('\x00')

                # Hash password for security
                password_hash = hashlib.sha256(password_str.encode()).hexdigest()[:16]
                logger.warning(
                    "[%s] PostgreSQL LOGIN ATTEMPT - user=%s, password_hash=%s...",
                    conn_id,
                    startup_info.get("user", "?"),
                    password_hash,
                )

                # Record credential command
                capture.record_command("password", {
                    "user": startup_info.get("user", "?"),
                    "password_hash": password_hash,
                })

                # Record credential harvest for dashboard
                stats = metadata.get("stats")
                if stats:
                    from honeypot.server import _iso
                    stats.add_event({
                        "type": "credential_harvest",
                        "timestamp": _iso(metadata.get("timestamp", 0)),
                        "src_ip": src_ip,
                        "username": startup_info.get("user", "?"),
                        "password": password_str,
                        "protocol": "postgresql",
                    })

            # Send Authentication OK
            capture.record_event("auth_ok_sent", {})
            await self._send_message(
                writer,
                MSG_AUTHENTICATION,
                struct.pack('>I', AUTH_OK),
            )

            # Send parameter status messages
            await self._send_param(writer, "server_version", self.SERVER_VERSION)
            await self._send_param(writer, "server_encoding", self.SERVER_ENCODING)
            await self._send_param(writer, "client_encoding", self.SERVER_ENCODING)
            await self._send_param(writer, "DateStyle", self.DATE_STYLE)
            await self._send_param(writer, "integer_datetimes", "on")
            await self._send_param(writer, "TimeZone", "UTC")
            await self._send_param(writer, "standard_conforming_strings", "on")

            # Send ReadyForQuery
            await self._send_message(writer, MSG_READY_FOR_QUERY, b'I')
            capture.record_event("ready_for_query", {})

            logger.info("[%s] PostgreSQL authentication successful, waiting for queries", conn_id)

            # Process queries (pass capture object)
            await self._process_queries(reader, writer, metadata, capture)

        finally:
            # Save captured metadata
            await capture.save()

    def _parse_startup(self, preamble: bytes, conn_id: str) -> dict:
        """Parse PostgreSQL startup packet."""
        info = {}

        try:
            msg_len = struct.unpack('>I', preamble[0:4])[0]
            proto_code = struct.unpack('>I', preamble[4:8])[0]

            # Check for SSL request
            if msg_len == 8 and proto_code == 0x04D2162F:
                info["is_ssl"] = True
                return info

            info["is_ssl"] = False
            info["protocol_version"] = proto_code

            # Parse key-value pairs (null-terminated strings)
            offset = 8
            current_key = None

            # Re-validate msg_len against actual preamble length (security check)
            if msg_len > len(preamble):
                logger.debug("[%s] Startup packet msg_len %d exceeds buffer %d", conn_id, msg_len, len(preamble))
                return info

            while offset < len(preamble) and offset < msg_len:
                # Find null terminator
                null_pos = preamble.find(b'\x00', offset)
                if null_pos == -1:
                    break

                value = preamble[offset:null_pos].decode('utf-8', errors='replace')

                if current_key is None:
                    current_key = value
                else:
                    info[current_key] = value
                    current_key = None

                offset = null_pos + 1

        except (struct.error, UnicodeDecodeError) as e:
            logger.debug("Error parsing startup packet: %s", e)

        return info

    async def _send_message(
        self,
        writer: asyncio.StreamWriter,
        msg_type: bytes,
        payload: bytes,
    ) -> None:
        """Send a PostgreSQL message."""
        length = struct.pack('>I', len(payload) + 4)
        writer.write(msg_type + length + payload)
        await writer.drain()

    async def _send_param(
        self,
        writer: asyncio.StreamWriter,
        name: str,
        value: str,
    ) -> None:
        """Send a ParameterStatus message."""
        payload = name.encode('utf-8') + b'\x00' + value.encode('utf-8') + b'\x00'
        await self._send_message(writer, MSG_PARAMETER_STATUS, payload)

    async def _process_queries(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        metadata: dict,
        capture: ConnectionCapture,
    ) -> None:
        """Process PostgreSQL queries."""
        conn_id = metadata.get("connection_id", "?")
        src_ip = metadata.get("src_ip", "?")

        while True:
            try:
                # Read message type (1 byte)
                msg_type = await reader.read(1)
                if not msg_type:
                    break

                msg_type = chr(msg_type[0])
                capture.add_bytes_received(1)

                # Read length (4 bytes)
                length_data = await asyncio.wait_for(reader.read(4), timeout=30.0)
                if len(length_data) < 4:
                    break

                msg_len = struct.unpack('>I', length_data)[0]
                capture.add_bytes_received(len(length_data))

                # Maximum query size to prevent DoS
                MAX_QUERY_SIZE = 1024 * 1024  # 1 MB
                if msg_len > MAX_QUERY_SIZE:
                    logger.warning("[%s] Query too large: %d bytes, closing", conn_id, msg_len)
                    capture.record_event("query_rejected", {"reason": "too_large", "size": msg_len})
                    return

                # Read payload
                payload = b""
                remaining = msg_len - 4
                while remaining > 0:
                    chunk = await asyncio.wait_for(reader.read(remaining), timeout=30.0)
                    if not chunk:
                        break
                    payload += chunk
                    capture.add_bytes_received(len(chunk))
                    remaining -= len(chunk)

                # Handle message
                await self._handle_query_message(msg_type, payload, writer, metadata, capture)

            except asyncio.TimeoutError:
                capture.record_event("timeout", {"stage": "query", "waited_seconds": 30.0})
                logger.debug("[%s] Query timeout", conn_id)
                break
            except (ConnectionResetError, BrokenPipeError):
                capture.record_event("client_disconnected", {"stage": "query"})
                logger.debug("[%s] Client disconnected", conn_id)
                break
            except Exception as e:
                capture.record_event("error", {"message": str(e)})
                logger.error("[%s] Error processing query: %s", conn_id, e)
                break

    async def _handle_query_message(
        self,
        msg_type: str,
        payload: bytes,
        writer: asyncio.StreamWriter,
        metadata: dict,
        capture: ConnectionCapture,
    ) -> None:
        """Handle a PostgreSQL query message."""
        conn_id = metadata.get("connection_id", "?")
        src_ip = metadata.get("src_ip", "?")
        stats = metadata.get("stats")

        if msg_type == 'Q':
            # Simple Query
            try:
                query = payload.rstrip(b'\x00').decode('utf-8', errors='replace')
                logger.info("[%s] Query: %s", conn_id, _sanitize_log_str(query[:200]))

                # Record query in metadata
                capture.record_command("query", {
                    "type": "simple",
                    "query": query[:1000],  # Truncate for storage
                    "length": len(query),
                })

                if stats:
                    from honeypot.server import _iso
                    stats.add_event({
                        "type": "postgresql_query",
                        "timestamp": _iso(metadata.get("timestamp", 0)),
                        "src_ip": src_ip,
                        "query": query[:500],  # Truncate long queries
                    })

                # Respond to query
                await self._respond_to_query(writer, query)
                capture.record_event("query_responded", {"query_type": "simple"})
            except Exception as e:
                capture.record_event("error", {"stage": "query_parse", "message": str(e)})
                logger.error("[%s] Error parsing query: %s", conn_id, e)

        elif msg_type == 'X':
            # Terminate
            capture.record_event("connection_terminated", {"by": "client"})
            logger.debug("[%s] Client terminated connection", conn_id)
            writer.close()

        elif msg_type == 'P':
            # Parse (extended protocol)
            parse_name = payload.split(b'\x00')[0].decode('utf-8', errors='replace')
            capture.record_command("parse", {"name": parse_name})
            logger.debug("[%s] Parse message (extended protocol)", conn_id)
            # Send Parse Complete
            await self._send_message(writer, b'1', b'')

        elif msg_type == 'B':
            # Bind
            capture.record_command("bind", {})
            logger.debug("[%s] Bind message", conn_id)

        elif msg_type == 'D':
            # Describe
            capture.record_command("describe", {})
            logger.debug("[%s] Describe message", conn_id)

        elif msg_type == 'E':
            # Execute
            capture.record_command("execute", {})
            logger.debug("[%s] Execute message", conn_id)
            # Send Command Complete
            await self._send_message(writer, MSG_COMMAND_COMPLETE, b"SELECT\x00")

        elif msg_type == 'S':
            # Sync
            capture.record_event("sync_received", {})
            logger.debug("[%s] Sync message", conn_id)
            await self._send_message(writer, MSG_READY_FOR_QUERY, b'I')

        else:
            capture.record_event("unknown_message", {"type": msg_type})
            logger.debug("[%s] Unknown message type: %s", conn_id, msg_type)

    async def _respond_to_query(
        self,
        writer: asyncio.StreamWriter,
        query: str,
    ) -> None:
        """Send a fake response to a query."""
        query_upper = query.upper().strip()

        # Check for common enumeration queries
        if "PG_TABLES" in query_upper or "INFORMATION_SCHEMA" in query_upper:
            # Fake table list
            await self._send_row_description(writer, [
                ("schemaname", "name"),
                ("tablename", "name"),
                ("tableowner", "name"),
            ])
            # Randomize table names per connection to prevent fingerprinting
            table_names = random.sample(_FAKE_TABLE_NAMES, 3)
            for table in table_names:
                await self._send_data_row(writer, ["public", table, "postgres"])
            await self._send_message(writer, MSG_COMMAND_COMPLETE, b"SELECT 3")

        elif "PG_USER" in query_upper or "PG_ROLES" in query_upper:
            # Fake user list
            await self._send_row_description(writer, [
                ("rolname", "name"),
                ("rolsuper", "bool"),
                ("rolinherit", "bool"),
            ])
            await self._send_data_row(writer, ["postgres", "t", "t"])
            await self._send_data_row(writer, ["admin", "f", "t"])
            await self._send_message(writer, MSG_COMMAND_COMPLETE, b"SELECT 2")

        elif query_upper.startswith("SELECT") or query_upper.startswith("SHOW"):
            # Generic SELECT - return fake data
            await self._send_row_description(writer, [
                ("result", "text"),
            ])
            await self._send_data_row(writer, ["OK"])
            await self._send_message(writer, MSG_COMMAND_COMPLETE, b"SELECT 1")

        elif query_upper.startswith("INSERT") or query_upper.startswith("UPDATE") or query_upper.startswith("DELETE"):
            # Write operations - fake success
            await self._send_message(writer, MSG_COMMAND_COMPLETE, b"UPDATE 1")

        else:
            # Unknown query - return empty success
            await self._send_message(writer, MSG_COMMAND_COMPLETE, b"SELECT 0")

        # Send ReadyForQuery
        await self._send_message(writer, MSG_READY_FOR_QUERY, b'I')

    async def _send_row_description(
        self,
        writer: asyncio.StreamWriter,
        columns: list[tuple[str, str]],
    ) -> None:
        """Send a RowDescription message."""
        payload = struct.pack('>H', len(columns))

        for col_name, col_type in columns:
            col_bytes = col_name.encode('utf-8')
            type_bytes = col_type.encode('utf-8')

            # Column format:
            # - Name (null-terminated string)
            # - Table OID (4 bytes, 0 for no table)
            # - Column attribute number (2 bytes, 0)
            # - Type OID (4 bytes)
            # - Type size (2 bytes)
            # - Type modifier (4 bytes, -1)
            # - Format code (2 bytes, 0 for text)

            payload += (
                col_bytes + b'\x00' +
                b'\x00\x00\x00\x00' +  # Table OID
                b'\x00\x00' +  # Column number
                b'\x00\x00\x00\x19' +  # Type OID (text)
                b'\xff\xff' +  # Type size (-1 for variable)
                b'\xff\xff\xff\xff' +  # Type modifier
                b'\x00\x00'  # Format code
            )

        await self._send_message(writer, MSG_ROW_DESCRIPTION, payload)

    async def _send_data_row(
        self,
        writer: asyncio.StreamWriter,
        values: list[str],
    ) -> None:
        """Send a DataRow message."""
        payload = struct.pack('>H', len(values))

        for value in values:
            value_bytes = value.encode('utf-8')
            payload += struct.pack('>I', len(value_bytes)) + value_bytes

        await self._send_message(writer, MSG_DATA_ROW, payload)
