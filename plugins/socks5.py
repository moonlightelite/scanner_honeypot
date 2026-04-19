"""SOCKS5 proxy honeypot plugin.

Simulates an open SOCKS5 proxy to attract scanners and observe their
connection patterns and target destinations.
"""

from __future__ import annotations

import asyncio
import hashlib
import socket
import struct
from typing import Optional

from honeypot.base_handler import BaseHandler
from honeypot.log import get_logger
from honeypot.metadata import ConnectionCapture

logger = get_logger(__name__)

# SOCKS5 constants
SOCKS_VERSION = 0x05

# Authentication methods
AUTH_NO_AUTH = 0x00
AUTH_GSSAPI = 0x01
AUTH_USERNAME_PASSWORD = 0x02
AUTH_NO_ACCEPTABLE = 0xFF

# Commands
CMD_CONNECT = 0x01
CMD_BIND = 0x02
CMD_ASSOCIATE = 0x03

# Address types
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04

# Reply codes
REP_SUCCESS = 0x00
REP_GENERAL_FAILURE = 0x01
REP_NOT_ALLOWED = 0x02
REP_NETWORK_UNREACHABLE = 0x03
REP_HOST_UNREACHABLE = 0x04
REP_CONNECTION_REFUSED = 0x05
REP_TTL_EXPIRED = 0x06
REP_CMD_NOT_SUPPORTED = 0x07
REP_ATYP_NOT_SUPPORTED = 0x08

# Maximum username/password length to prevent DoS
MAX_AUTH_LEN = 64


class SOCKS5Handler(BaseHandler):
    """Fake SOCKS5 proxy server."""

    name = "socks5"
    protocols = ["socks5", "socks", "proxy"]
    priority = 22
    is_fallback = False

    @classmethod
    def match(cls, preamble: bytes) -> bool:
        """Detect SOCKS5 greeting."""
        if len(preamble) < 3:
            return False

        # Check SOCKS version
        if preamble[0] != SOCKS_VERSION:
            return False

        # Get number of methods
        nmethods = preamble[1]
        if nmethods == 0 or nmethods > 128:
            return False

        # Verify we have enough bytes (or at least 4 for partial match)
        if len(preamble) < 2 + nmethods:
            if len(preamble) < 4:
                return False
            return True  # Partial preamble, let handler deal with it

        return True

    async def handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        preamble: bytes,
        metadata: dict,
    ) -> None:
        """Handle SOCKS5 connection."""
        # Initialize metadata capture
        capture = ConnectionCapture(metadata, "socks5")
        capture.record_event("connection_start", {"preamble_hex": preamble.hex()[:100]})

        try:
            conn_id = metadata.get("connection_id", "?")
            src_ip = metadata.get("src_ip", "?")
            dst_port = metadata.get("dst_port", 0)

            # Parse greeting
            nmethods = preamble[1]
            expected_greeting_len = 2 + nmethods
            if len(preamble) < expected_greeting_len:
                try:
                    missing = await asyncio.wait_for(
                        reader.readexactly(expected_greeting_len - len(preamble)),
                        timeout=5.0,
                    )
                    preamble += missing
                    capture.add_bytes_received(len(missing))
                except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                    capture.record_event("invalid_greeting", {"reason": "partial"})
                    return
            methods = list(preamble[2:2 + nmethods])

            capture.set_extra("auth_methods", methods)
            capture.record_command("greeting", {"nmethods": nmethods, "methods": methods})

            logger.info(
                "[%s] SOCKS5 greeting from %s:%d - methods=%s",
                conn_id,
                src_ip,
                dst_port,
                methods,
            )

            # Select authentication method
            # Prefer no-auth if available, otherwise username/password
            if AUTH_NO_AUTH in methods:
                selected_method = AUTH_NO_AUTH
            elif AUTH_USERNAME_PASSWORD in methods:
                selected_method = AUTH_USERNAME_PASSWORD
            else:
                selected_method = AUTH_NO_ACCEPTABLE

            # Send method selection
            writer.write(bytes([SOCKS_VERSION, selected_method]))
            await writer.drain()
            capture.add_bytes_sent(2)
            capture.record_event("method_selected", {"method": selected_method})
            if selected_method == AUTH_NO_ACCEPTABLE:
                return

            logger.debug("[%s] Selected auth method: %s", conn_id, selected_method)

            # Handle authentication if required
            username = None
            password = None

            if selected_method == AUTH_USERNAME_PASSWORD:
                auth_result = await self._handle_auth(reader, writer, metadata, capture)
                if auth_result:
                    username, password = auth_result
                    capture.set_extra("auth_username", username)
                    capture.record_command("authentication", {"username": username, "success": True})
                else:
                    # Auth failed or client disconnected
                    capture.record_event("auth_failed", {})
                    return

            try:
                request = await self._read_request(reader, capture)
            except asyncio.TimeoutError:
                capture.record_event("timeout", {"stage": "request", "waited_seconds": 30.0})
                logger.debug("[%s] Timeout waiting for SOCKS request", conn_id)
                return
            except (ConnectionResetError, BrokenPipeError):
                capture.record_event("client_disconnected", {"stage": "request"})
                logger.debug("[%s] Client disconnected before request", conn_id)
                return

            if len(request) < 7:
                capture.record_event("invalid_request", {"reason": "too_short", "length": len(request)})
                logger.debug("[%s] Invalid SOCKS request (too short)", conn_id)
                return

            # Parse request
            ver = request[0]
            cmd = request[1]
            rsv = request[2]
            atyp = request[3]

            if ver != SOCKS_VERSION:
                capture.record_event("invalid_request", {"reason": "bad_version", "version": ver})
                logger.debug("[%s] Invalid SOCKS version in request", conn_id)
                return

            # Parse destination address
            offset = 4
            dst_addr = None
            dst_port_num = None

            try:
                if atyp == ATYP_IPV4:
                    # IPv4: 4 bytes
                    dst_addr = socket.inet_ntoa(request[offset:offset + 4])
                    offset += 4
                elif atyp == ATYP_DOMAIN:
                    # Domain: 1 byte length + bytes
                    dlen = request[offset]
                    # Bounds check
                    if offset + 1 + dlen > len(request):
                        logger.debug("[%s] Domain length %d exceeds buffer", conn_id, dlen)
                        dst_addr = "parse_error"
                    else:
                        dst_addr = request[offset + 1:offset + 1 + dlen].decode('utf-8', errors='replace')
                        offset += 1 + dlen
                elif atyp == ATYP_IPV6:
                    # IPv6: 16 bytes
                    dst_addr = socket.inet_ntop(socket.AF_INET6, request[offset:offset + 16])
                    offset += 16
                else:
                    logger.debug("[%s] Unknown address type: %s", conn_id, atyp)
                    dst_addr = f"unknown(atyp={atyp})"

                # Parse port (2 bytes)
                dst_port_num = struct.unpack('>H', request[offset:offset + 2])[0]

            except (IndexError, ValueError, OSError) as e:
                logger.debug("[%s] Error parsing destination: %s", conn_id, e)
                dst_addr = "parse_error"
                dst_port_num = 0

            capture.set_extra("destination", f"{dst_addr}:{dst_port_num}")
            capture.set_extra("command", self._cmd_to_str(cmd))
            capture.record_command("request", {
                "command": self._cmd_to_str(cmd),
                "command_code": cmd,
                "address_type": atyp,
                "destination": dst_addr,
                "port": dst_port_num,
            })

            logger.info(
                "[%s] SOCKS5 request: cmd=%s, target=%s:%s",
                conn_id,
                self._cmd_to_str(cmd),
                dst_addr,
                dst_port_num,
            )

            # Log for dashboard
            stats = metadata.get("stats")
            if stats:
                from honeypot.server import _iso
                stats.add_event({
                    "type": "socks5_request",
                    "timestamp": _iso(metadata.get("timestamp", 0)),
                    "src_ip": src_ip,
                    "command": self._cmd_to_str(cmd),
                    "destination": f"{dst_addr}:{dst_port_num}",
                    "username": username,
                })

            # Build and send reply
            # Always succeed for honeypot purposes
            reply = self._build_reply(REP_SUCCESS, "0.0.0.0", 0)
            writer.write(reply)
            await writer.drain()
            capture.add_bytes_sent(len(reply))
            capture.record_event("reply_sent", {"reply": REP_SUCCESS})

            logger.info("[%s] Sent SOCKS5 success reply", conn_id)

            # Keep connection open and relay data (log only)
            await self._relay_data(reader, writer, metadata, capture)

        finally:
            # Save captured metadata
            await capture.save()

    async def _read_request(
        self,
        reader: asyncio.StreamReader,
        capture: ConnectionCapture,
    ) -> bytes:
        """Read one complete SOCKS5 request, respecting TCP fragmentation."""
        header = await asyncio.wait_for(reader.readexactly(4), timeout=30.0)
        capture.add_bytes_received(len(header))
        atyp = header[3]

        if atyp == ATYP_IPV4:
            tail_len = 4 + 2
        elif atyp == ATYP_IPV6:
            tail_len = 16 + 2
        elif atyp == ATYP_DOMAIN:
            dlen_data = await asyncio.wait_for(reader.readexactly(1), timeout=30.0)
            capture.add_bytes_received(1)
            dlen = dlen_data[0]
            tail = await asyncio.wait_for(reader.readexactly(dlen + 2), timeout=30.0)
            capture.add_bytes_received(len(tail))
            return header + dlen_data + tail
        else:
            tail_len = 2

        tail = await asyncio.wait_for(reader.readexactly(tail_len), timeout=30.0)
        capture.add_bytes_received(len(tail))
        return header + tail

    async def _handle_auth(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        metadata: dict,
        capture: ConnectionCapture,
    ) -> Optional[tuple[str, str]]:
        """Handle username/password authentication."""
        conn_id = metadata.get("connection_id", "?")

        try:
            # Read auth version (1 byte) with timeout
            auth_ver = await asyncio.wait_for(reader.readexactly(1), timeout=5.0)
            if not auth_ver or auth_ver[0] != 0x01:
                capture.record_event("auth_invalid_version", {})
                logger.debug("[%s] Invalid auth version", conn_id)
                return None
            capture.add_bytes_received(1)

            # Read username length with timeout
            ulen_data = await asyncio.wait_for(reader.readexactly(1), timeout=5.0)
            if not ulen_data:
                return None
            ulen = ulen_data[0]
            capture.add_bytes_received(1)

            # Validate username length
            if ulen == 0 or ulen > MAX_AUTH_LEN:
                capture.record_event("auth_invalid_length", {"length": ulen})
                logger.debug("[%s] Invalid username length: %d", conn_id, ulen)
                return None

            # Read username with timeout
            username = await asyncio.wait_for(reader.readexactly(ulen), timeout=5.0)
            if not username or len(username) != ulen:
                return None
            username = username.decode('utf-8', errors='replace')
            capture.add_bytes_received(ulen)

            # Read password length with timeout
            plen_data = await asyncio.wait_for(reader.readexactly(1), timeout=5.0)
            if not plen_data:
                return None
            plen = plen_data[0]
            capture.add_bytes_received(1)

            # Validate password length
            if plen > MAX_AUTH_LEN:
                capture.record_event("auth_invalid_length", {"length": plen})
                logger.debug("[%s] Invalid password length: %d", conn_id, plen)
                return None

            # Read password with timeout
            password = await asyncio.wait_for(reader.readexactly(plen), timeout=5.0)
            if not password or len(password) != plen:
                return None
            password = password.decode('utf-8', errors='replace')
            capture.add_bytes_received(plen)

            # Hash credentials for security (don't log plaintext)
            username_hash = hashlib.sha256(username.encode()).hexdigest()[:8]
            password_hash = hashlib.sha256(password.encode()).hexdigest()[:16]
            logger.warning(
                "[%s] SOCKS5 auth attempt: username_hash=%s..., password_hash=%s...",
                conn_id,
                username_hash,
                password_hash,
            )

            # Record credential harvest
            capture.record_command("credentials", {
                "username_hash": username_hash,
                "password_hash": password_hash,
            })

            stats = metadata.get("stats")
            if stats:
                from honeypot.server import _iso
                stats.add_event({
                    "type": "credential_harvest",
                    "timestamp": _iso(metadata.get("timestamp", 0)),
                    "src_ip": metadata.get("src_ip", "?"),
                    "username_hash": username_hash,
                    "password_hash": password_hash,
                    "protocol": "socks5",
                })

            # Send success response
            writer.write(bytes([0x01, 0x00]))
            await writer.drain()
            capture.add_bytes_sent(2)
            capture.record_event("auth_success", {})

            return (username, password)

        except asyncio.TimeoutError:
            capture.record_event("timeout", {"stage": "auth", "waited_seconds": 5.0})
            logger.debug("[%s] Auth timeout", conn_id)
            return None
        except (ConnectionResetError, BrokenPipeError):
            capture.record_event("client_disconnected", {"stage": "auth"})
            logger.debug("[%s] Auth failed/disconnected", conn_id)
            return None
        except asyncio.IncompleteReadError:
            capture.record_event("client_disconnected", {"stage": "auth"})
            logger.debug("[%s] Auth message was incomplete", conn_id)
            return None

    def _build_reply(self, rep: int, bnd_addr: str, bnd_port: int) -> bytes:
        """Build a SOCKS5 reply message."""
        # For simplicity, always use IPv4 address type
        try:
            addr_bytes = socket.inet_aton(bnd_addr)
            atyp = ATYP_IPV4
        except OSError:
            # Fallback for invalid address
            addr_bytes = socket.inet_aton("0.0.0.0")
            atyp = ATYP_IPV4

        return bytes([
            SOCKS_VERSION,
            rep,
            0x00,  # RSV
            atyp,
        ]) + addr_bytes + struct.pack('>H', bnd_port)

    def _cmd_to_str(self, cmd: int) -> str:
        """Convert command code to string."""
        return {
            CMD_CONNECT: "CONNECT",
            CMD_BIND: "BIND",
            CMD_ASSOCIATE: "ASSOCIATE",
        }.get(cmd, f"UNKNOWN({cmd})")

    async def _relay_data(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        metadata: dict,
        capture: ConnectionCapture,
    ) -> None:
        """Relay and log data from client."""
        conn_id = metadata.get("connection_id", "?")

        try:
            while True:
                data = await asyncio.wait_for(reader.read(4096), timeout=120.0)
                if not data:
                    capture.record_event("connection_closed", {"by": "client"})
                    logger.debug("[%s] Client closed connection", conn_id)
                    break

                capture.add_bytes_received(len(data))
                capture.record_event("data_relayed", {"bytes": len(data)})

                logger.debug(
                    "[%s] SOCKS5 relay: %d bytes from %s",
                    conn_id,
                    len(data),
                    metadata.get("src_ip", "?"),
                )

                # In a real proxy, we'd forward to destination
                # For honeypot, just log and optionally send fake response

        except asyncio.TimeoutError:
            capture.record_event("timeout", {"stage": "relay", "waited_seconds": 120.0})
            logger.debug("[%s] SOCKS5 relay timeout", conn_id)
        except (ConnectionResetError, BrokenPipeError):
            capture.record_event("client_disconnected", {"stage": "relay"})
            logger.debug("[%s] SOCKS5 relay disconnected", conn_id)
        except Exception as e:
            capture.record_event("error", {"stage": "relay", "message": str(e)})
            logger.error("[%s] SOCKS5 relay error: %s", conn_id, e)
