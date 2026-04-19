"""MikroTik Neighbor Discovery Protocol (MNDP) honeypot plugin.

Responds to MNDP discovery packets with fake router information to attract
network reconnaissance and identify scanners looking for MikroTik devices.
"""

from __future__ import annotations

import asyncio
import os
import socket
import struct
from typing import Optional

from honeypot.base_handler import BaseHandler
from honeypot.log import get_logger
from honeypot.metadata import ConnectionCapture

logger = get_logger(__name__)

# MNDP message types
MSG_DISCOVERY_REQUEST = 0x0005
MSG_DISCOVERY_REPLY = 0x0005  # Same type, direction inferred

# MNDP attribute types
ATTR_TXID = 0x0001
ATTR_MAC_ADDRESS = 0x0002
ATTR_VERSION = 0x0003
ATTR_MODEL = 0x0005
ATTR_IP_ADDRESS = 0x0007
ATTR_IDENTITY = 0x0010
ATTR_SOFTWARE_ID = 0x0014
ATTR_INTERFACE = 0x0016

# Fake router information
ROUTER_IDENTITY = "MikroTik-Gateway"
ROUTER_MODEL = "RB750Gr3"  # hEX (common model)
ROUTER_VERSION = "6.48.6"  # Stable LTS
ROUTER_IP = "192.168.88.1"  # Default MikroTik IP
ROUTER_SOFTWARE_ID = "A7F3B2C1"  # Random 8-char hex

# MikroTik OUI prefix (00:0C:42) - suffix generated per-connection
_MIKROTIK_OUI = bytes([0x00, 0x0C, 0x42])


def _generate_mac() -> bytes:
    """Generate random MAC with MikroTik OUI to prevent fingerprinting."""
    return _MIKROTIK_OUI + os.urandom(3)


class MikroTikMNDPHandler(BaseHandler):
    """Fake MikroTik router responding to MNDP discovery.

    Real MNDP runs over UDP. The current server is TCP-only, so this handler is
    intentionally disabled for TCP dispatch until the app has a UDP listener.
    """

    name = "mikrotik_mndp"
    protocols = ["mikrotik", "mndp", "mac-telnet"]
    priority = 30
    is_fallback = False

    @classmethod
    def match(cls, preamble: bytes) -> bool:
        """Always returns False — MNDP is UDP-only; disabled for TCP dispatch."""
        return False

    async def handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        preamble: bytes,
        metadata: dict,
    ) -> None:
        """Handle MNDP discovery request."""
        # Initialize metadata capture
        capture = ConnectionCapture(metadata, "mikrotik_mndp")
        capture.record_event("connection_start", {"preamble_hex": preamble.hex()[:100]})

        try:
            conn_id = metadata.get("connection_id", "?")
            src_ip = metadata.get("src_ip", "?")
            dst_port = metadata.get("dst_port", 0)

            # Parse request
            request_info = self._parse_mndp_request(preamble)

            capture.set_extra("txid", request_info.get("txid"))
            capture.set_extra("packet_length", request_info.get("packet_length"))
            capture.record_command("discovery_request", request_info)

            logger.info(
                "[%s] MNDP discovery from %s:%d - txid=%s",
                conn_id,
                src_ip,
                dst_port,
                request_info.get("txid", "?"),
            )

            # Record for dashboard
            stats = metadata.get("stats")
            if stats:
                from honeypot.server import _iso
                stats.add_event({
                    "type": "mndp_discovery",
                    "timestamp": _iso(metadata.get("timestamp", 0)),
                    "src_ip": src_ip,
                    "dst_port": dst_port,
                    "txid": request_info.get("txid"),
                })

            # Build response
            response = self._build_mndp_response(request_info.get("txid"))

            # Send response
            writer.write(response)
            await writer.drain()
            capture.add_bytes_sent(len(response))
            capture.record_event("response_sent", {"size": len(response)})

            logger.debug("[%s] Sent MNDP reply with fake router info", conn_id)

            # Close connection (MNDP is single request/response)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

        finally:
            # Save captured metadata
            await capture.save()

    def _parse_mndp_request(self, preamble: bytes) -> dict:
        """Parse MNDP request packet."""
        info = {
            "txid": None,
            "attributes": {},
        }

        try:
            msg_type = struct.unpack('>H', preamble[0:2])[0]
            pkt_len = struct.unpack('>H', preamble[2:4])[0]

            info["message_type"] = msg_type
            info["packet_length"] = pkt_len

            # Parse TLV attributes
            offset = 4
            while offset + 4 <= len(preamble):
                attr_type = struct.unpack('>H', preamble[offset:offset + 2])[0]
                attr_len = struct.unpack('>H', preamble[offset + 2:offset + 4])[0]
                offset += 4

                # Validate attr_len against remaining buffer AND declared packet length
                if attr_len > len(preamble) - offset or attr_len > pkt_len - offset:
                    break

                attr_value = preamble[offset:offset + attr_len]
                offset += attr_len

                # Parse known attributes
                if attr_type == ATTR_TXID and attr_len == 4:
                    info["txid"] = attr_value.hex()
                elif attr_type == ATTR_MAC_ADDRESS:
                    info["attributes"]["mac"] = attr_value.hex()
                elif attr_type == ATTR_IDENTITY:
                    info["attributes"]["identity"] = attr_value.decode('utf-8', errors='replace')

        except struct.error as e:
            logger.debug("Error parsing MNDP request: %s", e)

        return info

    def _build_mndp_response(self, txid: Optional[str]) -> bytes:
        """Build MNDP discovery reply."""
        tlvs = []

        # TXID (copy from request or generate new)
        if txid:
            txid_bytes = bytes.fromhex(txid)
        else:
            txid_bytes = os.urandom(4)
        tlvs.append(self._build_tlv(ATTR_TXID, txid_bytes))

        # MAC Address (generated per-response to prevent fingerprinting)
        tlvs.append(self._build_tlv(ATTR_MAC_ADDRESS, _generate_mac()))

        # Version
        version_bytes = ROUTER_VERSION.encode('utf-8')
        tlvs.append(self._build_tlv(ATTR_VERSION, version_bytes))

        # Model
        model_bytes = ROUTER_MODEL.encode('utf-8')
        tlvs.append(self._build_tlv(ATTR_MODEL, model_bytes))

        # IP Address
        ip_bytes = socket.inet_aton(ROUTER_IP)
        tlvs.append(self._build_tlv(ATTR_IP_ADDRESS, ip_bytes))

        # Identity
        identity_bytes = ROUTER_IDENTITY.encode('utf-8')
        tlvs.append(self._build_tlv(ATTR_IDENTITY, identity_bytes))

        # Software ID
        swid_bytes = ROUTER_SOFTWARE_ID.encode('utf-8')
        tlvs.append(self._build_tlv(ATTR_SOFTWARE_ID, swid_bytes))

        # Interface
        iface_bytes = b"ether1"
        tlvs.append(self._build_tlv(ATTR_INTERFACE, iface_bytes))

        # Combine all TLVs
        payload = b''.join(tlvs)

        # Build header
        header = struct.pack('>H', MSG_DISCOVERY_REPLY)
        length = struct.pack('>H', len(payload) + 4)

        return header + length + payload

    def _build_tlv(self, attr_type: int, value: bytes) -> bytes:
        """Build a TLV attribute."""
        return (
            struct.pack('>H', attr_type) +
            struct.pack('>H', len(value)) +
            value
        )
