"""TLS/SSL scanner honeypot plugin.

Responds to TLS handshakes with a fake server handshake to make scanners
think they're talking to a real TLS server. Logs SNI requests and TLS versions.
"""

from __future__ import annotations

import asyncio
import os
import time
from datetime import datetime, timedelta
from typing import Optional

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from honeypot.base_handler import BaseHandler
from honeypot.log import get_logger
from honeypot.metadata import ConnectionCapture

logger = get_logger(__name__)

# TLS record types
TLS_HANDSHAKE = 0x16
TLS_ALERT = 0x15
TLS_CHANGE_CIPHER_SPEC = 0x14
TLS_APPLICATION_DATA = 0x17

# Handshake message types
HS_CLIENT_HELLO = 0x01
HS_SERVER_HELLO = 0x02
HS_CERTIFICATE = 0x0B
HS_SERVER_HELLO_DONE = 0x0E

# TLS versions
TLS_1_0 = (3, 1)
TLS_1_1 = (3, 2)
TLS_1_2 = (3, 3)
TLS_1_3 = (3, 4)


class TlsScannerHandler(BaseHandler):
    """Fake TLS server to trap TLS scanners."""

    name = "tls_scanner"
    protocols = ["tls", "ssl", "https"]
    priority = 20
    is_fallback = False

    # Pre-generated certificate and key (generated eagerly at class definition)
    _private_key: rsa.RSAPrivateKey | None = None
    _certificate: x509.Certificate | None = None
    _cert_der: bytes | None = None
    _cert_lock: asyncio.Lock | None = None

    @classmethod
    def _generate_certificate(cls) -> None:
        """Generate a self-signed certificate for the honeypot."""
        if cls._certificate is not None:
            return  # Already generated

        # Generate RSA key
        cls._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )

        # Create certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Internal"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Honeypot"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Internal Services"),
            x509.NameAttribute(NameOID.COMMON_NAME, "api.internal"),
        ])

        now = datetime.utcnow()
        cls._certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(cls._private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=3650))  # 10 years
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                ]),
                critical=False,
            )
            .sign(cls._private_key, hashes.SHA256(), default_backend())
        )

        # Serialize to DER
        cls._cert_der = cls._certificate.public_bytes(
            encoding=serialization.Encoding.DER
        )

        logger.info("Generated TLS certificate for honeypot")

    @classmethod
    def match(cls, preamble: bytes) -> bool:
        """Detect TLS handshake by ClientHello record."""
        if len(preamble) < 6:
            return False

        # Check for TLS Handshake record (Content Type 0x16)
        if preamble[0] != TLS_HANDSHAKE:
            return False

        # Check TLS version byte (0x03 for TLS 1.x)
        if preamble[1] != 0x03:
            return False

        # Check version is in valid range (TLS 1.0 - TLS 1.3)
        if preamble[2] < 0x01 or preamble[2] > 0x04:
            return False

        # Check for ClientHello handshake type (0x01)
        # Byte 5 is the handshake type (after 3-byte header + 2-byte length)
        if preamble[5] != HS_CLIENT_HELLO:
            return False

        return True

    async def handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        preamble: bytes,
        metadata: dict,
    ) -> None:
        """Handle TLS handshake."""
        # Initialize metadata capture for this connection
        capture = ConnectionCapture(metadata, "tls")
        capture.record_event("connection_start", {"preamble_hex": preamble.hex()[:100]})

        try:
            # Ensure certificate is generated (thread-safe via lock)
            if self._certificate is None:
                if self.__class__._cert_lock is None:
                    self.__class__._cert_lock = asyncio.Lock()
                async with self.__class__._cert_lock:
                    self._generate_certificate()

            conn_id = metadata.get("connection_id", "?")
            src_ip = metadata.get("src_ip", "?")
            dst_port = metadata.get("dst_port", 0)

            # Parse ClientHello
            client_hello_info = self._parse_client_hello(preamble)

            # Record captured metadata
            capture.set_extra("tls_version", client_hello_info.get("tls_version"))
            capture.set_extra("sni", client_hello_info.get("sni"))
            capture.set_extra("cipher_suites", client_hello_info.get("cipher_suites", []))
            capture.set_extra("session_id", client_hello_info.get("session_id", b"").hex())
            capture.record_command("client_hello", client_hello_info)

            # Log the handshake attempt
            logger.info(
                "[%s] TLS handshake from %s:%d - version=TLS%s, SNI=%s, ciphers=%d",
                conn_id,
                src_ip,
                dst_port,
                f"1.{client_hello_info['tls_version']}" if client_hello_info['tls_version'] else "?",
                client_hello_info.get("sni", "none"),
                len(client_hello_info.get("cipher_suites", [])),
            )

            # Record event for dashboard
            stats = metadata.get("stats")
            if stats:
                from honeypot.server import _iso
                stats.add_event({
                    "type": "tls_handshake",
                    "timestamp": _iso(metadata.get("timestamp", 0)),
                    "src_ip": src_ip,
                    "dst_port": dst_port,
                    "tls_version": f"1.{client_hello_info['tls_version']}" if client_hello_info['tls_version'] else "?",
                    "sni": client_hello_info.get("sni"),
                    "cipher_count": len(client_hello_info.get("cipher_suites", [])),
                })

            # Send ServerHello
            await self._send_server_hello(writer, client_hello_info)
            capture.record_event("server_hello_sent", {})

            # Send Certificate
            await self._send_certificate(writer)
            capture.record_event("certificate_sent", {})

            # Send ServerHelloDone
            await self._send_server_hello_done(writer)
            capture.record_event("server_hello_done_sent", {})

            # Wait for client response
            try:
                response = await asyncio.wait_for(reader.read(4096), timeout=10.0)
                if response:
                    capture.add_bytes_received(len(response))
                    capture.record_event("client_response", {"bytes": len(response), "hex": response.hex()[:200]})
                    logger.debug("[%s] Client sent %d bytes after ServerHelloDone", conn_id, len(response))
            except asyncio.TimeoutError:
                capture.record_event("timeout", {"waited_seconds": 10.0})
                logger.debug("[%s] Timeout waiting for client TLS response", conn_id)
            except (ConnectionResetError, BrokenPipeError):
                capture.record_event("client_disconnected", {})
                logger.debug("[%s] Client disconnected during TLS handshake", conn_id)

        finally:
            # Close connection
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

            # Save captured metadata
            await capture.save()

    def _parse_client_hello(self, preamble: bytes) -> dict:
        """Parse ClientHello to extract SNI and other info."""
        # Minimum ClientHello size: TLS header (5) + handshake header (4) + version (2) + random (32) + session_len (1) = 44
        if len(preamble) < 44:
            return {
                "tls_version": preamble[2] if len(preamble) >= 3 else None,
                "sni": None,
                "cipher_suites": [],
                "session_id": b"",
                "random": b"",
            }

        info = {
            "tls_version": preamble[2],  # 0x01-0x04 for TLS 1.0-1.3
            "sni": None,
            "cipher_suites": [],
            "session_id": b"",
            "random": b"",
        }

        try:
            # Skip TLS record header (5 bytes) and handshake header (4 bytes)
            offset = 5  # TLS record header
            handshake_length = (preamble[3] << 8) | preamble[4]
            handshake_offset = 9  # After TLS record + handshake type

            # ClientHello structure:
            #   - Length (4 bytes, but first byte is 0)
            #   - Version (2 bytes)
            #   - Random (32 bytes)
            #   - Session ID length (1 byte)
            #   - Session ID (variable)
            #   - Cipher suites length (2 bytes)
            #   - Cipher suites (variable)
            #   - Compression methods length (1 byte)
            #   - Compression methods (variable)
            #   - Extensions length (2 bytes, optional)
            #   - Extensions (variable)

            offset = 5 + 4  # TLS header + handshake type + length high byte
            # Version in ClientHello (may differ from record version in TLS 1.3)
            hello_version = (preamble[offset] << 8) | preamble[offset + 1]
            offset += 2

            # Random (32 bytes)
            info["random"] = preamble[offset:offset + 32]
            offset += 32

            # Session ID
            session_id_len = preamble[offset]
            offset += 1
            info["session_id"] = preamble[offset:offset + session_id_len]
            offset += session_id_len

            # Cipher suites
            if offset + 2 <= len(preamble):
                cipher_len = (preamble[offset] << 8) | preamble[offset + 1]
                offset += 2
                # Parse cipher suites as 2-byte big-endian values
                info["cipher_suites"] = []
                for i in range(0, cipher_len, 2):
                    if offset + i + 2 <= len(preamble):
                        suite = (preamble[offset + i] << 8) | preamble[offset + i + 1]
                        info["cipher_suites"].append(suite)
                offset += cipher_len

            # Compression methods
            if offset + 1 <= len(preamble):
                comp_len = preamble[offset]
                offset += 1 + comp_len

            # Extensions
            if offset + 2 <= len(preamble):
                ext_len = (preamble[offset] << 8) | preamble[offset + 1]
                offset += 2
                ext_end = offset + ext_len

                # Parse extensions for SNI
                while offset + 4 <= ext_end:
                    ext_type = (preamble[offset] << 8) | preamble[offset + 1]
                    ext_data_len = (preamble[offset + 2] << 8) | preamble[offset + 3]
                    offset += 4

                    # SNI extension (type 0)
                    if ext_type == 0 and offset + ext_data_len <= len(preamble):
                        ext_data = preamble[offset:offset + ext_data_len]
                        # Parse SNI list
                        if len(ext_data) >= 2:
                            sni_list_len = (ext_data[0] << 8) | ext_data[1]
                            sni_offset = 2
                            while sni_offset + 3 < len(ext_data):  # Fixed: < not <=
                                name_type = ext_data[sni_offset]
                                name_len = (ext_data[sni_offset + 1] << 8) | ext_data[sni_offset + 2]
                                sni_offset += 3
                                # Bounds check before reading name
                                if sni_offset + name_len > len(ext_data):
                                    break
                                if name_type == 0:  # Host name
                                    info["sni"] = ext_data[sni_offset:sni_offset + name_len].decode('utf-8', errors='replace')
                                    break
                                sni_offset += name_len
                        break

                    offset += ext_data_len
        except (IndexError, ValueError) as e:
            logger.debug("Error parsing ClientHello: %s", e)

        return info

    async def _send_server_hello(self, writer: asyncio.StreamWriter, client_hello: dict) -> None:
        """Send ServerHello response."""
        # Build ServerHello
        # TLS 1.2 for maximum compatibility
        server_version = TLS_1_2

        # Generate server random (32 bytes: 4 timestamp + 28 random)
        timestamp = int(time.time())
        random_bytes = os.urandom(28)
        server_random = timestamp.to_bytes(4, 'big') + random_bytes

        # Session ID (empty - no session resumption)
        session_id = b""

        offered = set(client_hello.get("cipher_suites", []))
        supported = (0x0035, 0x002F, 0x000A, 0x0005)
        selected_suite = next((suite for suite in supported if suite in offered), 0x002F)
        cipher_suite = selected_suite.to_bytes(2, 'big')

        # Compression: null (0x00)
        compression = bytes([0x00])

        # Build handshake body (version + random + session + cipher + compression)
        handshake_body = (
            server_version[0].to_bytes(1) + server_version[1].to_bytes(1) +
            server_random +
            bytes([len(session_id)]) + session_id +
            cipher_suite +
            compression
        )

        # Build complete handshake with type and 3-byte length
        handshake = (
            bytes([HS_SERVER_HELLO]) +
            len(handshake_body).to_bytes(3, 'big') +
            handshake_body
        )

        # Build TLS record (always use TLS 1.2 version 0x0303 for compatibility)
        record = (
            bytes([TLS_HANDSHAKE]) +
            bytes([0x03, 0x03]) +
            len(handshake).to_bytes(2, 'big') +
            handshake
        )

        writer.write(record)
        await writer.drain()

    async def _send_certificate(self, writer: asyncio.StreamWriter) -> None:
        """Send Certificate message."""
        cert_der = self._cert_der

        # Build certificate list
        # Certificate structure:
        #   - Certificate list length (3 bytes)
        #   - Certificate length (3 bytes)
        #   - Certificate data
        if cert_der is None:
            raise RuntimeError("TLS certificate has not been generated")

        cert_length = len(cert_der)
        cert_list_length = 3 + cert_length
        handshake_body = (
            cert_list_length.to_bytes(3, 'big') +
            cert_length.to_bytes(3, 'big') +
            cert_der
        )

        handshake = (
            bytes([HS_CERTIFICATE]) +
            len(handshake_body).to_bytes(3, 'big') +
            handshake_body
        )

        # Build TLS record (TLS 1.2)
        record = (
            bytes([TLS_HANDSHAKE]) +
            bytes([0x03, 0x03]) +
            len(handshake).to_bytes(2, 'big') +
            handshake
        )

        writer.write(record)
        await writer.drain()

    async def _send_server_hello_done(self, writer: asyncio.StreamWriter) -> None:
        """Send ServerHelloDone message."""
        handshake = bytes([HS_SERVER_HELLO_DONE, 0x00, 0x00, 0x00])

        record = (
            bytes([TLS_HANDSHAKE]) +
            bytes([0x03, 0x03]) +
            len(handshake).to_bytes(2, 'big') +
            handshake
        )

        writer.write(record)
        await writer.drain()
