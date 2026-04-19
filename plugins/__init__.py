# honeypot plugins package

# Existing handlers
from honeypot.plugins.http_netgear import HttpNetgearHandler
from honeypot.plugins.http_vuln_scanner import HttpVulnScannerHandler
from honeypot.plugins.llm_fallback import LlmFallbackHandler

# New protocol handlers
from honeypot.plugins.tls_scanner import TlsScannerHandler
from honeypot.plugins.postgresql import PostgreSQLHandler
from honeypot.plugins.socks5 import SOCKS5Handler
from honeypot.plugins.mikrotik_mndp import MikroTikMNDPHandler

__all__ = [
    # Existing
    "HttpNetgearHandler",
    "HttpVulnScannerHandler",
    "LlmFallbackHandler",
    # New
    "TlsScannerHandler",
    "PostgreSQLHandler",
    "SOCKS5Handler",
    "MikroTikMNDPHandler",
]
