"""Netgear DGN2200/R7000 router simulation honeypot plugin.

Responds to HTTP requests with realistic Netgear admin-panel pages to attract
and observe automated scanners and manual attackers.  All HTTP parsing is done
manually to avoid leaking Python server fingerprints.
"""

from __future__ import annotations

import asyncio
import time
import urllib.parse
from typing import Optional

from honeypot.base_handler import BaseHandler
from honeypot.log import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# HTTP method prefixes used for protocol detection
# ---------------------------------------------------------------------------
_HTTP_METHODS = (
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
)

# ---------------------------------------------------------------------------
# Fake device constants
# ---------------------------------------------------------------------------
_SERVER_HEADER = "NETGEAR DGN2200 Firmware/1.0.0.29"
_FIRMWARE = "V1.0.0.29"
_MODEL = "DGN2200"
_REALM = "NETGEAR DGN2200"

# Netgear OUI prefix (00:14:6C) - suffix generated per-connection to prevent fingerprinting
_NETGEAR_OUI = bytes([0x00, 0x14, 0x6C])

# Control character translation table for log sanitization
_CONTROL_CHAR_TABLE = str.maketrans(
    {c: f"\\x{c:02x}" for c in range(0x20) if c not in (0x09,)}  # keep tab
    | {0x7F: "\\x7f"}
)


def _sanitize_log_str(s: str) -> str:
    """Replace control characters in attacker-supplied strings to prevent log injection."""
    return s.translate(_CONTROL_CHAR_TABLE)


def _generate_mac() -> str:
    """Generate a random MAC address with Netgear OUI prefix to prevent fingerprinting."""
    import os
    random_suffix = os.urandom(3)
    mac_bytes = _NETGEAR_OUI + random_suffix
    return ":".join(f"{b:02X}" for b in mac_bytes)

# ---------------------------------------------------------------------------
# HTML templates
# ---------------------------------------------------------------------------

_LOGIN_PAGE = """\
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>NETGEAR DGN2200 - Login</title>
<style>
body{{background:#2b2b2b;color:#eee;font-family:Arial,sans-serif;margin:0;padding:0}}
.header{{background:#e07800;padding:12px 20px;font-size:20px;font-weight:bold;color:#fff}}
.content{{max-width:400px;margin:60px auto;background:#3a3a3a;padding:30px;border-radius:4px}}
h2{{color:#e07800;margin-top:0}}
label{{display:block;margin-bottom:4px;font-size:13px}}
input[type=text],input[type=password]{{width:100%;padding:8px;margin-bottom:16px;
  background:#555;color:#eee;border:1px solid #666;border-radius:3px;box-sizing:border-box}}
input[type=submit]{{width:100%;padding:10px;background:#e07800;color:#fff;
  border:none;border-radius:3px;cursor:pointer;font-size:14px}}
input[type=submit]:hover{{background:#c96a00}}
.error{{color:#ff6b6b;font-size:13px;margin-bottom:12px}}
.model{{font-size:12px;color:#999;text-align:right;margin-top:16px}}
</style>
</head>
<body>
<div class="header">NETGEAR Router</div>
<div class="content">
<h2>Administrator Login</h2>
{error_block}
<form method="post" action="/login.cgi">
<label>Username</label>
<input type="text" name="username" autocomplete="off">
<label>Password</label>
<input type="password" name="password">
<input type="submit" value="Log In">
</form>
<div class="model">Model: {model} &nbsp;|&nbsp; Firmware: {firmware}</div>
</div>
</body>
</html>"""

_CURRENT_SETTINGS = """\
Model={model}
Firmware={firmware}
MAC={mac}
Ession=A7D8F3B2C1E456
Region=1
AP_MODE=0
wl_mode=0
"""

_FORBIDDEN_PAGE = """\
<!DOCTYPE html>
<html><head><title>403 Forbidden</title></head>
<body><h1>403 Forbidden</h1><p>Access denied.</p>
<hr><small>{server}</small></body></html>"""

_NOT_FOUND_PAGE = """\
<!DOCTYPE html>
<html><head><title>404 Not Found</title>
<style>body{{font-family:Arial;background:#2b2b2b;color:#eee;padding:40px}}
h1{{color:#e07800}}</style>
</head>
<body><h1>404 Not Found</h1><p>The requested page was not found on this router.</p>
<hr><small>{server}</small></body></html>"""

_SETUP_PAGE = """\
<!DOCTYPE html>
<html><head><title>NETGEAR Setup</title>
<style>body{{font-family:Arial;background:#2b2b2b;color:#eee;padding:40px}}
h1{{color:#e07800}}</style>
</head>
<body><h1>Setup Wizard</h1><p>Setup is not available at this time.</p>
<p>Please log in and try again.</p>
<hr><small>{server}</small></body></html>"""

# 1x1 transparent GIF
_FAVICON_GIF = bytes([
    0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00,
    0x01, 0x00, 0x80, 0x00, 0x00, 0xff, 0xff, 0xff,
    0x00, 0x00, 0x00, 0x21, 0xf9, 0x04, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44,
    0x01, 0x00, 0x3b,
])


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------


class HttpNetgearHandler(BaseHandler):
    """Simulate a Netgear DGN2200 / R7000 HTTP admin interface."""

    name = "http_netgear"
    protocols = ["http"]
    priority = 10
    is_fallback = False

    @classmethod
    def match(cls, preamble: bytes) -> bool:
        """Return True if the preamble starts with an HTTP method."""
        return any(preamble.startswith(m) for m in _HTTP_METHODS)

    async def handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        preamble: bytes,
        metadata: dict,
    ) -> None:
        src_ip = metadata.get("src_ip", "?")
        connection_id = metadata.get("connection_id", "?")

        try:
            method, path, headers, body = _parse_http_request(preamble)
        except Exception as exc:
            logger.warning("[%s] Could not parse HTTP request from %s: %s", connection_id, src_ip, exc)
            await _send_response(writer, 400, b"Bad Request", {}, b"Bad Request")
            return

        user_agent = headers.get("user-agent", "-")
        # Strip all control characters to prevent log injection
        path_safe = _sanitize_log_str(path)
        ua_safe = _sanitize_log_str(user_agent)
        logger.info(
            "[%s] HTTP %s %r from %s UA=%r",
            connection_id,
            method,
            path_safe,
            src_ip,
            ua_safe,
        )

        await self._route(writer, method, path, headers, body, metadata)

    async def _route(
        self,
        writer: asyncio.StreamWriter,
        method: str,
        path: str,
        headers: dict,
        body: bytes,
        metadata: dict,
    ) -> None:
        connection_id = metadata.get("connection_id", "?")
        src_ip = metadata.get("src_ip", "?")

        # Strip query string for routing
        path_only = path.split("?")[0].rstrip("/") or "/"

        # POST /login.cgi -- log credentials, always reject
        if method == "POST" and path_only == "/login.cgi":
            creds = _parse_form_body(body)
            username = creds.get("username", "")
            password = creds.get("password", "")
            logger.warning(
                "[%s] LOGIN ATTEMPT from %s username=%r password=%r",
                connection_id,
                src_ip,
                _sanitize_log_str(username),
                _sanitize_log_str(password),
            )
            # Record credential harvest event for dashboard
            stats = metadata.get("stats")
            if stats is not None:
                from honeypot.server import _iso
                stats.add_event({
                    "type": "credential_harvest",
                    "timestamp": _iso(metadata.get("timestamp", 0)),
                    "src_ip": src_ip,
                    "username": username,
                    "password": password,
                })
            html = _LOGIN_PAGE.format(
                error_block='<div class="error">Incorrect username or password.</div>',
                model=_MODEL,
                firmware=_FIRMWARE,
            ).encode()
            # No WWW-Authenticate header - form-based auth only
            await _send_response(writer, 401, b"Unauthorized", {}, html)
            return

        # GET / -- redirect to /start.htm
        if path_only == "/":
            await _send_response(
                writer, 302, b"Found",
                {"Location": "/start.htm"}, b"",
            )
            return

        # Login pages
        if path_only in ("/start.htm", "/login.htm"):
            html = _LOGIN_PAGE.format(
                error_block="",
                model=_MODEL,
                firmware=_FIRMWARE,
            ).encode()
            await _send_response(writer, 200, b"OK", {}, html, content_type="text/html; charset=utf-8")
            return

        # Current settings
        if path_only == "/currentsetting.htm":
            body_out = _CURRENT_SETTINGS.format(
                model=_MODEL, firmware=_FIRMWARE, mac=_generate_mac()
            ).encode()
            await _send_response(writer, 200, b"OK", {}, body_out, content_type="text/plain")
            return

        # CGI bin -- forbidden
        if path_only.startswith("/cgi-bin"):
            html = _FORBIDDEN_PAGE.format(server=_SERVER_HEADER).encode()
            await _send_response(writer, 403, b"Forbidden", {}, html)
            return

        # Setup pages
        if path_only.startswith("/setup.cgi") or path_only.startswith("/BRS_"):
            html = _SETUP_PAGE.format(server=_SERVER_HEADER).encode()
            await _send_response(writer, 200, b"OK", {}, html, content_type="text/html; charset=utf-8")
            return

        # Favicon
        if path_only == "/favicon.ico":
            await _send_response(writer, 200, b"OK", {}, _FAVICON_GIF, content_type="image/gif")
            return

        # 404 for everything else
        html = _NOT_FOUND_PAGE.format(server=_SERVER_HEADER).encode()
        await _send_response(writer, 404, b"Not Found", {}, html)


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------


def _parse_http_request(raw: bytes) -> tuple[str, str, dict[str, str], bytes]:
    """
    Minimal HTTP/1.x request parser.

    Returns (method, path, headers_dict, body_bytes).
    Header names are lowercased.
    """
    # Split headers from body at the blank line
    if b"\r\n\r\n" in raw:
        head, body = raw.split(b"\r\n\r\n", 1)
    elif b"\n\n" in raw:
        head, body = raw.split(b"\n\n", 1)
    else:
        head = raw
        body = b""

    lines = head.split(b"\r\n") if b"\r\n" in head else head.split(b"\n")
    request_line = lines[0].decode("ascii", errors="replace").strip()
    parts = request_line.split(" ")
    if len(parts) < 2:
        raise ValueError(f"Malformed request line: {request_line!r}")

    method = parts[0].upper()
    path = parts[1]

    headers: dict[str, str] = {}
    for line in lines[1:]:
        decoded = line.decode("latin-1", errors="replace").strip()
        if ":" in decoded:
            key, _, value = decoded.partition(":")
            headers[key.strip().lower()] = value.strip()

    return method, path, headers, body


def _parse_form_body(body: bytes) -> dict[str, str]:
    """Parse application/x-www-form-urlencoded body."""
    try:
        text = body.decode("utf-8", errors="replace")
        return dict(urllib.parse.parse_qsl(text))
    except Exception:
        return {}


async def _send_response(
    writer: asyncio.StreamWriter,
    status: int,
    reason: bytes,
    extra_headers: dict,
    body: bytes,
    content_type: str = "text/html; charset=utf-8",
) -> None:
    """Write an HTTP/1.0 response to *writer*."""
    from email.utils import formatdate
    header_lines = [
        f"HTTP/1.0 {status} {reason.decode()}",
        f"Server: {_SERVER_HEADER}",
        f"Date: {formatdate(timeval=None, usegmt=True)}",
        f"Content-Type: {content_type}",
        f"Content-Length: {len(body)}",
        "Connection: close",
    ]
    for key, value in extra_headers.items():
        header_lines.append(f"{key}: {value}")

    header_lines.append("")  # blank line
    header_lines.append("")

    response = "\r\n".join(header_lines).encode("latin-1") + body
    writer.write(response)
    await writer.drain()
