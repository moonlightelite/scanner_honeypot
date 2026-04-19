"""Web vulnerability scanner honeypot plugin.

Responds to common CVE/RCE probes with fake vulnerable responses to keep
attackers engaged and observe their TTPs.
"""

from __future__ import annotations

import asyncio
import time
import urllib.parse
from typing import Optional

from honeypot.base_handler import BaseHandler
from honeypot.log import get_logger

logger = get_logger(__name__)

_HTTP_METHODS = (
    b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ",
)

_SERVER_HEADER = "Apache/2.4.41 (Ubuntu) PHP/7.4.3"


def _send_response(
    writer: asyncio.StreamWriter,
    status: int,
    reason: str,
    extra_headers: dict,
    body: bytes,
    content_type: str = "text/html; charset=utf-8",
) -> None:
    from email.utils import formatdate
    header_lines = [
        f"HTTP/1.1 {status} {reason}",
        f"Server: {_SERVER_HEADER}",
        f"Date: {formatdate(timeval=None, usegmt=True)}",
        f"Content-Type: {content_type}",
        f"Content-Length: {len(body)}",
        "Connection: close",
        "X-Powered-By: PHP/7.4.3",
    ]
    for key, value in extra_headers.items():
        header_lines.append(f"{key}: {value}")
    header_lines.append("")
    header_lines.append("")
    response = "\r\n".join(header_lines).encode("latin-1") + body
    writer.write(response)


async def _send_response_async(
    writer: asyncio.StreamWriter,
    status: int,
    reason: str,
    extra_headers: dict,
    body: bytes,
    content_type: str = "text/html; charset=utf-8",
) -> None:
    from email.utils import formatdate
    header_lines = [
        f"HTTP/1.1 {status} {reason}",
        f"Server: {_SERVER_HEADER}",
        f"Date: {formatdate(timeval=None, usegmt=True)}",
        f"Content-Type: {content_type}",
        f"Content-Length: {len(body)}",
        "Connection: close",
        "X-Powered-By: PHP/7.4.3",
    ]
    for key, value in extra_headers.items():
        header_lines.append(f"{key}: {value}")
    header_lines.append("")
    header_lines.append("")
    response = "\r\n".join(header_lines).encode("latin-1") + body
    writer.write(response)
    await writer.drain()


class HttpVulnScannerHandler(BaseHandler):
    """Fake vulnerable web app to trap vulnerability scanners."""

    name = "http_vuln"
    protocols = ["http-vuln"]
    priority = 15  # Higher than netgear (10), catches vuln probes first
    is_fallback = False

    @classmethod
    def match(cls, preamble: bytes) -> bool:
        if not any(preamble.startswith(m) for m in _HTTP_METHODS):
            return False
        # Check for common vulnerability probe patterns
        vuln_patterns = [
            b"phpunit",
            b"eval-stdin",
            b"think",
            b"invokefunction",
            b"call_user_func",
            b"pearcmd",
            b"containers/json",
            b".env",
            b"wp-config",
            b"shell",
            b"cmd=",
            b"exec=",
            b"system(",
            b"passthru(",
            b"../",
            b"..\\",
            b"%00",
            b"<script>",
            b"SELECT%20",
            b"UNION%20",
            b"etc/passwd",
            b"etc/shadow",
            # Additional common vulnerability probes
            b"actuator",
            b"swagger",
            b"api-docs",
            b"graphql",
            b"solr/",
            b"jmx-console",
            b"admin-console",
            b"web-console",
            b"jboss",
            b"struts",
            b"ognl",
            b"runtime",
            b"webdav",
            b"cgi-bin",
            b".git/",
            b".svn",
            b"backup.",
            b"dump.",
            b"sql.",
            b"database",
            b"mysql",
            b"phpmyadmin",
            b"pma/",
            b"manager/html",
            b"status/full",
            b"server-status",
            b"xmlrpc",
            b"wp-admin",
            b"wp-login",
            b"wp-includes",
            b"wp-content",
            b"woocommerce",
            b"joomla",
            b"administrator",
            b"drupal",
            b"magento",
            b"cgi-bin/test-cgi",
            b"logs/",
            b"access.log",
            b"error.log",
            b"debug",
            b"trace",
            b"actuator/health",
            b"actuator/env",
            b"spring",
            b"log4j",
            b"jndi",
            b"${jndi",
            b"robot.txt",
            b"sitemap.xml",
        ]
        return any(pattern in preamble.lower() for pattern in vuln_patterns)

    async def handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        preamble: bytes,
        metadata: dict,
    ) -> None:
        src_ip = metadata.get("src_ip", "?")
        connection_id = metadata.get("connection_id", "?")

        method, path, headers, body = self._parse_http_request(preamble)
        path_safe = path.rstrip("\r\n")

        logger.warning(
            "[%s] VULN PROBE %s %r from %s",
            connection_id, method, path_safe, src_ip,
        )

        # Record the probe attempt
        stats = metadata.get("stats")
        if stats is not None:
            from honeypot.server import _iso
            stats.add_event({
                "type": "vuln_probe",
                "timestamp": _iso(metadata.get("timestamp", 0)),
                "src_ip": src_ip,
                "method": method,
                "path": path_safe,
            })

        # Route to fake vulnerable endpoints
        await self._route(writer, method, path_safe, headers, body, metadata)

    def _parse_http_request(self, raw: bytes) -> tuple:
        if b"\r\n\r\n" in raw:
            head, body = raw.split(b"\r\n\r\n", 1)
        elif b"\n\n" in raw:
            head, body = raw.split(b"\n\n", 1)
        else:
            head, body = raw, b""

        lines = head.split(b"\r\n") if b"\r\n" in head else head.split(b"\n")
        request_line = lines[0].decode("ascii", errors="replace").strip()
        parts = request_line.split(" ")
        method = parts[0].upper() if parts else "GET"
        path = parts[1] if len(parts) > 1 else "/"

        headers = {}
        for line in lines[1:]:
            decoded = line.decode("latin-1", errors="replace").strip()
            if ":" in decoded:
                key, _, value = decoded.partition(":")
                headers[key.strip().lower()] = value.strip()

        return method, path, headers, body

    async def _route(self, writer, method, path, headers, body, metadata):
        path_lower = path.lower()

        # PHPUnit RCE - fake success
        if "phpunit" in path_lower or "eval-stdin" in path_lower:
            await self._phpunit_rce(writer, path, metadata)
            return

        # ThinkPHP RCE
        if "think" in path_lower or "invokefunction" in path_lower:
            await self._thinkphp_rce(writer, path, metadata)
            return

        # PEAR CMD injection
        if "pearcmd" in path_lower:
            await self._pearcmd_injection(writer, path, metadata)
            return

        # Docker API
        if "containers/json" in path_lower:
            await self._docker_api(writer, path, metadata)
            return

        # Path traversal
        if "../" in path or "..\\" in path_lower or "etc/passwd" in path_lower:
            await self._path_traversal(writer, path, metadata)
            return

        # Generic shell/command injection
        if any(x in path_lower for x in ["shell", "cmd=", "exec=", "system(", "passthru("]):
            await self._shell_injection(writer, path, metadata)
            return

        # SQL injection probes
        if any(x in path_lower for x in ["select%20", "union%20", "1=1", "or%201", "drop%20table"]):
            await self._sql_injection(writer, path, metadata)
            return

        # XSS probes
        if "<script>" in path_lower or "javascript:" in path_lower or "onerror=" in path_lower:
            await self._xss_probe(writer, path, metadata)
            return

        # Log4j / JNDI injection
        if "jndi" in path_lower or "log4j" in path_lower or "${" in path:
            await self._log4j_jndi(writer, path, metadata)
            return

        # Spring Boot Actuator
        if "actuator" in path_lower:
            await self._spring_actuator(writer, path, metadata)
            return

        # PHPMyAdmin
        if "phpmyadmin" in path_lower or "/pma/" in path_lower:
            await self._phpmyadmin(writer, path, metadata)
            return

        # .env file exposure
        if "/.env" in path_lower or path_lower.endswith(".env"):
            await self._env_file_probe(writer, path, metadata)
            return

        # WordPress probes
        if "wp-config" in path_lower:
            await self._wp_config_probe(writer, path, metadata)
            return
        if any(x in path_lower for x in ["wp-admin", "wp-login", "wp-content", "wp-includes"]):
            await self._wordpress_probe(writer, path, metadata)
            return

        # Git/SVN exposure
        if ".git/" in path_lower or ".svn" in path_lower:
            await self._git_svn_probe(writer, path, metadata)
            return

        # Database probes
        if any(x in path_lower for x in ["mysql", "database", "sql.", "dump.", "backup."]):
            await self._database_probe(writer, path, metadata)
            return

        # CGI probes
        if "cgi-bin" in path_lower:
            await self._cgi_probe(writer, path, metadata)
            return

        # Default: fake 404
        await self._not_found(writer, path, metadata)

    async def _phpunit_rce(self, writer, path, metadata):
        """Fake PHPUnit RCE response - looks like code executed."""
        src_ip = metadata.get("src_ip", "?")
        logger.info("[%s] PHPUnit RCE probe - returning fake code execution", metadata.get("connection_id"))
        # Return what looks like successful PHP code execution
        body = b"Hello PHPUnit"  # Echo back what the probe expects
        await _send_response_async(writer, 200, "OK", {}, body, "text/plain")

    async def _thinkphp_rce(self, writer, path, metadata):
        """Fake ThinkPHP RCE response."""
        logger.info("[%s] ThinkPHP RCE probe - returning fake output", metadata.get("connection_id"))
        # Fake ThinkPHP debug output
        body = b"""\
<html><head><title>ThinkPHP Debug</title></head>
<body>
<h2>System Information</h2>
<p>ThinkPHP Version: 5.0.24</p>
<p>Server OS: Linux</p>
<p>PHP Version: 7.4.3</p>
<p>Document Root: /var/www/html</p>
</body></html>"""
        await _send_response_async(writer, 200, "OK", {}, body)

    async def _pearcmd_injection(self, writer, path, metadata):
        """Fake PEAR CMD injection response."""
        logger.info("[%s] PEAR CMD injection probe", metadata.get("connection_id"))
        body = b"""
CONFIGURATION:
==============
Auth_SASL Version: 1.0
PEAR Version: 1.10.1
PHP Version: 7.4.3
"""
        await _send_response_async(writer, 200, "OK", {}, body, "text/plain")

    async def _docker_api(self, writer, path, metadata):
        """Fake Docker API response."""
        logger.info("[%s] Docker API probe", metadata.get("connection_id"))
        # Fake Docker container list
        body = b"""[
  {
    "Id": "deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678",
    "Names": ["/redis-cache"],
    "Image": "redis:alpine",
    "State": "running",
    "Status": "Up 47 days",
    "Ports": [{"IP": "0.0.0.0", "PrivatePort": 6379, "PublicPort": 6379, "Type": "tcp"}]
  },
  {
    "Id": "cafebabe1234567890abcdef1234567890abcdef1234567890abcdef12345678",
    "Names": ["/postgres-db"],
    "Image": "postgres:13",
    "State": "running",
    "Status": "Up 47 days",
    "Ports": [{"IP": "0.0.0.0", "PrivatePort": 5432, "PublicPort": 5432, "Type": "tcp"}]
  }
]"""
        await _send_response_async(writer, 200, "OK", {}, body, "application/json")

    async def _path_traversal(self, writer, path, metadata):
        """Fake path traversal response - return fake passwd file."""
        logger.info("[%s] Path traversal probe", metadata.get("connection_id"))
        body = b"""\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
mysql:x:34:34:MySQL Server:/var/lib/mysql:/bin/false
"""
        await _send_response_async(writer, 200, "OK", {}, body, "text/plain")

    async def _shell_injection(self, writer, path, metadata):
        """Fake shell injection response."""
        logger.info("[%s] Shell injection probe", metadata.get("connection_id"))
        body = b"uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"
        await _send_response_async(writer, 200, "OK", {}, body, "text/plain")

    async def _not_found(self, writer, path, metadata):
        """Generic 404 response."""
        body = b"""<!DOCTYPE html>
<html><head><title>404 Not Found</title></head>
<body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at 192.0.2.1 Port 80</address>
</body></html>"""
        await _send_response_async(writer, 404, "Not Found", {}, body)

    async def _sql_injection(self, writer, path, metadata):
        """Fake SQL injection response - looks like SQL error."""
        logger.info("[%s] SQL injection probe", metadata.get("connection_id"))
        body = b"""<html><head><title>Database Error</title></head>
<body>
<h2>SQL Syntax Error</h2>
<p>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near the injected payload.</p>
<p>MySQL Version: 5.7.32</p>
</body></html>"""
        await _send_response_async(writer, 500, "Internal Server Error", {}, body)

    async def _xss_probe(self, writer, path, metadata):
        """Fake XSS vulnerability response."""
        logger.info("[%s] XSS probe", metadata.get("connection_id"))
        body = b"""<html><head><title>Search Results</title></head>
<body>
<h1>Search Results</h1>
<p>Your search term was: <script>alert('XSS')</script></p>
<p>The above content reflects your input to simulate reflected XSS.</p>
</body></html>"""
        await _send_response_async(writer, 200, "OK", {}, body)

    async def _log4j_jndi(self, writer, path, metadata):
        """Fake Log4j/JNDI vulnerability response."""
        logger.info("[%s] Log4j/JNDI probe", metadata.get("connection_id"))
        body = b"""ERROR StatusLogger JNDI lookup initiated
Looking up: ldap://attacker-server.com/exploit
Connection established to ldap://attacker-server.com:389
Attempting to load class: Exploit
Class loaded successfully
"""
        await _send_response_async(writer, 500, "Internal Server Error", {}, body, "text/plain")

    async def _spring_actuator(self, writer, path, metadata):
        """Fake Spring Boot Actuator response."""
        logger.info("[%s] Spring Actuator probe", metadata.get("connection_id"))
        body = b"""{
  "status": "UP",
  "components": {
    "diskSpace": {"status": "UP", "total": 524288000, "free": 209715200},
    "db": {"status": "UP", "database": "MySQL", "version": "5.7.32"},
    "redis": {"status": "UP", "host": "redis-cache", "port": 6379},
    "mail": {"status": "UP", "location": "smtp://mail.internal:25"},
    "ping": {"status": "UP"}
  }
}"""
        await _send_response_async(writer, 200, "OK", {}, body, "application/json")

    async def _phpmyadmin(self, writer, path, metadata):
        """Fake phpMyAdmin login page."""
        logger.info("[%s] phpMyAdmin probe", metadata.get("connection_id"))
        body = b"""<!DOCTYPE html>
<html><head><title>phpMyAdmin 5.0.4</title></head>
<body>
<h1>phpMyAdmin 5.0.4</h1>
<form method="post" action="/index.php">
<label>Username: <input type="text" name="username"></label>
<label>Password: <input type="password" name="password"></label>
<input type="submit" value="Go">
</form>
<p>MySQL 5.7.32 on Linux</p>
</body></html>"""
        await _send_response_async(writer, 200, "OK", {}, body)

    async def _wp_config_probe(self, writer, path, metadata):
        """Fake wp-config.php exposure response."""
        logger.info("[%s] wp-config.php probe", metadata.get("connection_id"))
        body = b"""<?php
// WordPress Configuration File

define('DB_NAME', 'wordpress_db');
define('DB_USER', 'wp_admin');
define('DB_PASSWORD', 'Wp@dmin2023!Secure');
define('DB_HOST', 'localhost:3306');
define('DB_CHARSET', 'utf8mb4');
define('DB_COLLATE', '');

define('AUTH_KEY',         'jK8#mN2$pQ5&rT9!wX3^yZ6*aB4%cD7@');
define('SECURE_AUTH_KEY',  'eF1#gH4$iJ7&kL0!mN3^oP6*qR9%sT2@');
define('LOGGED_IN_KEY',    'uV5#wX8$yZ1&aB4!cD7^eF0*gH3%iJ6@');
define('NONCE_KEY',        'kL9#mN2$oP5&qR8!sT1^uV4*wX7*yZ0@');
define('AUTH_SALT',        'aB3#cD6$eF9&gH2!iJ5^kL8*mN1*oP4@');
define('SECURE_AUTH_SALT', 'qR7#sT0$uV3&wX6!yZ9^aB2*cD5%eF8@');
define('LOGGED_IN_SALT',   'gH1#iJ4$kL7&mN0!oP3^qR6*sT9%uV2@');
define('NONCE_SALT',       'wX5#yZ8$aB1&cD4!eF7^gH0*iJ3*kL6@');

$table_prefix = 'wp_a1b2c3_';

define('WP_DEBUG', false);
define('ABSPATH', '/var/www/html/wordpress/');

// Custom settings
define('WP_MEMORY_LIMIT', '256M');
define('WP_MAX_MEMORY_LIMIT', '512M');
?>"""
        await _send_response_async(writer, 200, "OK", {}, body, "text/plain")

    async def _wordpress_probe(self, writer, path, metadata):
        """Fake WordPress probe response."""
        logger.info("[%s] WordPress probe", metadata.get("connection_id"))
        body = b"""<!DOCTYPE html>
<html><head><title>WordPress Login</title></head>
<body>
<h1>WordPress</h1>
<form method="post" action="/wp-login.php">
<label>Username: <input type="text" name="log"></label>
<label>Password: <input type="password" name="pwd"></label>
<input type="submit" value="Log In">
</form>
<p>Powered by WordPress 5.8.2</p>
</body></html>"""
        await _send_response_async(writer, 200, "OK", {}, body)

    async def _git_svn_probe(self, writer, path, metadata):
        """Fake Git/SVN exposure response."""
        logger.info("[%s] Git/SVN probe", metadata.get("connection_id"))
        if ".git/" in path.lower():
            body = b"""0673a28f4b6e050327e0a0e2f4e0a0e2f4e0a0e2 HEAD
refs/heads/main
refs/heads/develop
refs/tags/v1.0.0
"""
        else:
            body = b"""dir
2
<
D
3648
4e0a0e2f
"""
        await _send_response_async(writer, 200, "OK", {}, body, "text/plain")

    async def _env_file_probe(self, writer, path, metadata):
        """Fake .env file exposure response."""
        logger.info("[%s] .env file probe", metadata.get("connection_id"))
        body = b"""APP_NAME=HoneypotApp
APP_ENV=production
APP_KEY=base64:abc123def456ghi789jkl012mno345pq
APP_DEBUG=false
APP_URL=http://192.0.2.1

LOG_CHANNEL=stack
LOG_DEPRECATIONS_CHANNEL=null
LOG_LEVEL=error

DB_CONNECTION=mysql
DB_HOST=10.0.0.5
DB_PORT=3306
DB_DATABASE=production_db
DB_USERNAME=app_user
DB_PASSWORD=Str0ng_P@ssw0rd!

REDIS_HOST=10.0.0.6
REDIS_PASSWORD=redis_secret
REDIS_PORT=6379

MAIL_MAILER=smtp
MAIL_HOST=smtp.mailgun.org
MAIL_PORT=587
MAIL_USERNAME=noreply@honeypot.app
MAIL_PASSWORD=mail_p@ss123
MAIL_ENCRYPTION=tls
"""
        await _send_response_async(writer, 200, "OK", {}, body, "text/plain")

    async def _database_probe(self, writer, path, metadata):
        """Fake database file exposure response."""
        logger.info("[%s] Database probe", metadata.get("connection_id"))
        body = b"""SQLite format 3
table: users
columns: id, username, email, password_hash
row1: 1, admin, admin@example.com, $2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi
row2: 2, test, test@example.com, $2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi
"""
        await _send_response_async(writer, 200, "OK", {}, body, "text/plain")

    async def _cgi_probe(self, writer, path, metadata):
        """Fake CGI probe response."""
        logger.info("[%s] CGI probe", metadata.get("connection_id"))
        body = b"""Content-Type: text/html

<html><head><title>CGI Test</title></head>
<body>
<h1>CGI Test Succeeded</h1>
<p>Server: Apache/2.4.41 (Ubuntu)</p>
<p>Document Root: /var/www/html</p>
<p>CGI-BIN Path: /usr/lib/cgi-bin</p>
</body></html>"""
        await _send_response_async(writer, 200, "OK", {}, body)
