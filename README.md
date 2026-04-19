# Scanner Honeypot

A transparent TCP honeypot system with protocol-aware plugin handlers, designed to attract and observe automated scanners and manual attackers.

## Features

- **Protocol-aware detection** - Reads connection preambles and dispatches to specialized handlers based on detected protocols
- **Plugin architecture** - Load, unload, and reload handlers at runtime via admin socket commands
- **Transparent proxy support** - Optional IP_TRANSPARENT support for production deployments
- **LLM fallback** - Unrecognized protocols can be forwarded to a local LLM for dynamic response generation
- **Web dashboard** - Real-time monitoring of connections and events
- **Metadata capture** - JSONL logging of connection metadata for analysis
- **Syslog integration** - Optional syslog logging for centralized log management

## Supported Protocols

| Plugin | Protocols | Description |
|--------|-----------|-------------|
| `http_vuln` | http-vuln | Simulates vulnerable web applications with fake CVE/RCE responses |
| `http_netgear` | http, https | NETGEAR DGN2200 router admin panel simulation |
| `socks5` | socks5, socks, proxy | Open SOCKS5 proxy simulation |
| `postgresql` | postgresql | PostgreSQL database server simulation |
| `mikrotik_mndp` | mikrotik-mndp | MikroTik MNDP/ROMON protocol simulation |
| `tls_scanner` | tls, ssl | TLS/SSL scanner detection and response |
| `llm_fallback` | * | Catch-all handler using LLM for unknown protocols |

## Quick Start

### Installation

```bash
pip install -r requirements.txt
```

### Running the Honeypot

```bash
# Run as a package
python -m honeypot --host 0.0.0.0 --port 23456

# With custom configuration
python -m honeypot \
    --host 0.0.0.0 \
    --port 23456 \
    --dashboard-port 8888 \
    --load-plugin honeypot.plugins.http_vuln_scanner \
    --load-plugin honeypot.plugins.socks5

# With everything enabled and inside a network namespace
ip netns exec nsudp screen -S llm_honeypot python3 -m honeypot \
    --host 127.0.0.1 --port 23456 --dashboard-port 8888 \
    --llm-model "unsloth/Qwen3.5-397B-A17B-GGUF:Q3_K_M" \
    --load-plugin honeypot.plugins.http_netgear \
    --load-plugin honeypot.plugins.http_vuln_scanner \
    --load-plugin honeypot.plugins.tls_scanner \
    --load-plugin honeypot.plugins.postgresql \
    --load-plugin honeypot.plugins.socks5 \
    --load-plugin honeypot.plugins.mikrotik_mndp \
    --load-plugin honeypot.plugins.llm_fallback
```

### Command-Line Options

| Option | Default | Description |
|--------|---------|-------------|
| `--host` | 0.0.0.0 | Bind address for the TCP server |
| `--port` | 23456 | Bind port for the TCP server |
| `--admin-socket` | /tmp/honeypot-admin.sock | Path for admin Unix socket |
| `--llm-endpoint` | (empty) | LLM API endpoint URL |
| `--llm-model` | (empty) | LLM model name |
| `--dashboard-host` | 127.0.0.1 | Dashboard bind address |
| `--dashboard-port` | 8888 | Dashboard HTTP port |
| `--metadata-dir` | /var/log/honeypot | Directory for metadata JSONL files |
| `--load-plugin` | (none) | Module path to load (repeatable) |
| `--no-syslog` | - | Disable syslog output |
| `--no-metadata` | - | Disable metadata capture |
| `--no-dashboard` | - | Disable web dashboard |

## Plugin System

### Built-in Plugins

All plugins are located in the `plugins/` directory:

- **http_vuln_scanner.py** - Responds to common vulnerability probes (PHPunit RCE, ThinkPHP, Log4j, SQL injection, XSS, path traversal, etc.)
- **http_netgear.py** - Simulates a NETGEAR DGN2200 router with realistic admin pages
- **socks5.py** - Fake open SOCKS5 proxy that logs connection attempts
- **postgresql.py** - PostgreSQL wire protocol simulation
- **mikrotik_mndp.py** - MikroTik neighbor discovery protocol
- **tls_scanner.py** - TLS/SSL scanner detection
- **llm_fallback.py** - LLM-powered catch-all handler

### Creating Custom Plugins

Create a new file in `plugins/` with a `BaseHandler` subclass:

```python
from honeypot.base_handler import BaseHandler

class MyHandler(BaseHandler):
    name = "my_protocol"
    protocols = ["myproto"]
    priority = 10
    is_fallback = False

    @classmethod
    def match(cls, preamble: bytes) -> bool:
        return preamble.startswith(b"MYPROTO")

    async def handle(self, reader, writer, preamble, metadata):
        # Handle the connection
        data = await reader.read(1024)
        writer.write(b"Response")
        await writer.drain()
```

## Admin Socket API

The admin Unix socket accepts JSON commands for runtime management:

```bash
# List loaded plugins
echo '{"cmd": "list"}' | socat - UNIX-CONNECT:/tmp/honeypot-admin.sock

# Load a plugin
echo '{"cmd": "load", "module": "honeypot.plugins.socks5"}' | socat - UNIX-CONNECT:/tmp/honeypot-admin.sock

# Unload a plugin
echo '{"cmd": "unload", "name": "socks5"}' | socat - UNIX-CONNECT:/tmp/honeypot-admin.sock

# Reload a plugin (after code changes)
echo '{"cmd": "reload", "name": "socks5"}' | socat - UNIX-CONNECT:/tmp/honeypot-admin.sock

# Get server status
echo '{"cmd": "status"}' | socat - UNIX-CONNECT:/tmp/honeypot-admin.sock
```

### Response Format

```json
// List response
{"ok": true, "handlers": [{"name": "socks5", "protocols": ["socks5"], "priority": 22}]}

// Status response
{"ok": true, "uptime": 3600.5, "connections_total": 150, "connections_active": 3}
```

## Dashboard

The built-in web dashboard (enabled by default on `http://127.0.0.1:8888`) provides:

- Real-time connection statistics
- Protocol distribution charts
- Recent events log
- Per-IP connection counts
- System uptime and metrics

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Honeypot Server                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │
│  │   TCP       │  │  Protocol   │  │   Plugin        │  │
│  │   Listener  │─▶│  Detector   │─▶│   Registry      │  │
│  └─────────────┘  └─────────────┘  └─────────────────┘  │
│         │                │                  │            │
│         ▼                ▼                  ▼            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │
│  │  Metadata   │  │    LLM      │  │   Admin         │  │
│  │  Capture    │  │  Fallback   │  │   Socket        │  │
│  └─────────────┘  └─────────────┘  └─────────────────┘  │
└─────────────────────────────────────────────────────────┘
                              │
                              ▼
                     ┌─────────────────┐
                     │   Dashboard     │
                     │   (Web UI)      │
                     └─────────────────┘
```

## Security Considerations

- **IP_TRANSPARENT** - Requires root/CAP_NET_ADMIN. Falls back gracefully if unavailable
- **Plugin validation** - Only modules under `honeypot.plugins.` or `plugins.` can be loaded
- **Log sanitization** - Control characters in attacker input are escaped to prevent log injection
- **Rate limiting** - LRU eviction prevents OOM from tracking too many IPs

## Requirements

- Python 3.10+
- aiohttp >= 3.9.0
- cryptography >= 39.0.0

## License

MIT License
