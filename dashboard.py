"""HTTP monitoring dashboard for the honeypot system.

Serves a self-contained HTML page (no external assets) that auto-refreshes
stats every 5 seconds via JavaScript fetch calls to ``/api/stats``.

Uses ``aiohttp.web`` which is already a project dependency.
"""

from __future__ import annotations

import heapq
import json
import time
from pathlib import Path
from typing import Optional

from honeypot.log import get_logger

from honeypot.metadata import get_recent_connections

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Dashboard HTML template (self-contained, no external dependencies)
# ---------------------------------------------------------------------------

_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Honeypot Dashboard</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#1a1a2e;color:#e0e0e0;font-family:monospace,monospace;font-size:14px}
header{background:#16213e;padding:14px 24px;border-bottom:2px solid #e07800;
  display:flex;align-items:center;gap:16px}
header h1{color:#e07800;font-size:18px;letter-spacing:1px}
.dot{width:10px;height:10px;border-radius:50%;background:#4caf50;display:inline-block}
.dot.offline{background:#f44336}
main{padding:20px 24px;max-width:1400px}
section{margin-bottom:24px}
h2{color:#e07800;font-size:13px;text-transform:uppercase;letter-spacing:1px;
   margin-bottom:10px;padding-bottom:4px;border-bottom:1px solid #2d2d44}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:12px}
.card{background:#16213e;border:1px solid #2d2d44;border-radius:4px;padding:14px}
.card .label{color:#888;font-size:11px;text-transform:uppercase;letter-spacing:0.5px}
.card .value{color:#e07800;font-size:24px;font-weight:bold;margin-top:4px}
table{width:100%;border-collapse:collapse;background:#16213e;border-radius:4px;
      overflow:hidden}
th{background:#0f3460;color:#e07800;font-size:11px;text-transform:uppercase;
   letter-spacing:0.5px;padding:8px 12px;text-align:left}
td{padding:7px 12px;border-bottom:1px solid #1f2a40;color:#ccc;font-size:12px}
tr:last-child td{border-bottom:none}
tr:hover td{background:#1f2a40}
.tag{display:inline-block;background:#0f3460;color:#7ec8e3;font-size:10px;
     padding:2px 6px;border-radius:3px;margin:1px}
.tag.fallback{background:#3a1a00;color:#e07800}
#events-table td{font-size:11px}
#events-table{table-layout:fixed}
#events-table th:nth-child(1),#events-table td:nth-child(1){width:160px}
#events-table th:nth-child(3),#events-table td:nth-child(3){width:90px}
#events-table th:nth-child(4),#events-table td:nth-child(4){width:110px}
#events-table th:nth-child(5),#events-table td:nth-child(5){width:80px}
#connections-table{margin-top:12px}
#connections-table th:nth-child(1),#connections-table td:nth-child(1){width:100px}
#connections-table th:nth-child(3),#connections-table td:nth-child(3){width:80px}
#connections-table th:nth-child(6),#connections-table td:nth-child(6){width:120px}
#connections-table th:nth-child(7),#connections-table td:nth-child(7){width:80px}
.events-wrap{max-height:360px;overflow-y:auto;border:1px solid #2d2d44;border-radius:4px}
.last-updated{font-size:11px;color:#555;text-align:right;margin-top:8px}
</style>
</head>
<body>
<header>
  <span class="dot" id="status-dot"></span>
  <h1>Honeypot Dashboard</h1>
  <span id="uptime-badge" style="color:#888;font-size:12px"></span>
</header>
<main>
  <section>
    <h2>Summary</h2>
    <div class="grid">
      <div class="card"><div class="label">Uptime</div><div class="value" id="s-uptime">-</div></div>
      <div class="card"><div class="label">Total Connections</div><div class="value" id="s-total">-</div></div>
      <div class="card"><div class="label">Active Now</div><div class="value" id="s-active">-</div></div>
    </div>
  </section>

  <section>
    <h2>Connections by Protocol</h2>
    <table>
      <thead><tr><th>Protocol</th><th>Count</th></tr></thead>
      <tbody id="proto-body"></tbody>
    </table>
  </section>

  <section>
    <h2>Top Source IPs</h2>
    <table>
      <thead><tr><th>IP Address</th><th>Connections</th></tr></thead>
      <tbody id="ip-body"></tbody>
    </table>
  </section>

  <section>
    <h2>Loaded Handlers</h2>
    <table>
      <thead><tr><th>Name</th><th>Protocols</th><th>Type</th><th>Priority</th></tr></thead>
      <tbody id="handler-body"></tbody>
    </table>
  </section>

  <section>
    <h2>Recent Events</h2>
    <div class="events-wrap">
      <table id="events-table">
        <thead><tr><th>Timestamp</th><th>Source IP</th><th>Dst Port</th><th>Protocol</th><th>ID</th></tr></thead>
        <tbody id="events-body"></tbody>
      </table>
    </div>
  </section>

  <section>
    <h2>Captured Connections</h2>
    <div class="events-wrap">
      <table id="connections-table">
        <thead><tr><th>Connection ID</th><th>Start Time</th><th>Duration</th><th>Source IP</th><th>Protocol</th><th>Commands</th><th>Events</th></tr></thead>
        <tbody id="connections-body"></tbody>
      </table>
    </div>
  </section>

  <div class="last-updated">Last updated: <span id="last-updated">never</span></div>
</main>

<script>
function fmtUptime(s) {
  s = Math.floor(s);
  var d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600),
      m = Math.floor((s % 3600) / 60), sec = s % 60;
  if (d > 0) return d + 'd ' + h + 'h ' + m + 'm';
  if (h > 0) return h + 'h ' + m + 'm ' + sec + 's';
  return m + 'm ' + sec + 's';
}
function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
function setTbody(id, rows) {
  document.getElementById(id).innerHTML = rows;
}

async function refresh() {
  var dot = document.getElementById('status-dot');
  try {
    var r = await fetch('/api/stats');
    var d = await r.json();
    dot.className = 'dot';

    document.getElementById('s-uptime').textContent = fmtUptime(d.uptime_seconds);
    document.getElementById('s-total').textContent = d.connections_total;
    document.getElementById('s-active').textContent = d.connections_active;
    document.getElementById('uptime-badge').textContent = 'up ' + fmtUptime(d.uptime_seconds);

    var protoRows = '';
    for (var p in d.connections_by_protocol) {
      protoRows += '<tr><td>' + esc(p) + '</td><td>' + esc(d.connections_by_protocol[p]) + '</td></tr>';
    }
    setTbody('proto-body', protoRows || '<tr><td colspan="2" style="color:#555">No data yet</td></tr>');

    var ipRows = (d.top_source_ips || []).map(function(e) {
      return '<tr><td>' + esc(e.ip) + '</td><td>' + esc(e.count) + '</td></tr>';
    }).join('');
    setTbody('ip-body', ipRows || '<tr><td colspan="2" style="color:#555">No data yet</td></tr>');

    var hRows = (d.handlers || []).map(function(h) {
      var protos = (h.protocols || []).map(function(p) {
        return '<span class="tag">' + esc(p) + '</span>';
      }).join('');
      var type = h.is_fallback
        ? '<span class="tag fallback">fallback</span>'
        : '<span class="tag">detector</span>';
      return '<tr><td>' + esc(h.name) + '</td><td>' + protos + '</td><td>' + type + '</td><td>' + esc(h.priority !== undefined ? h.priority : '-') + '</td></tr>';
    }).join('');
    setTbody('handler-body', hRows || '<tr><td colspan="4" style="color:#555">No handlers loaded</td></tr>');

    var evRows = (d.recent_events || []).slice().reverse().map(function(e) {
      // Handle credential harvest events specially
      if (e.type === 'credential_harvest') {
        return '<tr><td>' + esc(e.timestamp) + '</td><td>' + esc(e.src_ip) + '</td><td>-</td><td><span class="tag">CREDENTIAL HARVEST</span></td><td>' + esc(e.username || '-') + ':' + esc(e.password || '-') + '</td></tr>';
      }
      // Handle scanner probe events
      if (e.event_type === 'scanner_probe') {
        return '<tr><td>' + esc(e.timestamp) + '</td><td>' + esc(e.src_ip) + '</td><td>' +
          esc(e.dst_port) + '</td><td><span class="tag">SCANNER</span></td><td>' + esc(e.connection_id) + '</td></tr>';
      }
      // Regular events
      return '<tr><td>' + esc(e.timestamp) + '</td><td>' + esc(e.src_ip) + '</td><td>' +
        esc(e.dst_port) + '</td><td>' + esc(e.protocol) + '</td><td>' + esc(e.connection_id) + '</td></tr>';
    }).join('');
    setTbody('events-body', evRows || '<tr><td colspan="5" style="color:#555">No events yet</td></tr>');

    // Load captured connections from /api/connections
    loadConnections();

    document.getElementById('last-updated').textContent = new Date().toLocaleTimeString();
  } catch(e) {
    dot.className = 'dot offline';
  }
}

refresh();
setInterval(refresh, 5000);

async function loadConnections() {
  try {
    var r = await fetch('/api/connections');
    var d = await r.json();
    var connRows = (d.connections || []).map(function(c) {
      var cmdCount = (c.commands || []).length;
      var eventCount = (c.events || []).length;
      var duration = c.duration_seconds !== null ? c.duration_seconds + 's' : '-';
      var startTs = c.start_iso ? c.start_iso.replace('T', ' ').substr(0, 19) : '-';
      return '<tr><td>' + esc(c.connection_id) + '</td><td>' + esc(startTs) + '</td><td>' + esc(duration) + '</td><td>' + esc(c.src_ip) + '</td><td><span class="tag">' + esc(c.protocol) + '</span></td><td>' + esc(cmdCount) + '</td><td>' + esc(eventCount) + '</td></tr>';
    }).join('');
    setTbody('connections-body', connRows || '<tr><td colspan="7" style="color:#555">No connections captured yet</td></tr>');
  } catch(e) {
    // Silently fail - connections are optional
  }
}
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# DashboardServer
# ---------------------------------------------------------------------------


class DashboardServer:
    """Lightweight aiohttp-based HTTP monitoring dashboard."""

    def __init__(self, config, registry, stats) -> None:
        """
        Args:
            config: HoneypotConfig instance.
            registry: PluginRegistry instance.
            stats: ServerStats instance.
        """
        self._config = config
        self._registry = registry
        self._stats = stats
        self._runner: Optional[object] = None

    async def start(self) -> None:
        try:
            from aiohttp import web  # noqa: PLC0415
        except ImportError:
            logger.error(
                "aiohttp is not installed -- dashboard will not start. "
                "Install it with: pip install aiohttp"
            )
            return

        host = self._config.dashboard_host
        port = self._config.dashboard_port

        if host not in ("127.0.0.1", "::1", "localhost"):
            logger.warning(
                "Dashboard is bound to %s (not localhost). "
                "This may expose monitoring data publicly!",
                host,
            )

        app = web.Application()
        app.router.add_get("/", self._handle_index)
        app.router.add_get("/api/stats", self._handle_stats)
        app.router.add_get("/api/connections", self._handle_connections)

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, host, port)
        await site.start()
        self._runner = runner

        logger.info("Dashboard listening on http://%s:%d/", host, port)

    async def stop(self) -> None:
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None
        logger.info("Dashboard server stopped")

    # ------------------------------------------------------------------
    # Route handlers
    # ------------------------------------------------------------------

    async def _handle_index(self, request) -> object:
        from aiohttp import web  # noqa: PLC0415
        return web.Response(
            text=_DASHBOARD_HTML,
            content_type="text/html",
            charset="utf-8",
        )

    async def _handle_stats(self, request) -> object:
        from aiohttp import web  # noqa: PLC0415

        stats = self._stats

        # Top source IPs by count descending, top 20 (heapq is O(n log 20) vs full sort)
        top_ips = [
            {"ip": ip, "count": count}
            for count, ip in heapq.nlargest(20, ((v, k) for k, v in stats.connections_by_ip.items()))
        ]

        # Handler info
        handlers_info = [
            {
                "name": cls.name,
                "protocols": cls.protocols,
                "is_fallback": getattr(cls, "is_fallback", False),
                "priority": cls.priority,
            }
            for cls in self._registry.get_all()
        ]

        # Recent events (list copy so it doesn't mutate under us)
        recent = list(stats.recent_events)

        payload = {
            "uptime_seconds": round(stats.uptime, 2),
            "connections_total": stats.connections_total,
            "connections_active": stats.connections_active,
            "connections_by_protocol": dict(stats.connections_by_protocol),
            "top_source_ips": top_ips,
            "handlers": handlers_info,
            "recent_events": recent,
        }

        return web.Response(
            text=json.dumps(payload),
            content_type="application/json",
        )

    async def _handle_connections(self, request) -> object:
        from aiohttp import web  # noqa: PLC0415

        if self._config.metadata_enabled:
            connections = await get_recent_connections(
                limit=50,
                storage_dir=Path(self._config.metadata_storage_dir),
            )
        else:
            connections = []

        payload = {"connections": connections}

        return web.Response(
            text=json.dumps(payload),
            content_type="application/json",
        )
