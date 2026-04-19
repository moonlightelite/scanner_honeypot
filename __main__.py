"""Entry point for running the honeypot as a package.

Run with:
    python -m honeypot [args...]

Use --help for available options.
"""

from __future__ import annotations

import asyncio
import signal
import sys
from pathlib import Path

from honeypot.admin import AdminServer, ServerStats
from honeypot.config import HoneypotConfig
from honeypot.log import get_logger
from honeypot.metadata import start_capture, stop_capture
from honeypot.registry import PluginRegistry
from honeypot.server import HoneypotServer

async def _run(config: HoneypotConfig) -> None:
    # Initialize logging with syslog setting from config BEFORE any other imports
    logger = get_logger("honeypot", syslog=config.log_to_syslog)

    # Start metadata capture system. It fails open if the storage directory is unavailable.
    if config.metadata_enabled:
        capture = await start_capture(Path(config.metadata_storage_dir))
        if capture.enabled:
            logger.info("Metadata capture started")
        else:
            logger.warning("Metadata capture disabled; continuing without persistent capture")
    else:
        await start_capture(Path(config.metadata_storage_dir), enabled=False)

    stats = ServerStats()
    registry = PluginRegistry()

    # --- Load plugins specified on the command line ---
    for module_path in config.load_plugins:
        try:
            await registry.load(module_path)
            logger.info("Loaded plugin: %s", module_path)
        except Exception as exc:
            logger.error("Failed to load plugin '%s': %s", module_path, exc)

    # --- Create servers ---
    server = HoneypotServer(config, registry, stats=stats)
    admin = AdminServer(config, registry)
    admin.set_stats(stats)

    dashboard = None
    if config.dashboard_enabled:
        try:
            from honeypot.dashboard import DashboardServer  # noqa: PLC0415
            dashboard = DashboardServer(config, registry, stats)
        except Exception as exc:
            logger.warning("Could not create dashboard server: %s", exc)

    # --- Start everything ---
    await server.start()
    await admin.start()
    if dashboard is not None:
        await dashboard.start()

    # --- Set up graceful shutdown ---
    loop = asyncio.get_running_loop()
    shutdown_event = asyncio.Event()

    def _request_shutdown() -> None:
        logger.info("Shutdown signal received")
        shutdown_event.set()

    # Signal handling: SIGINT/SIGTERM on Linux/macOS; KeyboardInterrupt fallback elsewhere.
    if sys.platform != "win32":
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, _request_shutdown)
            except (NotImplementedError, OSError):
                pass

    logger.info("Honeypot running. Press Ctrl+C to stop.")

    try:
        await shutdown_event.wait()
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received")

    # --- Graceful shutdown ---
    logger.info("Shutting down...")
    await server.stop()
    await admin.stop()
    if dashboard is not None:
        await dashboard.stop()
    if config.metadata_enabled:
        await stop_capture()
    logger.info("Shutdown complete")


def main() -> None:
    config = HoneypotConfig.from_cli()

    try:
        asyncio.run(_run(config))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
