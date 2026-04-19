"""Logging helpers for the honeypot system.

The module is named ``log`` (not ``logging``) to avoid shadowing the stdlib
``logging`` module.

Usage::

    from honeypot.log import get_logger
    logger = get_logger(__name__)
"""

from __future__ import annotations

import logging
import logging.handlers
import sys

_STDOUT_FORMAT = "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"
_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"

# Track which loggers have already been configured so we don't add duplicate
# handlers across multiple calls to get_logger().
_configured: set[str] = set()


def get_logger(name: str, *, syslog: bool = False) -> logging.Logger:
    """
    Return a configured Logger for *name*.

    Adds a stdout handler with a structured format on the first call for a
    given name.  If *syslog* is True and ``/dev/log`` is available, also
    attaches a SysLogHandler.
    """
    logger = logging.getLogger(name)

    if name in _configured:
        return logger

    _configured.add(name)
    logger.setLevel(logging.DEBUG)

    # Stdout handler
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setLevel(logging.DEBUG)
    stdout_handler.setFormatter(logging.Formatter(_STDOUT_FORMAT, datefmt=_DATE_FORMAT))
    logger.addHandler(stdout_handler)

    # Optional syslog handler
    if syslog:
        try:
            syslog_handler = logging.handlers.SysLogHandler(address="/dev/log")
            syslog_handler.setLevel(logging.INFO)
            syslog_handler.setFormatter(logging.Formatter("%(name)s: %(message)s"))
            logger.addHandler(syslog_handler)
        except (OSError, AttributeError):
            # /dev/log not available (e.g., non-Linux or running in a container
            # without syslog).  Log a warning on stderr and continue.
            print(
                "WARNING: syslog handler requested but /dev/log is not available; "
                "falling back to stdout only.",
                file=sys.stderr,
            )

    return logger


def log_connection(
    logger: logging.Logger,
    metadata: dict,
    protocol: str,
    raw_hex: str,
) -> None:
    """
    Emit a structured connection log line.

    Args:
        logger: Logger instance to use.
        metadata: Connection metadata dict (src_ip, src_port, dst_ip, dst_port,
                  connection_id).
        protocol: Detected or matched protocol name.
        raw_hex: Hex representation of the preamble (may be truncated).
    """
    cid = metadata.get("connection_id", "?")
    src = f"{metadata.get('src_ip', '?')}:{metadata.get('src_port', '?')}"
    dst = f"{metadata.get('dst_ip', '?')}:{metadata.get('dst_port', '?')}"
    logger.info(
        "[%s] %s -> %s protocol=%s raw_hex=%s",
        cid,
        src,
        dst,
        protocol,
        raw_hex,
    )
