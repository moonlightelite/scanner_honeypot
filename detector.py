"""Protocol detector that matches incoming preamble bytes to registered handlers."""

from __future__ import annotations

import asyncio
from typing import Optional

from honeypot.base_handler import BaseHandler
from honeypot.log import get_logger

logger = get_logger(__name__)


class ProtocolDetector:
    """
    Reads a preamble from an open connection and selects a matching handler.

    The detector iterates over all registered handlers sorted by descending
    ``priority`` and returns the first one whose ``match(preamble)`` returns
    True.  If no handler matches it returns None, meaning the caller should
    use the fallback handler (if any).
    """

    # Cache for sorted handler list - invalidated on registry changes
    _cache: list[type[BaseHandler]] | None = None
    _cache_version: int = 0
    """
    Reads a preamble from an open connection and selects a matching handler.

    The detector iterates over all registered handlers sorted by descending
    ``priority`` and returns the first one whose ``match(preamble)`` returns
    True.  If no handler matches it returns None, meaning the caller should
    use the fallback handler (if any).
    """

    def __init__(
        self,
        registry,  # PluginRegistry (avoid circular import with type hint)
        preamble_size: int = 4096,
        preamble_timeout: float = 5.0,
    ) -> None:
        self._registry = registry
        self._preamble_size = preamble_size
        self._preamble_timeout = preamble_timeout
        self._local_cache: list[type[BaseHandler]] | None = None
        self._local_cache_version: int = 0

    def invalidate_cache(self) -> None:
        """Invalidate the cached sorted handler list. Call after registry changes."""
        self._local_cache = None
        self._local_cache_version += 1

    async def read_preamble(self, reader: asyncio.StreamReader) -> bytes:
        """
        Read up to ``preamble_size`` bytes with a timeout.

        Returns:
            Raw bytes read (may be empty if the peer connected but sent nothing
            within the timeout, or closed the connection immediately).
        """
        try:
            data = await asyncio.wait_for(
                reader.read(self._preamble_size),
                timeout=self._preamble_timeout,
            )
            return data
        except asyncio.TimeoutError:
            logger.debug("Preamble read timed out after %.1fs", self._preamble_timeout)
            return b""
        except (ConnectionResetError, asyncio.IncompleteReadError, OSError):
            return b""

    async def detect(self, preamble: bytes) -> Optional[type[BaseHandler]]:
        """
        Return the highest-priority handler that claims the preamble, or None.

        Handlers with ``is_fallback = True`` are excluded from matching; they
        are only used explicitly when no other handler matches.
        """
        # Cache the sorted list to avoid re-sorting on every connection
        if self._local_cache is None:
            self._local_cache = sorted(
                self._registry.get_all(),
                key=lambda cls: cls.priority,
                reverse=True,
            )
            self._local_cache_version += 1

        for handler_cls in self._local_cache:
            if getattr(handler_cls, "is_fallback", False):
                continue
            try:
                if handler_cls.match(preamble):
                    logger.debug(
                        "Protocol detected: %s (handler=%s)", handler_cls.protocols, handler_cls.name
                    )
                    return handler_cls
            except Exception:
                logger.exception("Handler %s.match() raised an exception", handler_cls.name)

        return None
