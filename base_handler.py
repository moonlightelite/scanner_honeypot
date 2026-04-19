"""Abstract base class for honeypot protocol handlers."""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod


class BaseHandler(ABC):
    """
    Abstract base class that all honeypot protocol handlers must implement.

    Subclasses declare which protocols they handle via class attributes and
    implement the ``handle`` coroutine to process incoming connections.

    Note: Subclasses should define protocols as a class attribute for readability,
    but the instance attribute takes precedence to avoid mutable shared state.
    """

    # Human-readable name used as the registry key (must be unique).
    name: str = ""

    # Protocol identifiers this handler claims (e.g. ["http", "https"]).
    # Subclasses should override this, but each instance gets its own list.
    protocols: list[str] = []

    # Higher priority handlers are checked first during protocol detection.
    priority: int = 0

    # Set to True to mark this handler as the catch-all fallback.
    is_fallback: bool = False

    def __init__(self) -> None:
        # Instance-level protocols list to avoid mutable shared state
        # Subclasses that define protocols = [...] at class level will still work
        # due to attribute lookup, but modifications won't affect other instances
        if not hasattr(self, '_protocols_initialized'):
            self._protocols_initialized = True
            # Copy class-level protocols to instance level if not already a list
            if not isinstance(type(self).__dict__.get('protocols'), list):
                self.protocols = list(self.protocols)

    @classmethod
    def match(cls, preamble: bytes) -> bool:
        """
        Return True if this handler claims the connection based on the preamble.

        The default implementation always returns False; subclasses that want
        to participate in protocol detection must override this method.
        """
        return False

    @abstractmethod
    async def handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        preamble: bytes,
        metadata: dict,
    ) -> None:
        """
        Handle an accepted TCP connection.

        Args:
            reader: Asyncio stream reader for the connection.
            writer: Asyncio stream writer for the connection.
            preamble: Bytes already read during protocol detection.
            metadata: Connection metadata dict with keys:
                - src_ip (str)
                - src_port (int)
                - dst_ip (str)
                - dst_port (int)
                - timestamp (float)
                - connection_id (str)
                - config (HoneypotConfig) -- injected by server
        """
        ...
