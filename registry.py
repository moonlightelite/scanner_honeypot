"""Plugin registry for honeypot handler management."""

from __future__ import annotations

import asyncio
import importlib
import inspect
from typing import Optional

from honeypot.base_handler import BaseHandler
from honeypot.log import get_logger

logger = get_logger(__name__)


class PluginRegistry:
    """
    Registry of BaseHandler subclasses loaded as plugins.

    Thread-safety note: all public methods acquire ``_lock`` before mutating
    internal state.  Since we run in a single-threaded asyncio event loop this
    prevents concurrent reloads triggered by the admin socket from corrupting
    the handler dict.
    """

    def __init__(self) -> None:
        # name -> handler class
        self._handlers: dict[str, type[BaseHandler]] = {}
        # name -> module path (needed for reload)
        self._module_paths: dict[str, str] = {}
        self._lock = asyncio.Lock()
        self._detector = None  # Set by server for cache invalidation

    def set_detector(self, detector) -> None:
        """Set reference to ProtocolDetector for cache invalidation."""
        self._detector = detector

    def _invalidate_detector_cache(self) -> None:
        """Invalidate the detector's cached sorted list."""
        if self._detector is not None:
            self._detector.invalidate_cache()

    async def load(self, module_path: str) -> str:
        """
        Import *module_path* and register the BaseHandler subclass found there.

        Returns:
            The handler's ``name`` attribute.

        Raises:
            ValueError: If a handler with the same name is already registered,
                        if no BaseHandler subclass is found, or if the
                        discovered class lacks a non-empty ``name``.
        """
        loop = asyncio.get_running_loop()
        async with self._lock:
            # Run blocking import in executor to avoid blocking event loop
            module = await loop.run_in_executor(
                None, importlib.import_module, module_path
            )

            handler_cls = self._find_handler_class(module)
            if handler_cls is None:
                raise ValueError(f"No BaseHandler subclass found in module '{module_path}'")

            if not handler_cls.name:
                raise ValueError(
                    f"Handler class {handler_cls.__qualname__} in '{module_path}' "
                    "has an empty 'name' attribute"
                )

            if handler_cls.name in self._handlers:
                raise ValueError(
                    f"A handler named '{handler_cls.name}' is already registered"
                )

            self._handlers[handler_cls.name] = handler_cls
            self._module_paths[handler_cls.name] = module_path
            self._invalidate_detector_cache()
            logger.info("Loaded handler '%s' from '%s'", handler_cls.name, module_path)
            return handler_cls.name

    async def unload(self, name: str) -> None:
        """Remove handler *name* from the registry.

        Raises:
            KeyError: If no handler with *name* is registered.
        """
        async with self._lock:
            self._unload_unlocked(name)

    def _unload_unlocked(self, name: str) -> None:
        if name not in self._handlers:
            raise KeyError(f"No handler named '{name}' is registered")
        del self._handlers[name]
        del self._module_paths[name]
        self._invalidate_detector_cache()
        logger.info("Unloaded handler '%s'", name)

    async def reload(self, name: str) -> None:
        """Unload and re-import handler *name*.

        The module is re-imported via ``importlib.reload`` so that code changes
        on disk are picked up.

        Raises:
            KeyError: If no handler with *name* is registered.
            ValueError: If the reloaded module fails validation (syntax error, etc.)
        """
        async with self._lock:
            if name not in self._module_paths:
                raise KeyError(f"No handler named '{name}' is registered")
            module_path = self._module_paths[name]

            # Load new module FIRST (before unloading) to catch syntax errors
            # This prevents permanently losing the handler on reload failure
            loop = asyncio.get_running_loop()
            new_module = await loop.run_in_executor(
                None, importlib.import_module, module_path
            )
            await loop.run_in_executor(None, importlib.reload, new_module)

            # Validate the new module before swapping
            handler_cls = self._find_handler_class(new_module)
            if handler_cls is None:
                raise ValueError(f"No BaseHandler subclass found in module '{module_path}'")
            if not handler_cls.name:
                raise ValueError(
                    f"Handler class {handler_cls.__qualname__} in '{module_path}' "
                    "has an empty 'name' attribute"
                )

            # Now safe to swap - unload old, register new
            self._unload_unlocked(name)
            self._handlers[handler_cls.name] = handler_cls
            self._module_paths[handler_cls.name] = module_path
            self._invalidate_detector_cache()
            logger.info("Reloaded handler '%s' from '%s'", handler_cls.name, module_path)

    def get_all(self) -> list[type[BaseHandler]]:
        """Return all registered handler classes (unordered)."""
        return list(self._handlers.values())

    def get_fallback(self) -> Optional[type[BaseHandler]]:
        """Return the handler marked as ``is_fallback = True``, or None."""
        for cls in self._handlers.values():
            if getattr(cls, "is_fallback", False):
                return cls
        return None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _find_handler_class(module) -> Optional[type[BaseHandler]]:
        """Find the concrete BaseHandler subclass defined in *module*.

        Raises:
            ValueError: If multiple handler classes are found in the module.
        """
        handlers = []
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, BaseHandler)
                and obj is not BaseHandler
                and obj.__module__ == module.__name__
            ):
                handlers.append(obj)

        if len(handlers) > 1:
            handler_names = [cls.__name__ for cls in handlers]
            raise ValueError(
                f"Module '{module.__name__}' contains multiple handler classes: {handler_names}. "
                "Only one handler class per module is supported."
            )

        return handlers[0] if handlers else None
