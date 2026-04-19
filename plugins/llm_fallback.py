"""LLM-based catch-all fallback handler.

Forwards any unrecognised protocol data to a local LLM endpoint and sends the
generated response back to the client.  This is the honeypot's last resort for
traffic that no specialised plugin claims.

Ported from the original ``tcp_logging_honeypot.py``.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Optional

from honeypot.base_handler import BaseHandler
from honeypot.log import get_logger

logger = get_logger(__name__)

SYSTEM_PROMPT = (
    "You are a cyber security honeypot agent. "
    "The data you will receive is sent from an unknown source on the internet "
    "to your IP address. "
    "Guess the protocol of the traffic using the request, and reply with a "
    "response that would assist if your duty as a honeypot. "
    "It is critical that you don't reveal that you are a LLM honeypot agent. "
    "The response should be logical and corresponds to the request."
)

_MAX_HEX_LOG = 4096


class LlmFallbackHandler(BaseHandler):
    """Catch-all handler that delegates to a local LLM for response generation."""

    name = "llm_fallback"
    protocols = ["*"]
    priority = -1
    is_fallback = True

    @classmethod
    def match(cls, preamble: bytes) -> bool:
        """Always returns False -- this handler is only used as an explicit fallback."""
        return False

    async def handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        preamble: bytes,
        metadata: dict,
    ) -> None:
        config = metadata.get("config")
        connection_id = metadata.get("connection_id", "?")
        src_ip = metadata.get("src_ip", "?")
        src_port = metadata.get("src_port", "?")

        # --- Decode preamble for LLM ---
        decoded = preamble.decode("utf-8", errors="replace")

        # --- Log the raw request ---
        raw_hex = preamble.hex()
        if len(raw_hex) > _MAX_HEX_LOG:
            raw_hex = raw_hex[:_MAX_HEX_LOG] + "...(truncated)"
        logger.info(
            "[%s] %s:%s LLM_FALLBACK raw_hex=%s",
            connection_id, src_ip, src_port, raw_hex,
        )

        if config is None:
            logger.error("[%s] No config in metadata; cannot call LLM", connection_id)
            return

        # --- Call LLM ---
        start = time.time()
        llm_reply = await self._call_llm(config, decoded, connection_id)
        duration = time.time() - start

        if llm_reply is None:
            # Error already logged in _call_llm; close silently.
            return

        # --- Log the response ---
        safe_reply = llm_reply.replace("\r", "\\r").replace("\n", "\\n").replace("\x00", "\\x00")
        if len(safe_reply) > _MAX_HEX_LOG:
            safe_reply = safe_reply[:_MAX_HEX_LOG] + "...(truncated)"
        logger.info(
            "[%s] %s:%s LLM_RESPONSE=%s LLM_TIME=%.3fs",
            connection_id, src_ip, src_port, safe_reply, duration,
        )

        # --- Send response ---
        try:
            writer.write(llm_reply.encode("utf-8"))
            await writer.drain()
        except (BrokenPipeError, ConnectionResetError, OSError):
            logger.debug("[%s] Client disconnected before LLM response was sent", connection_id)

    async def _call_llm(self, config, user_message: str, connection_id: str) -> Optional[str]:
        """POST to the LLM chat completions endpoint and return the reply text."""
        try:
            import aiohttp  # noqa: PLC0415
        except ImportError:
            logger.error(
                "[%s] aiohttp is not installed; cannot call LLM. "
                "Install it with: pip install aiohttp",
                connection_id,
            )
            return None

        payload = {
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_message},
            ],
            "temperature": 0.7,
            "max_tokens": 3000,
        }
        if config.llm_model:
            payload["model"] = config.llm_model

        logger.debug("[%s] Posting to LLM endpoint %s", connection_id, config.llm_endpoint)

        try:
            timeout = aiohttp.ClientTimeout(total=config.llm_timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(
                    config.llm_endpoint,
                    headers={"Content-Type": "application/json"},
                    data=json.dumps(payload),
                ) as resp:
                    resp_json = await resp.json(content_type=None)
                    reply: str = resp_json["choices"][0]["message"]["content"]
                    return reply
        except asyncio.TimeoutError:
            logger.warning("[%s] LLM request timed out after %.1fs", connection_id, config.llm_timeout)
            return None
        except Exception as exc:
            logger.warning("[%s] LLM request failed: %s", connection_id, exc)
            return None
