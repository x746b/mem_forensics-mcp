"""
Memoxide Rust engine client.

Spawns the memoxide binary as a subprocess and communicates via MCP stdio transport
(JSON-RPC 2.0). Provides async methods for all memoxide tools.

If the binary is unavailable or crashes, methods return None to signal
the caller should fall back to Tier 2/3.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


class MemoxideClient:
    """
    Subprocess MCP client for the memoxide Rust binary.

    Spawns memoxide as a child process using stdio MCP transport and sends
    JSON-RPC tool calls. Handles process lifecycle, timeouts, and graceful
    degradation when the binary is unavailable.
    """

    def __init__(
        self,
        binary_path: str | Path | None = None,
        symbols_root: str | Path | None = None,
        call_timeout: float = 30.0,
    ):
        from ..config import MEMOXIDE_BINARY, MEMOXIDE_SYMBOLS

        self._binary_path = Path(binary_path) if binary_path else MEMOXIDE_BINARY
        self._symbols_root = Path(symbols_root) if symbols_root else MEMOXIDE_SYMBOLS
        self._call_timeout = call_timeout
        self._process: Optional[asyncio.subprocess.Process] = None
        self._request_id = 0
        self._initialized = False
        self._lock = asyncio.Lock()
        self._pending: dict[int, asyncio.Future] = {}
        self._reader_task: Optional[asyncio.Task] = None

    @property
    def binary_available(self) -> bool:
        """Check if the memoxide binary exists and is executable."""
        return self._binary_path.exists() and os.access(self._binary_path, os.X_OK)

    def is_available(self) -> bool:
        """Check if memoxide process is running and responsive."""
        if not self.binary_available:
            return False
        if self._process is None:
            return False
        return self._process.returncode is None

    async def start(self) -> bool:
        """
        Start the memoxide subprocess.

        Returns:
            True if started successfully, False otherwise.
        """
        if not self.binary_available:
            logger.warning(f"Memoxide binary not found at {self._binary_path}")
            return False

        if self.is_available():
            return True

        try:
            env = os.environ.copy()
            if self._symbols_root.exists():
                env["MEMOXIDE_SYMBOLS_ROOT"] = str(self._symbols_root)

            self._process = await asyncio.create_subprocess_exec(
                str(self._binary_path),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )

            # Start reader task for responses
            self._reader_task = asyncio.create_task(self._read_responses())

            # Send MCP initialize
            init_result = await self._send_request("initialize", {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "mem_forensics_mcp", "version": "0.1.0"},
            })

            if init_result is not None:
                # Send initialized notification
                await self._send_notification("notifications/initialized", {})
                self._initialized = True
                logger.info("Memoxide engine started successfully")
                return True
            else:
                logger.warning("Memoxide engine failed to initialize")
                await self.stop()
                return False

        except Exception as e:
            logger.error(f"Failed to start memoxide: {e}")
            await self.stop()
            return False

    async def stop(self) -> None:
        """Stop the memoxide subprocess."""
        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
            self._reader_task = None

        if self._process:
            try:
                self._process.terminate()
                try:
                    await asyncio.wait_for(self._process.wait(), timeout=5.0)
                except asyncio.TimeoutError:
                    self._process.kill()
                    await self._process.wait()
            except ProcessLookupError:
                pass
            self._process = None

        self._initialized = False
        # Cancel all pending futures
        for future in self._pending.values():
            if not future.done():
                future.cancel()
        self._pending.clear()

    async def _read_responses(self) -> None:
        """Background task to read JSON-RPC responses from stdout."""
        try:
            while self._process and self._process.returncode is None:
                line = await self._process.stdout.readline()
                if not line:
                    break

                line_str = line.decode("utf-8").strip()
                if not line_str:
                    continue

                try:
                    msg = json.loads(line_str)
                except json.JSONDecodeError:
                    continue

                # Match response to pending request
                msg_id = msg.get("id")
                if msg_id is not None and msg_id in self._pending:
                    future = self._pending.pop(msg_id)
                    if not future.done():
                        if "error" in msg:
                            # Propagate error info instead of silently returning None
                            error_info = msg["error"]
                            if isinstance(error_info, dict):
                                error_msg = error_info.get("message", str(error_info))
                            else:
                                error_msg = str(error_info)
                            future.set_result({"_rust_error": error_msg})
                        else:
                            future.set_result(msg.get("result"))

        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug(f"Reader task error: {e}")

    async def _send_request(self, method: str, params: dict) -> Optional[dict]:
        """Send a JSON-RPC request and wait for response."""
        if not self._process or self._process.returncode is not None:
            return None

        async with self._lock:
            self._request_id += 1
            req_id = self._request_id

        request = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
            "params": params,
        }

        loop = asyncio.get_event_loop()
        future = loop.create_future()
        self._pending[req_id] = future

        try:
            request_bytes = (json.dumps(request) + "\n").encode("utf-8")
            self._process.stdin.write(request_bytes)
            await self._process.stdin.drain()

            result = await asyncio.wait_for(future, timeout=self._call_timeout)
            return result

        except asyncio.TimeoutError:
            self._pending.pop(req_id, None)
            logger.warning(f"Memoxide call timed out: {method}")
            return None
        except Exception as e:
            self._pending.pop(req_id, None)
            logger.warning(f"Memoxide call failed: {method}: {e}")
            return None

    async def _send_notification(self, method: str, params: dict) -> None:
        """Send a JSON-RPC notification (no response expected)."""
        if not self._process or self._process.returncode is not None:
            return

        notification = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        }

        try:
            msg_bytes = (json.dumps(notification) + "\n").encode("utf-8")
            self._process.stdin.write(msg_bytes)
            await self._process.stdin.drain()
        except Exception as e:
            logger.debug(f"Failed to send notification: {e}")

    async def call_tool(self, tool_name: str, params: dict) -> Optional[dict]:
        """
        Call an MCP tool on the memoxide engine.

        Args:
            tool_name: Tool name (e.g., "memory_analyze_image")
            params: Tool parameters

        Returns:
            Tool result dict, or None if call failed
        """
        if not self.is_available():
            if not await self.start():
                return None

        result = await self._send_request("tools/call", {
            "name": tool_name,
            "arguments": params,
        })

        if result is None:
            return None

        # Check for Rust engine error (propagated from _read_responses)
        if isinstance(result, dict) and "_rust_error" in result:
            return {"error": result["_rust_error"], "engine": "rust"}

        # MCP tools return content array - extract text
        content = result.get("content", [])
        if content and isinstance(content, list):
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text":
                    text = item.get("text", "")
                    try:
                        return json.loads(text)
                    except json.JSONDecodeError:
                        return {"raw_text": text}

        return result

    async def analyze_image(
        self,
        image_path: str,
        symbols_root: Optional[str] = None,
        dtb: Optional[str] = None,
        kernel_base: Optional[str] = None,
    ) -> Optional[dict]:
        """
        Call memory_analyze_image to detect profile and create session.

        Returns:
            Session info dict, or None if Rust engine failed.
        """
        params: dict[str, Any] = {"image_path": image_path}
        if symbols_root:
            params["symbols_root"] = symbols_root
        elif self._symbols_root.exists():
            params["symbols_root"] = str(self._symbols_root)
        if dtb:
            params["dtb"] = dtb
        if kernel_base:
            params["kernel_base"] = kernel_base

        return await self.call_tool("memory_analyze_image", params)

    async def run_plugin(
        self,
        session_id: str,
        plugin: str,
        params: Optional[dict] = None,
    ) -> Optional[dict]:
        """
        Call memory_run_plugin on the Rust engine.

        Returns:
            Plugin result dict, or None if failed.
        """
        tool_params: dict[str, Any] = {
            "session_id": session_id,
            "plugin": plugin,
        }
        if params:
            tool_params["params"] = params

        return await self.call_tool("memory_run_plugin", tool_params)

    async def full_triage(self, session_id: str) -> Optional[dict]:
        """
        Call memory_full_triage on the Rust engine.

        Returns:
            Triage result dict, or None if failed.
        """
        return await self.call_tool("memory_full_triage", {"session_id": session_id})

    async def hunt_process_anomalies(self, session_id: str) -> Optional[dict]:
        """Call memory_hunt_process_anomalies."""
        return await self.call_tool("memory_hunt_process_anomalies", {"session_id": session_id})

    async def find_injected_code(self, session_id: str) -> Optional[dict]:
        """Call memory_find_injected_code."""
        return await self.call_tool("memory_find_injected_code", {"session_id": session_id})

    async def find_c2_connections(self, session_id: str) -> Optional[dict]:
        """Call memory_find_c2_connections."""
        return await self.call_tool("memory_find_c2_connections", {"session_id": session_id})

    async def get_command_history(self, session_id: str) -> Optional[dict]:
        """Call memory_get_command_history."""
        return await self.call_tool("memory_get_command_history", {"session_id": session_id})
