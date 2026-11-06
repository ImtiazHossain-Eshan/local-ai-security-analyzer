"""
Model Service managing the local llama.cpp server runtime.
Strictly enforces single model instance, 2 CPU threads, 2048 context limit,
and single-worker concurrency via an async lock.
"""
import os
import time
import json
import asyncio
import psutil
import subprocess
from pathlib import Path
from typing import Optional, Dict, Any, List
import httpx

from app.config import settings

class ModelService:
    def __init__(self):
        self.server_process: Optional[subprocess.Popen] = None
        self.server_port = settings.llama_server_port
        self.base_url = f"http://127.0.0.1:{self.server_port}"
        self.lock = asyncio.Lock()
        self._is_ready = False

    @property
    def is_downloaded(self) -> bool:
        return settings.model_path.exists() and settings.model_path.stat().st_size > 500_000_000

    @property
    def is_available(self) -> bool:
        server_exe = settings.llama_bin_dir / "llama-server.exe"
        return self.is_downloaded and server_exe.exists()

    def get_server_rss_mb(self) -> float:
        """Measure actual RSS memory consumption of the llama-server process."""
        if not self.server_process or self.server_process.poll() is not None:
            return 0.0
        try:
            proc = psutil.Process(self.server_process.pid)
            mem = proc.memory_info().rss
            for child in proc.children(recursive=True):
                mem += child.memory_info().rss
            return round(mem / (1024 * 1024), 2)
        except Exception:
            return 0.0

    async def check_health(self) -> bool:
        """Check if llama-server is listening and ready for requests."""
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.get(f"{self.base_url}/health")
                if resp.status_code == 200:
                    self._is_ready = True
                    return True
        except Exception:
            pass
        self._is_ready = False
        return False

    async def ensure_running(self) -> bool:
        """Start llama-server subprocess if not already running."""
        if await self.check_health():
            return True

        if not self.is_available:
            return False

        server_exe = settings.llama_bin_dir / "llama-server.exe"
        cmd = [
            str(server_exe),
            "-m", str(settings.model_path),
            "-c", str(settings.model_context_limit),
            "-t", str(settings.cpu_threads),
            "--host", "127.0.0.1",
            "--port", str(self.server_port),
            "-np", "1"  # Strict single slot for 1 simultaneous request
        ]

        # Launch process with stdout/stderr suppressed to prevent pipe buffer deadlocks
        self.server_process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        # Poll health for up to 15 seconds
        for _ in range(30):
            await asyncio.sleep(0.5)
            if await self.check_health():
                return True
            if self.server_process.poll() is not None:
                break

        return False

    def stop_server(self):
        """Terminate the server process gracefully on app shutdown."""
        if self.server_process and self.server_process.poll() is None:
            try:
                self.server_process.terminate()
                self.server_process.wait(timeout=3.0)
            except Exception:
                try:
                    self.server_process.kill()
                except Exception:
                    pass
        self._is_ready = False
        self.server_process = None

    async def get_status(self) -> Dict[str, Any]:
        """Comprehensive status reporting for health endpoints and dashboard."""
        healthy = await self.check_health()
        rss_mb = self.get_server_rss_mb()
        total_sys_ram = round(psutil.virtual_memory().total / (1024 * 1024), 2)
        avail_sys_ram = round(psutil.virtual_memory().available / (1024 * 1024), 2)

        return {
            "model_name": settings.model_name,
            "downloaded": self.is_downloaded,
            "available": self.is_available,
            "loaded": healthy,
            "ready": healthy,
            "context_limit": settings.model_context_limit,
            "cpu_threads": settings.cpu_threads,
            "active_pid": self.server_process.pid if (self.server_process and self.server_process.poll() is None) else None,
            "model_memory_rss_mb": rss_mb,
            "system_available_ram_mb": avail_sys_ram,
            "system_total_ram_mb": total_sys_ram,
            "safety_margin_tokens": settings.safety_margin_tokens,
            "reserved_output_tokens": settings.reserved_output_tokens
        }

    async def generate_completion(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int = 350,
        temperature: float = 0.1,
        timeout_seconds: float = 60.0
    ) -> Dict[str, Any]:
        """
        Execute model inference protected by concurrency lock.
        Processes strictly ONE model request at a time.
        """
        if not await self.ensure_running():
            raise RuntimeError("Local AI Model server is not running and could not be started.")

        payload = {
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": False
        }

        async with self.lock:
            start_time = time.perf_counter()
            async with httpx.AsyncClient(timeout=timeout_seconds) as client:
                response = await client.post(
                    f"{self.base_url}/v1/chat/completions",
                    json=payload
                )

            duration_ms = int((time.perf_counter() - start_time) * 1000)

            if response.status_code != 200:
                raise RuntimeError(f"Model inference failed with HTTP {response.status_code}: {response.text}")

            result = response.json()
            choice = result.get("choices", [{}])[0]
            message = choice.get("message", {})
            content = message.get("content", "")
            reasoning = message.get("reasoning_content", "")

            # If content is empty but model put output in reasoning block, extract it
            if not content.strip() and reasoning.strip():
                content = reasoning

            usage = result.get("usage", {})
            return {
                "content": content,
                "reasoning": reasoning,
                "prompt_tokens": usage.get("prompt_tokens", 0),
                "completion_tokens": usage.get("completion_tokens", 0),
                "total_tokens": usage.get("total_tokens", 0),
                "duration_ms": duration_ms
            }

# Singleton model service
model_service = ModelService()
