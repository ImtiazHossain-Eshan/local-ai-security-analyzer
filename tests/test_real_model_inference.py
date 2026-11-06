"""
Optional real model integration test.
Runs actual local inference on Qwen3.5-0.8B via llama.cpp CPU runner.
"""
import pytest
import asyncio
from pathlib import Path
from app.services.model_service import model_service
from app.services.json_parser import parse_and_validate_chunk_response
from app.config import settings

def test_live_local_model_inference():
    if not model_service.is_available:
        pytest.skip("Local model binary or weights not found on system.")

    async def _run():
        # Start model runtime
        started = await model_service.ensure_running()
        assert started is True, "llama-server must start and respond to health check"

        status = await model_service.get_status()
        assert status["ready"] is True
        assert status["model_name"] == settings.model_name
        assert status["context_limit"] == 2048

        messages = [
            {
                "role": "system",
                "content": "You are a cybersecurity analyst. Output JSON only matching: {\"chunk_id\": 1, \"findings\": []}"
            },
            {
                "role": "user",
                "content": "Log chunk 1:\n[Line 1] 2026-11-01 401 invalid_password admin from 203.0.113.44"
            }
        ]

        resp = await model_service.generate_completion(messages, max_tokens=150, temperature=0.1)
        assert resp["duration_ms"] > 0
        assert "findings" in resp["content"] or "findings" in resp["reasoning"]

        # Test parser on real response
        parsed = parse_and_validate_chunk_response(resp["content"], chunk_id=1, start_line=1, end_line=1)
        assert parsed.chunk_id == 1

        # Measure memory
        rss_mb = model_service.get_server_rss_mb()
        print(f"\n[+] Real Model Inference Succeeded! Latency: {resp['duration_ms']}ms, Model RSS RAM: {rss_mb} MB")
        assert rss_mb < 2000  # Well within the 4000 MB constraint

    asyncio.run(_run())
