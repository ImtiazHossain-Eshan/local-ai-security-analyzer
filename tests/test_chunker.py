"""
Unit tests for Sentinel Intelligent Token-Aware Chunker.
Verifies dynamic budget enforcement, boundary splits, and oversized entry handling.
"""
import pytest
from pathlib import Path
from app.services.log_chunker import log_chunker, LogChunk
from app.services.tokenizer_service import tokenizer_service
from app.config import settings

def test_dynamic_budget_calculation():
    budget_empty_context = log_chunker.calculate_log_budget("{}")
    assert budget_empty_context > 500
    assert budget_empty_context <= (settings.max_input_tokens - 400)

    # Budget should dynamically shrink as compact context expands
    large_context = '{"known_ips": {"1.1.1.1": {"failed": 10}}, "attack_indicators": ["Ongoing brute-force across 5 accounts", "Scanning detected"]}'
    budget_with_context = log_chunker.calculate_log_budget(large_context)
    assert budget_with_context < budget_empty_context

def test_oversized_single_log_entry_handling(tmp_path):
    # Create a single log line with a massive distinct payload exceeding log token budget
    massive_payload = " ".join([f"overflow_token_param_{i}_data" for i in range(1200)])
    log_content = (
        f'Line 1: Normal event before\n'
        f'Line 2: Massive buffer overflow attempt: {massive_payload}\n'
        f'Line 3: Normal event after\n'
    )
    p = tmp_path / "oversized.log"
    p.write_text(log_content, encoding="utf-8")

    chunks = list(log_chunker.chunk_log_file(p))
    assert len(chunks) >= 2

    # Verify that the oversized chunk contains the truncation indicator and retains line 2
    oversized_chunk = next(c for c in chunks if c.start_line == 2)
    assert "[TRUNCATED DUE TO TOKEN BUDGET]" in oversized_chunk.log_text
    assert oversized_chunk.start_line == 2
    assert oversized_chunk.end_line == 2

    # Verify every chunk strictly respects the max context budget
    for c in chunks:
        assert c.input_tokens + log_chunker.get_base_prompt_overhead() <= settings.max_input_tokens

def test_complete_line_continuity(tmp_path):
    # Test continuous line ranges across chunks without dropping lines
    log_content = "\n".join([f'{{"line_id": {i}, "msg": "Log entry testing chunking sequence"}}' for i in range(1, 101)])
    p = tmp_path / "continuity.log"
    p.write_text(log_content, encoding="utf-8")

    chunks = list(log_chunker.chunk_log_file(p))
    assert len(chunks) > 1

    expected_line = 1
    for c in chunks:
        assert c.start_line == expected_line
        assert c.end_line >= c.start_line
        expected_line = c.end_line + 1

    assert expected_line == 101  # Covered all 100 lines continuously
