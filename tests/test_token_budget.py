"""
Unit tests for exact token budgeting and conservative limits in Sentinel.
Verifies the non-negotiable constraints:
- Total context <= 2,048 tokens
- Max assembled input <= 1,548 tokens
- Reserved output >= 350 tokens
- Safety margin >= 150 tokens
"""
import pytest
from app.config import settings
from app.services.tokenizer_service import tokenizer_service
from app.services.log_chunker import log_chunker

def test_fixed_budget_constraints():
    assert settings.model_context_limit == 2048
    assert settings.max_input_tokens == 1548
    assert settings.reserved_output_tokens == 350
    assert settings.safety_margin_tokens >= 150

    # Verify math consistency
    assert settings.max_input_tokens + settings.reserved_output_tokens + settings.safety_margin_tokens == settings.model_context_limit + 0

def test_assembled_prompt_under_limit():
    sys_prompt = (settings.prompts_dir / "system_prompt.txt").read_text(encoding="utf-8")
    analysis_template = (settings.prompts_dir / "analysis_prompt.txt").read_text(encoding="utf-8")

    sample_context = '{"known_ips": {"203.0.113.44": {"failed_logins": 5}}}'
    sample_log = "\n".join([f"[Line {i}] 2026-11-01 401 invalid_password workspace.admin" for i in range(1, 20)])

    user_prompt = analysis_template.format(
        chunk_id=1,
        start_line=1,
        end_line=20,
        compact_context_json=sample_context,
        log_entries_text=sample_log
    )

    sys_tokens = tokenizer_service.count_tokens(sys_prompt)
    user_tokens = tokenizer_service.count_tokens(user_prompt)
    total_assembled_input = sys_tokens + user_tokens + 15  # ChatML formatting overhead

    assert total_assembled_input <= settings.max_input_tokens
    assert total_assembled_input + settings.reserved_output_tokens + settings.safety_margin_tokens <= settings.model_context_limit
