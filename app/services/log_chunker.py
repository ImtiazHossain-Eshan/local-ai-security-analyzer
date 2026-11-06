"""
Intelligent Token-Aware Log Chunker for Sentinel.
Calculates prompt budgets dynamically, respects exact tokenizer counts,
preserves original physical line numbers, and ensures context never exceeds 2,048 tokens.
"""
import json
from pathlib import Path
from typing import Generator, List, Dict, Any, Union, Optional
from pydantic import BaseModel, Field

from app.config import settings
from app.services.tokenizer_service import tokenizer_service
from app.services.log_parser import iter_log_entries, LogEntry

class LogChunk(BaseModel):
    chunk_id: int
    start_line: int
    end_line: int
    log_text: str
    input_tokens: int
    reserved_output_tokens: int = Field(default=350)
    safety_margin_tokens: int = Field(default=150)
    total_budget: int = Field(default=2048)
    events: List[Dict[str, Any]] = Field(default_factory=list)

    def to_metadata_dict(self) -> Dict[str, Any]:
        return {
            "chunk_id": self.chunk_id,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "input_tokens": self.input_tokens,
            "reserved_output_tokens": self.reserved_output_tokens,
            "safety_margin_tokens": self.safety_margin_tokens,
            "total_budget": self.total_budget,
            "event_count": len(self.events)
        }


class LogChunker:
    def __init__(self):
        self.system_prompt_path = settings.prompts_dir / "system_prompt.txt"
        self.analysis_prompt_path = settings.prompts_dir / "analysis_prompt.txt"
        self._system_prompt_template = self._load_prompt(self.system_prompt_path)
        self._analysis_prompt_template = self._load_prompt(self.analysis_prompt_path)

    def _load_prompt(self, path: Path) -> str:
        if path.exists():
            return path.read_text(encoding="utf-8")
        return ""

    def get_base_prompt_overhead(self, compact_context_json: str = "{}") -> int:
        """
        Calculate exact token overhead for system prompt, analysis prompt skeleton,
        and current compact context.
        """
        # Render a skeleton prompt with empty log text to count prompt overhead
        skeleton = self._analysis_prompt_template.format(
            chunk_id=999,
            start_line=1,
            end_line=999,
            compact_context_json=compact_context_json,
            log_entries_text=""
        )
        sys_tokens = tokenizer_service.count_tokens(self._system_prompt_template)
        skeleton_tokens = tokenizer_service.count_tokens(skeleton)
        # Extra 15 tokens for chat template tags (<|im_start|>, <|im_end|>, etc.)
        return sys_tokens + skeleton_tokens + 15

    def calculate_log_budget(self, compact_context_json: str = "{}") -> int:
        """
        Dynamically calculate remaining tokens available strictly for log entries.
        Enforces:
        assembled_input <= 1,548 tokens
        assembled_input + reserved_output (350) + safety_margin (150) <= 2,048 tokens.
        """
        prompt_overhead = self.get_base_prompt_overhead(compact_context_json)

        # Budget from max context: 2048 - 350 - 150 - overhead
        budget_from_total = (
            settings.model_context_limit
            - settings.reserved_output_tokens
            - settings.safety_margin_tokens
            - prompt_overhead
        )
        # Budget from max input constraint: 1548 - overhead
        budget_from_input = settings.max_input_tokens - prompt_overhead

        available = min(budget_from_total, budget_from_input)
        # Ensure a sane minimum floor
        return max(200, available)

    def chunk_log_file(
        self,
        file_path: Union[str, Path],
        compact_context_json: str = "{}"
    ) -> Generator[LogChunk, None, None]:
        """
        Streams through log entries and yields token-budgeted LogChunk instances.
        Preserves original 1-indexed line numbers.
        """
        log_budget = self.calculate_log_budget(compact_context_json)

        current_chunk_entries: List[LogEntry] = []
        current_chunk_lines: List[str] = []
        current_chunk_tokens: int = 0
        current_chunk_id: int = 1

        for entry in iter_log_entries(file_path):
            # Format entry text with original physical line number
            entry_formatted = entry.summary_text + "\n"
            entry_tokens = tokenizer_service.count_tokens(entry_formatted)

            # Handle unusually large single log entry
            if entry_tokens > log_budget:
                # Flush existing chunk if any
                if current_chunk_entries:
                    yield self._build_chunk(
                        chunk_id=current_chunk_id,
                        entries=current_chunk_entries,
                        formatted_lines=current_chunk_lines,
                        total_tokens=current_chunk_tokens
                    )
                    current_chunk_id += 1
                    current_chunk_entries = []
                    current_chunk_lines = []
                    current_chunk_tokens = 0

                # Controlled fallback: truncate payload body while retaining line number header
                header = f"[Line {entry.start_line}] "
                header_tokens = tokenizer_service.count_tokens(header)
                allowed_body_tokens = max(50, log_budget - header_tokens - 25)
                truncated_body = tokenizer_service.truncate_to_tokens(entry.raw_text, allowed_body_tokens)
                fallback_text = f"{header}{truncated_body} [TRUNCATED DUE TO TOKEN BUDGET]\n"
                fallback_tokens = tokenizer_service.count_tokens(fallback_text)

                single_chunk = LogChunk(
                    chunk_id=current_chunk_id,
                    start_line=entry.start_line,
                    end_line=entry.end_line,
                    log_text=fallback_text,
                    input_tokens=fallback_tokens,
                    reserved_output_tokens=settings.reserved_output_tokens,
                    safety_margin_tokens=settings.safety_margin_tokens,
                    total_budget=settings.model_context_limit,
                    events=[{
                        "start_line": entry.start_line,
                        "end_line": entry.end_line,
                        "format": entry.format_type,
                        "truncated": True
                    }]
                )
                yield single_chunk
                current_chunk_id += 1
                continue

            # Check if adding this entry exceeds available budget
            if current_chunk_tokens + entry_tokens > log_budget and current_chunk_entries:
                # Finalize and yield current chunk
                yield self._build_chunk(
                    chunk_id=current_chunk_id,
                    entries=current_chunk_entries,
                    formatted_lines=current_chunk_lines,
                    total_tokens=current_chunk_tokens
                )
                current_chunk_id += 1
                current_chunk_entries = []
                current_chunk_lines = []
                current_chunk_tokens = 0

            current_chunk_entries.append(entry)
            current_chunk_lines.append(entry_formatted)
            current_chunk_tokens += entry_tokens

        # Flush final chunk
        if current_chunk_entries:
            yield self._build_chunk(
                chunk_id=current_chunk_id,
                entries=current_chunk_entries,
                formatted_lines=current_chunk_lines,
                total_tokens=current_chunk_tokens
            )

    def _build_chunk(
        self,
        chunk_id: int,
        entries: List[LogEntry],
        formatted_lines: List[str],
        total_tokens: int
    ) -> LogChunk:
        start_line = entries[0].start_line
        end_line = entries[-1].end_line
        log_text = "".join(formatted_lines)
        events = [
            {
                "start_line": e.start_line,
                "end_line": e.end_line,
                "format": e.format_type,
                "client_ip": e.parsed_data.get("client_ip") or e.parsed_data.get("ip"),
                "username": e.parsed_data.get("username") or e.parsed_data.get("user"),
                "status": e.parsed_data.get("status"),
                "path": e.parsed_data.get("path") or e.parsed_data.get("uri"),
                "method": e.parsed_data.get("method"),
                "auth_result": e.parsed_data.get("auth_result"),
                "submitted_text": e.parsed_data.get("submitted_text"),
                "message": e.parsed_data.get("message")
            }
            for e in entries
        ]
        return LogChunk(
            chunk_id=chunk_id,
            start_line=start_line,
            end_line=end_line,
            log_text=log_text,
            input_tokens=total_tokens,
            reserved_output_tokens=settings.reserved_output_tokens,
            safety_margin_tokens=settings.safety_margin_tokens,
            total_budget=settings.model_context_limit,
            events=events
        )

# Global chunker instance
log_chunker = LogChunker()
