"""
Streaming Log Parser for Sentinel.
Supports JSON Lines, Common/Combined Log Format, timestamped application logs,
multiline log entries, and unknown formats while strictly preserving physical 1-indexed line numbers.
"""
import re
import json
from pathlib import Path
from typing import Generator, Dict, Any, Optional, Union
from pydantic import BaseModel, Field

# Regex for Common/Combined Log Format (Apache/Nginx)
CLF_REGEX = re.compile(
    r'^(?P<client_ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>[^\s"]+)(?:\s+(?P<protocol>[^\s"]+))?"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)

# Regex for standard timestamped logs (ISO, Syslog, or Standard Date/Time)
TIMESTAMP_REGEX = re.compile(
    r'^(?:\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?|[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
)

# Indentation/continuation indicating multiline tracebacks
CONTINUATION_REGEX = re.compile(r'^(?:\s{2,}|\t|Traceback|Caused by:|Exception:|Error:|\}\s*$)')

class LogEntry(BaseModel):
    start_line: int
    end_line: int
    raw_text: str
    format_type: str = "raw"  # "json", "clf", "timestamped", "raw"
    parsed_data: Dict[str, Any] = Field(default_factory=dict)

    @property
    def summary_text(self) -> str:
        """Compact standardized representation for AI prompt consumption."""
        if self.start_line == self.end_line:
            return f"[Line {self.start_line}] {self.raw_text}"
        return f"[Lines {self.start_line}-{self.end_line}] {self.raw_text}"


def parse_line_data(line: str) -> tuple[str, Dict[str, Any]]:
    """Determine format and extract structured metadata from a single line."""
    stripped = line.strip()
    if not stripped:
        return "empty", {}

    # 1. Try JSON / JSON Lines
    if (stripped.startswith("{") and stripped.endswith("}")) or (stripped.startswith("{") and '"' in stripped):
        try:
            data = json.loads(stripped)
            if isinstance(data, dict):
                return "json", data
        except Exception:
            pass

    # 2. Try Common / Combined Log Format (CLF)
    clf_match = CLF_REGEX.match(stripped)
    if clf_match:
        data = clf_match.groupdict()
        try:
            data["status"] = int(data["status"])
        except (ValueError, TypeError):
            pass
        return "clf", data

    # 3. Try Timestamped Application Log
    if TIMESTAMP_REGEX.match(stripped):
        parts = stripped.split(maxsplit=3)
        data = {"timestamp": parts[0]}
        if len(parts) > 1 and parts[1].strip("[]():").upper() in {"INFO", "WARN", "WARNING", "ERROR", "CRITICAL", "DEBUG"}:
            data["level"] = parts[1].strip("[]():").upper()
            if len(parts) > 2:
                data["message"] = " ".join(parts[2:])
        else:
            data["message"] = " ".join(parts[1:])
        return "timestamped", data

    # 4. Unknown/Generic line format
    return "raw", {"content": stripped}


def iter_log_entries(file_path: Union[str, Path]) -> Generator[LogEntry, None, None]:
    """
    Streams log file line-by-line.
    Maintains physical 1-indexed line numbers and buffers multiline entries safely.
    Zero full-file string copying.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Log file not found: {path}")

    current_entry_lines: list[str] = []
    current_start_line: int = 1
    current_format: str = "raw"
    current_data: Dict[str, Any] = {}

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line_num, line in enumerate(f, start=1):
            line_clean = line.rstrip("\r\n")

            # Check if this line looks like a continuation of previous entry (e.g. stacktrace)
            is_continuation = bool(
                current_entry_lines and
                (CONTINUATION_REGEX.match(line) or (not line_clean.strip()))
            )

            # If it's a JSON block spanning multiple lines (e.g. pretty-printed JSON)
            if current_entry_lines and current_format == "json_pending":
                current_entry_lines.append(line_clean)
                combined = "\n".join(current_entry_lines)
                try:
                    data = json.loads(combined)
                    yield LogEntry(
                        start_line=current_start_line,
                        end_line=line_num,
                        raw_text=combined,
                        format_type="json",
                        parsed_data=data
                    )
                    current_entry_lines = []
                    current_format = "raw"
                    current_data = {}
                    continue
                except Exception:
                    # Still incomplete JSON block, continue reading lines
                    continue

            if is_continuation:
                current_entry_lines.append(line_clean)
                continue

            # Emit previous accumulated entry before starting a new one
            if current_entry_lines:
                raw_text = "\n".join(current_entry_lines)
                yield LogEntry(
                    start_line=current_start_line,
                    end_line=line_num - 1,
                    raw_text=raw_text,
                    format_type=current_format,
                    parsed_data=current_data
                )
                current_entry_lines = []

            # Start analyzing new line
            current_start_line = line_num
            fmt, data = parse_line_data(line_clean)

            # Handle start of pretty-printed multiline JSON
            if line_clean.strip() == "{" and fmt != "json":
                current_entry_lines = [line_clean]
                current_format = "json_pending"
                current_data = {}
                continue

            current_entry_lines = [line_clean]
            current_format = fmt
            current_data = data

        # Flush final entry
        if current_entry_lines:
            raw_text = "\n".join(current_entry_lines)
            if current_format == "json_pending":
                try:
                    current_data = json.loads(raw_text)
                    current_format = "json"
                except Exception:
                    current_format = "raw"
            yield LogEntry(
                start_line=current_start_line,
                end_line=current_start_line + len(current_entry_lines) - 1,
                raw_text=raw_text,
                format_type=current_format,
                parsed_data=current_data
            )


def get_log_context(file_path: Union[str, Path], target_line: int, window: int = 5) -> Dict[str, Any]:
    """
    Extracts lines surrounding target_line for human evidence inspection.
    Returns exact 1-indexed line numbers and text.
    """
    path = Path(file_path)
    start_bound = max(1, target_line - window)
    end_bound = target_line + window

    lines = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line_num, line in enumerate(f, start=1):
            if line_num > end_bound:
                break
            if line_num >= start_bound:
                lines.append({
                    "line": line_num,
                    "text": line.rstrip("\r\n"),
                    "is_target": (line_num == target_line)
                })

    return {
        "target_line": target_line,
        "start_line": start_bound,
        "end_line": min(end_bound, start_bound + len(lines) - 1 if lines else end_bound),
        "lines": lines
    }
