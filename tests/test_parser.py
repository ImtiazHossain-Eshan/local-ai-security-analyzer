"""
Unit tests for Sentinel Streaming Log Parser.
Verifies line numbering, JSON lines, CLF, application logs, and multiline stacktraces.
"""
import pytest
from pathlib import Path
from app.services.log_parser import iter_log_entries, parse_line_data, get_log_context

def test_parse_json_lines(tmp_path):
    log_content = (
        '{"time": "2026-11-01T08:00:00Z", "client_ip": "10.0.0.1", "status": 200, "path": "/home"}\n'
        '{"time": "2026-11-01T08:01:00Z", "client_ip": "10.0.0.2", "status": 401, "path": "/login"}\n'
    )
    p = tmp_path / "test_json.log"
    p.write_text(log_content, encoding="utf-8")

    entries = list(iter_log_entries(p))
    assert len(entries) == 2
    assert entries[0].start_line == 1
    assert entries[0].end_line == 1
    assert entries[0].format_type == "json"
    assert entries[0].parsed_data["client_ip"] == "10.0.0.1"

    assert entries[1].start_line == 2
    assert entries[1].end_line == 2
    assert entries[1].parsed_data["status"] == 401

def test_parse_clf_format():
    line = '192.168.1.10 - frank [10/Oct/2026:13:55:36 -0700] "GET /admin HTTP/1.1" 403 2326'
    fmt, data = parse_line_data(line)
    assert fmt == "clf"
    assert data["client_ip"] == "192.168.1.10"
    assert data["status"] == 403
    assert data["path"] == "/admin"

def test_multiline_traceback_preservation(tmp_path):
    log_content = (
        'Line 1: Normal start\n'
        'Line 2: Exception in thread "main"\n'
        '    at com.example.MyClass.doSomething(MyClass.java:45)\n'
        '    at com.example.MyClass.main(MyClass.java:12)\n'
        'Line 5: Resumed normal line\n'
    )
    p = tmp_path / "traceback.log"
    p.write_text(log_content, encoding="utf-8")

    entries = list(iter_log_entries(p))
    assert len(entries) == 3
    # First entry
    assert entries[0].start_line == 1
    assert entries[0].end_line == 1
    # Multiline entry spanning lines 2 to 4
    assert entries[1].start_line == 2
    assert entries[1].end_line == 4
    assert "com.example.MyClass.doSomething" in entries[1].raw_text
    # Third entry preserves original physical line 5
    assert entries[2].start_line == 5
    assert entries[2].end_line == 5

def test_get_log_context(tmp_path):
    lines = [f"Server log record line {i}" for i in range(1, 21)]
    p = tmp_path / "context_test.log"
    p.write_text("\n".join(lines), encoding="utf-8")

    ctx = get_log_context(p, target_line=10, window=3)
    assert ctx["target_line"] == 10
    assert ctx["start_line"] == 7
    assert ctx["end_line"] == 13
    assert len(ctx["lines"]) == 7

    target_entry = next(l for l in ctx["lines"] if l["line"] == 10)
    assert target_entry["is_target"] is True
    assert target_entry["text"] == "Server log record line 10"
