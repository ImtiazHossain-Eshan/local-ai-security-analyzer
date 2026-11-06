"""
Unit tests for Cross-Chunk Security Event Correlation in Sentinel.
Verifies the central requirement:
Chunk 1: IP A makes 3 failed logins
Chunk 2: IP A makes 5 more failed logins
Chunk 3: IP A successfully authenticates and accesses data
-> Correlates into ONE single Critical investigation linking all 3 chunks.
"""
import pytest
from app.services.correlation_engine import correlation_engine
from app.database.models import Severity, Disposition

def test_cross_chunk_brute_force_to_compromise():
    # 1. Synthetic Findings from 3 different chunks
    raw_findings = [
        # From Chunk 1
        {
            "chunk_id": 1,
            "attack_type": "Brute-force login attempt",
            "severity": "Medium",
            "source_ip": "203.0.113.44",
            "account": "workspace.admin",
            "evidence": [
                {"line": 12, "excerpt": "auth_result=invalid_password"},
                {"line": 15, "excerpt": "auth_result=invalid_password"},
                {"line": 18, "excerpt": "auth_result=invalid_password"}
            ],
            "reason": "Initial auth failures.",
            "suggested_action": "Monitor source.",
            "confidence": 0.85,
            "disposition": "Suspicious activity"
        },
        # From Chunk 2
        {
            "chunk_id": 2,
            "attack_type": "Brute-force login attempt",
            "severity": "High",
            "source_ip": "203.0.113.44",
            "account": "workspace.admin",
            "evidence": [
                {"line": 45, "excerpt": "auth_result=invalid_password"},
                {"line": 52, "excerpt": "auth_result=invalid_password"},
                {"line": 61, "excerpt": "auth_result=invalid_password"}
            ],
            "reason": "Continued auth failures.",
            "suggested_action": "Block IP.",
            "confidence": 0.90,
            "disposition": "Attempted attack"
        },
        # From Chunk 3
        {
            "chunk_id": 3,
            "attack_type": "Unauthorized access",
            "severity": "High",
            "source_ip": "203.0.113.44",
            "account": "workspace.admin",
            "evidence": [
                {"line": 110, "excerpt": "POST /api/v1/auth/login 200 success"},
                {"line": 112, "excerpt": "GET /api/v1/workspaces/7/export 200"}
            ],
            "reason": "Valid login followed by sensitive export.",
            "suggested_action": "Audit account.",
            "confidence": 0.95,
            "disposition": "Suspicious activity"
        }
    ]

    # Full-file event summaries across the timeline
    chunk_events = [
        {"line": 12, "client_ip": "203.0.113.44", "username": "workspace.admin", "auth_result": "invalid_password", "status": 401, "path": "/api/v1/auth/login"},
        {"line": 15, "client_ip": "203.0.113.44", "username": "workspace.admin", "auth_result": "invalid_password", "status": 401, "path": "/api/v1/auth/login"},
        {"line": 18, "client_ip": "203.0.113.44", "username": "workspace.admin", "auth_result": "invalid_password", "status": 401, "path": "/api/v1/auth/login"},
        {"line": 45, "client_ip": "203.0.113.44", "username": "workspace.admin", "auth_result": "invalid_password", "status": 401, "path": "/api/v1/auth/login"},
        {"line": 52, "client_ip": "203.0.113.44", "username": "workspace.admin", "auth_result": "invalid_password", "status": 401, "path": "/api/v1/auth/login"},
        {"line": 61, "client_ip": "203.0.113.44", "username": "workspace.admin", "auth_result": "invalid_password", "status": 401, "path": "/api/v1/auth/login"},
        {"line": 110, "client_ip": "203.0.113.44", "username": "workspace.admin", "auth_result": "success", "status": 200, "path": "/api/v1/auth/login", "method": "POST"},
        {"line": 112, "client_ip": "203.0.113.44", "username": "workspace.admin", "status": 200, "path": "/api/v1/workspaces/7/export", "method": "GET"}
    ]

    correlated = correlation_engine.correlate_and_synthesize(raw_findings, chunk_events)

    # CRUCIAL ASSERTION: Must NOT be 3 unrelated findings.
    # Must be consolidated into ONE correlated breach investigation for this entity.
    compromise_findings = [f for f in correlated if f["source_ip"] == "203.0.113.44"]
    assert len(compromise_findings) == 1

    finding = compromise_findings[0]
    assert finding["severity"] == Severity.CRITICAL.value
    assert finding["disposition"] == Disposition.CONFIRMED_COMPROMISE.value
    assert "credential compromise" in finding["attack_type"].lower()

    # Verify that evidence spans all 3 chunks (line 12 from chunk 1 up to line 112 from chunk 3)
    evidence_lines = [e["line"] for e in finding["evidence"]]
    assert 12 in evidence_lines
    assert 45 in evidence_lines
    assert 110 in evidence_lines
    assert 112 in evidence_lines
    assert len(evidence_lines) >= 8
