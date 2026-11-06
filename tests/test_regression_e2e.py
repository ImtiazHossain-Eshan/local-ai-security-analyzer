"""
Regression integration test for Cultive8_Workspace_Agrigen_Server.log.
Verifies end-to-end ingestion, chunking, security detection, and report consolidation.
"""
from pathlib import Path
from fastapi.testclient import TestClient
from app.main import app
from app.database.db import db
from app.services.log_chunker import log_chunker
from app.services.correlation_engine import correlation_engine
from app.services.report_service import report_service
from app.database.models import Severity, Disposition

client = TestClient(app)

def test_cultive8_regression_log():
    log_file = Path("Cultive8_Workspace_Agrigen_Server.log")
    assert log_file.exists(), "Cultive8_Workspace_Agrigen_Server.log must be present"

    # 1. API Upload
    with open(log_file, "rb") as f:
        upload_res = client.post("/api/upload", files={"file": ("Cultive8_Workspace_Agrigen_Server.log", f, "text/plain")})
    assert upload_res.status_code == 201
    upload_data = upload_res.json()
    job_id = upload_data["job_id"]
    assert upload_data["total_lines"] == 258

    # 2. Chunking Verification
    chunks = list(log_chunker.chunk_log_file(log_file))
    assert len(chunks) == 56
    assert chunks[0].start_line == 1
    assert chunks[-1].end_line == 258

    # Verify line continuity
    cur = 1
    for c in chunks:
        assert c.start_line == cur
        cur = c.end_line + 1
    assert cur == 259

    # 3. Simulate and verify end-to-end correlation and report generation
    all_events = []
    for c in chunks:
        all_events.extend(c.events)

    # Correlate all events
    correlated = correlation_engine.correlate_and_synthesize(
        raw_findings=[],
        chunk_events_summary=all_events
    )

    # 4. Assert Key Detections
    # A. Confirmed Compromise
    compromise = next((f for f in correlated if f["source_ip"] == "203.0.113.44"), None)
    assert compromise is not None, "Must detect compromise for 203.0.113.44"
    assert compromise["severity"] == Severity.CRITICAL.value
    assert compromise["disposition"] == Disposition.CONFIRMED_COMPROMISE.value
    assert compromise["account"] == "workspace.admin"

    # Evidence lines must include the brute force lines, login, and export
    ev_lines = [e["line"] for e in compromise["evidence"]]
    assert 196 in ev_lines  # Login 200 success
    assert 198 in ev_lines  # Admin access
    assert 201 in ev_lines  # Data export CSV

    # B. Directory Scanning
    scanner = next((f for f in correlated if f["source_ip"] == "203.0.113.90"), None)
    assert scanner is not None, "Must detect directory scanner 203.0.113.90"
    assert scanner["severity"] == Severity.MEDIUM.value
    assert scanner["disposition"] == Disposition.BLOCKED.value

    # C. Prompt Injection
    prompt_inj = next((f for f in correlated if f["source_ip"] == "203.0.113.201"), None)
    assert prompt_inj is not None, "Must detect prompt injection 203.0.113.201"
    assert prompt_inj["disposition"] == Disposition.BLOCKED.value

    # D. Isolated user typo (field.officer)
    typo_user = next((f for f in correlated if f["source_ip"] == "198.51.100.96"), None)
    if typo_user:
        assert typo_user["severity"] == Severity.LOW.value

    # 5. Consolidated Report
    job_record = db.get_job(job_id)
    report = report_service.generate_consolidated_report(job_record, correlated, chunks)
    assert report["statistics"]["critical"] >= 1
    assert "CRITICAL BREACH CONFIRMED" in report["overall_status"]
    assert len(report["suspicious_entities"]) >= 2
