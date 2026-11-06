"""
Integration tests for Sentinel Backend API Endpoints.
Verifies health, model status, file upload validation, progress, reports, and context inspection.
"""
import io
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database.db import db

client = TestClient(app)

def test_health_endpoint():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert "available_ram_mb" in data

def test_model_status_endpoint():
    res = client.get("/api/model/status")
    assert res.status_code == 200
    data = res.json()
    assert "downloaded" in data
    assert "ready" in data
    assert data["context_limit"] == 2048

def test_upload_invalid_extension():
    fake_exe = io.BytesIO(b"MZ executable header")
    res = client.post("/api/upload", files={"file": ("malware.exe", fake_exe, "application/octet-stream")})
    assert res.status_code == 400
    assert "Invalid file extension" in res.json()["detail"]

def test_upload_valid_log():
    log_content = io.BytesIO(b'{"time":"2026-11-01T08:00:00Z","client_ip":"192.168.1.1","status":200}\n')
    res = client.post("/api/upload", files={"file": ("server_audit.log", log_content, "text/plain")})
    assert res.status_code == 201
    data = res.json()
    assert "job_id" in data
    assert data["filename"] == "server_audit.log"
    assert data["total_lines"] >= 1
    assert data["status"] == "PENDING"

def test_job_progress_and_report_flow():
    # 1. Create a job directly in db
    job_id = db.create_job("flow_test.log", "data/uploads/flow_test.log", 500, "hash999", 10)
    db.update_job(job_id, status="RUNNING", current_stage="ANALYZING", total_chunks=2, completed_chunks=1)

    # 2. Check progress
    prog_res = client.get(f"/api/jobs/{job_id}/progress")
    assert prog_res.status_code == 200
    prog_data = prog_res.json()
    assert prog_data["job_id"] == job_id
    assert prog_data["current_stage"] == "ANALYZING"
    assert prog_data["percentage"] == 50.0

    # 3. Simulate report generation
    db.save_final_report(
        job_id=job_id,
        report_data={"report_id": "REP-FLOW", "filename": "flow_test.log", "findings": []},
        summary="Test analysis summary",
        counts={"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
    )
    db.update_job(job_id, status="COMPLETED", current_stage="REPORT_READY")

    # 4. Fetch report
    rep_res = client.get(f"/api/reports/{job_id}")
    assert rep_res.status_code == 200
    assert rep_res.json()["report_id"] == "REP-FLOW"

    # 5. Export report
    exp_res = client.get(f"/api/reports/{job_id}/export")
    assert exp_res.status_code == 200
    assert "attachment;" in exp_res.headers.get("content-disposition", "")
