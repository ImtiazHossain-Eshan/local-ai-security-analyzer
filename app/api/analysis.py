"""
Analysis management, progress tracking, and system health endpoints for Sentinel.
"""
import time
from datetime import datetime, timezone
import psutil
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from typing import List, Dict, Any, Optional

from app.database.db import db
from app.services.analysis_service import analysis_service
from app.services.model_service import model_service

router = APIRouter(prefix="/api", tags=["analysis"])

class AnalyzeResponse(BaseModel):
    job_id: str
    status: str
    stage: str
    message: str

class ProgressResponse(BaseModel):
    job_id: str
    filename: str
    status: str
    current_stage: str
    current_chunk: int
    total_chunks: int
    completed_chunks: int
    failed_chunks: int
    percentage: float
    total_tokens: int
    elapsed_seconds: float
    model_rss_mb: float
    system_available_ram_mb: float

@router.get("/health")
async def health_check():
    """System health check endpoint."""
    mem = psutil.virtual_memory()
    return {
        "status": "healthy",
        "service": "Sentinel Local AI Security Analyzer",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "total_ram_mb": round(mem.total / (1024 * 1024), 2),
        "available_ram_mb": round(mem.available / (1024 * 1024), 2),
        "used_ram_mb": round(mem.used / (1024 * 1024), 2)
    }

@router.get("/model/status")
async def model_status():
    """Local model health and runtime readiness endpoint."""
    return await model_service.get_status()

@router.post("/analyze/{job_id}", response_model=AnalyzeResponse)
async def trigger_analysis(job_id: str):
    """Enqueues an uploaded log file for sequential model analysis."""
    job = db.get_job(job_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job with ID '{job_id}' not found."
        )

    if job["status"] == "RUNNING":
        return AnalyzeResponse(
            job_id=job_id,
            status=job["status"],
            stage=job["current_stage"],
            message="Analysis is already actively running."
        )

    await analysis_service.enqueue_job(job_id)

    return AnalyzeResponse(
        job_id=job_id,
        status="PENDING",
        stage="UPLOADED",
        message="Job successfully enqueued for sequential AI analysis."
    )

@router.get("/jobs", response_model=List[Dict[str, Any]])
async def list_jobs():
    """List all submitted analysis jobs."""
    return db.list_jobs()

@router.get("/jobs/{job_id}")
async def get_job_details(job_id: str):
    """Get full record and chunk metadata for a job."""
    job = db.get_job(job_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job with ID '{job_id}' not found."
        )
    chunks = db.get_chunks_for_job(job_id)
    return {
        "job": job,
        "chunks": chunks
    }

@router.get("/jobs/{job_id}/progress", response_model=ProgressResponse)
async def get_job_progress(job_id: str):
    """Real-time database-backed progress reporting for the dashboard."""
    job = db.get_job(job_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job with ID '{job_id}' not found."
        )

    total_c = job.get("total_chunks", 0)
    completed_c = job.get("completed_chunks", 0)
    failed_c = job.get("failed_chunks", 0)

    # Calculate percentage
    if total_c > 0:
        percent = round(((completed_c + failed_c) / total_c) * 100.0, 1)
        if job.get("status") == "COMPLETED":
            percent = 100.0
    else:
        percent = 0.0

    # Calculate elapsed seconds
    created_at_dt = datetime.fromisoformat(job["created_at"])
    if job.get("status") in {"COMPLETED", "FAILED"}:
        updated_at_dt = datetime.fromisoformat(job["updated_at"])
        elapsed = (updated_at_dt - created_at_dt).total_seconds()
    else:
        elapsed = (datetime.now(timezone.utc) - created_at_dt).total_seconds()

    current_c = min(total_c, completed_c + failed_c + (1 if job.get("status") == "RUNNING" else 0))

    mem_rss = model_service.get_server_rss_mb()
    avail_ram = round(psutil.virtual_memory().available / (1024 * 1024), 2)

    return ProgressResponse(
        job_id=job_id,
        filename=job["filename"],
        status=job["status"],
        current_stage=job["current_stage"],
        current_chunk=current_c,
        total_chunks=total_c,
        completed_chunks=completed_c,
        failed_chunks=failed_c,
        percentage=percent,
        total_tokens=job.get("total_tokens", 0),
        elapsed_seconds=round(elapsed, 1),
        model_rss_mb=mem_rss,
        system_available_ram_mb=avail_ram
    )
