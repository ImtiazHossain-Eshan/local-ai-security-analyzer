"""
Report and log evidence context inspection endpoints for Sentinel.
"""
from pathlib import Path
from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import JSONResponse, Response
from typing import Dict, Any

from app.database.db import db
from app.services.log_parser import get_log_context

router = APIRouter(prefix="/api", tags=["reports"])

@router.get("/reports/{job_id}")
async def get_report(job_id: str):
    """Retrieve consolidated security incident report for a job."""
    report_record = db.get_final_report(job_id)
    if not report_record:
        job = db.get_job(job_id)
        if not job:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Job '{job_id}' not found."
            )
        if job["status"] != "COMPLETED":
            return {
                "job_id": job_id,
                "status": job["status"],
                "current_stage": job["current_stage"],
                "message": "Report is still being generated. Please monitor progress."
            }
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report for completed job '{job_id}' could not be located."
        )

    return report_record["report_data"]

@router.get("/reports/{job_id}/export")
async def export_report_json(job_id: str):
    """Export the consolidated security report as a downloadable JSON file."""
    report_record = db.get_final_report(job_id)
    if not report_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report for job '{job_id}' is not yet available."
        )

    filename = f"sentinel_report_{job_id[:8]}.json"
    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"'
    }
    return JSONResponse(
        content=report_record["report_data"],
        headers=headers
    )

@router.get("/logs/{job_id}/context")
async def get_evidence_context(
    job_id: str,
    line: int = Query(..., description="Target evidence line number"),
    window: int = Query(5, description="Number of lines before and after to display")
):
    """
    Returns original log lines surrounding a cited evidence line
    so analysts can inspect the authentic source context.
    """
    job = db.get_job(job_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job '{job_id}' not found."
        )

    file_path = Path(job["file_path"])
    if not file_path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Source log file is no longer present on disk."
        )

    context_data = get_log_context(file_path, target_line=line, window=window)
    return context_data
