"""
Upload API endpoints for Sentinel.
Validates file extensions (.log, .txt), performs streaming disk write,
computes SHA256 checksum and line count without multiple memory copies.
"""
import os
import hashlib
from pathlib import Path
from fastapi import APIRouter, UploadFile, File, HTTPException, status
from pydantic import BaseModel

from app.config import settings
from app.database.db import db

router = APIRouter(prefix="/api", tags=["upload"])

ALLOWED_EXTENSIONS = {".log", ".txt"}

class UploadResponse(BaseModel):
    job_id: str
    filename: str
    file_size_bytes: int
    file_sha256: str
    total_lines: int
    status: str
    message: str

@router.post("/upload", response_model=UploadResponse, status_code=status.HTTP_201_CREATED)
async def upload_log_file(file: UploadFile = File(...)):
    # 1. Validate file extension
    ext = Path(file.filename or "").suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid file extension '{ext}'. Only .log and .txt files are supported."
        )

    # 2. Prepare destination path
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    clean_filename = Path(file.filename).name
    dest_path = settings.upload_dir / clean_filename

    # 3. Streaming disk write with hash and line counting
    sha256_hash = hashlib.sha256()
    total_bytes = 0
    total_lines = 0
    chunk_size = 64 * 1024  # 64 KB streaming buffer
    max_bytes = settings.max_upload_size_mb * 1024 * 1024

    with open(dest_path, "wb") as f_out:
        while True:
            chunk = await file.read(chunk_size)
            if not chunk:
                break
            total_bytes += len(chunk)
            if total_bytes > max_bytes:
                dest_path.unlink(missing_ok=True)
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"File exceeds maximum upload limit of {settings.max_upload_size_mb} MB."
                )
            sha256_hash.update(chunk)
            total_lines += chunk.count(b"\n")
            f_out.write(chunk)

    # If file doesn't end with newline but has bytes, count final line
    if total_bytes > 0 and total_lines == 0:
        total_lines = 1

    file_hash = sha256_hash.hexdigest()

    # 4. Create database job record
    job_id = db.create_job(
        filename=clean_filename,
        file_path=str(dest_path),
        file_size=total_bytes,
        file_hash=file_hash,
        total_lines=total_lines
    )

    return UploadResponse(
        job_id=job_id,
        filename=clean_filename,
        file_size_bytes=total_bytes,
        file_sha256=file_hash,
        total_lines=total_lines,
        status="PENDING",
        message="File uploaded and verified successfully. Ready for analysis."
    )

@router.post("/load-sample", response_model=UploadResponse, status_code=status.HTTP_201_CREATED)
async def load_sample_log():
    """
    Instantly stages the Cultive8 Workspace Agrigen regression log for zero-friction evaluation.
    """
    candidates = [
        Path("Cultive8_Workspace_Agrigen_Server.log"),
        Path(__file__).resolve().parent.parent.parent / "Cultive8_Workspace_Agrigen_Server.log",
        Path("tests/fixtures/Cultive8_Workspace_Agrigen_Server.log")
    ]
    sample_path = None
    for cand in candidates:
        if cand.exists():
            sample_path = cand
            break

    if not sample_path:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Sample regression log file not found in repository."
        )

    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    clean_filename = "Cultive8_Workspace_Agrigen_Server.log"
    dest_path = settings.upload_dir / clean_filename

    # Read and write to uploads
    content = sample_path.read_bytes()
    dest_path.write_bytes(content)

    sha256_hash = hashlib.sha256(content).hexdigest()
    total_lines = content.count(b"\n")
    if len(content) > 0 and total_lines == 0:
        total_lines = 1

    job_id = db.create_job(
        filename=clean_filename,
        file_path=str(dest_path),
        file_size=len(content),
        file_hash=sha256_hash,
        total_lines=total_lines
    )

    return UploadResponse(
        job_id=job_id,
        filename=clean_filename,
        file_size_bytes=len(content),
        file_sha256=sha256_hash,
        total_lines=total_lines,
        status="PENDING",
        message="Sample regression log loaded into queue successfully."
    )

