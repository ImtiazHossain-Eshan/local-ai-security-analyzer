"""
Database models and Pydantic schemas for Sentinel.
"""
from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

class JobStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    PAUSED = "PAUSED"

class Stage(str, Enum):
    UPLOADED = "UPLOADED"
    CHUNKING = "CHUNKING"
    ANALYZING = "ANALYZING"
    CORRELATING = "CORRELATING"
    REPORT_READY = "REPORT_READY"
    FAILED = "FAILED"

class ChunkStatus(str, Enum):
    PENDING = "PENDING"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

class Disposition(str, Enum):
    ATTEMPTED = "Attempted attack"
    BLOCKED = "Blocked attack attempt"
    SUSPICIOUS = "Suspicious activity"
    POSSIBLE_COMPROMISE = "Possible compromise"
    CONFIRMED_COMPROMISE = "Confirmed compromise"
    OPERATIONAL = "Operational finding"

class EvidenceItem(BaseModel):
    line: int
    excerpt: str

class FindingCreate(BaseModel):
    attack_type: str
    severity: Severity
    source_ip: str = "Unknown"
    account: Optional[str] = None
    evidence: List[EvidenceItem] = Field(default_factory=list)
    reason: str
    suggested_action: str
    confidence: Optional[float] = 0.85
    disposition: Optional[Disposition] = Disposition.SUSPICIOUS

class FindingRecord(FindingCreate):
    id: str
    job_id: str
    chunk_id: Optional[int] = None
    fingerprint: str
    created_at: str

class JobRecord(BaseModel):
    id: str
    filename: str
    file_path: str
    file_size: int
    file_hash: str
    total_lines: int
    total_chunks: int = 0
    completed_chunks: int = 0
    failed_chunks: int = 0
    total_tokens: int = 0
    status: JobStatus = JobStatus.PENDING
    current_stage: Stage = Stage.UPLOADED
    created_at: str
    updated_at: str
    error_message: Optional[str] = None

class ChunkRecord(BaseModel):
    id: int
    job_id: str
    chunk_index: int
    start_line: int
    end_line: int
    input_tokens: int
    reserved_output_tokens: int
    total_budget: int
    status: ChunkStatus
    retry_count: int = 0
    created_at: str
    updated_at: str

class FinalReportRecord(BaseModel):
    id: str
    job_id: str
    report_data: Dict[str, Any]
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    summary: str
    created_at: str
