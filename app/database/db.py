"""
Thread-safe SQLite Database manager with WAL mode for Sentinel.
"""
import sqlite3
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any
from contextlib import contextmanager

from app.config import settings

def get_iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()

class Database:
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or settings.database_path
        self.init_db()

    @contextmanager
    def get_connection(self):
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=30.0,
            check_same_thread=False
        )
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init_db(self):
        with self.get_connection() as conn:
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS analysis_jobs (
                id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                file_hash TEXT NOT NULL,
                total_lines INTEGER NOT NULL,
                total_chunks INTEGER DEFAULT 0,
                completed_chunks INTEGER DEFAULT 0,
                failed_chunks INTEGER DEFAULT 0,
                total_tokens INTEGER DEFAULT 0,
                status TEXT NOT NULL,
                current_stage TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                error_message TEXT
            );

            CREATE TABLE IF NOT EXISTS log_chunks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT NOT NULL,
                chunk_index INTEGER NOT NULL,
                start_line INTEGER NOT NULL,
                end_line INTEGER NOT NULL,
                input_tokens INTEGER NOT NULL,
                reserved_output_tokens INTEGER NOT NULL,
                total_budget INTEGER NOT NULL,
                status TEXT NOT NULL,
                retry_count INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (job_id) REFERENCES analysis_jobs(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS chunk_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chunk_id INTEGER NOT NULL,
                job_id TEXT NOT NULL,
                raw_model_response TEXT,
                parsed_json TEXT NOT NULL,
                compact_context_after TEXT NOT NULL,
                prompt_tokens INTEGER DEFAULT 0,
                completion_tokens INTEGER DEFAULT 0,
                duration_ms INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY (chunk_id) REFERENCES log_chunks(id) ON DELETE CASCADE,
                FOREIGN KEY (job_id) REFERENCES analysis_jobs(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                job_id TEXT NOT NULL,
                chunk_id INTEGER,
                fingerprint TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                account TEXT,
                evidence TEXT NOT NULL,
                reason TEXT NOT NULL,
                suggested_action TEXT NOT NULL,
                confidence REAL DEFAULT 0.85,
                disposition TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (job_id) REFERENCES analysis_jobs(id) ON DELETE CASCADE,
                FOREIGN KEY (chunk_id) REFERENCES log_chunks(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS final_reports (
                id TEXT PRIMARY KEY,
                job_id TEXT UNIQUE NOT NULL,
                report_data TEXT NOT NULL,
                total_findings INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                summary TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (job_id) REFERENCES analysis_jobs(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_chunks_job ON log_chunks(job_id);
            CREATE INDEX IF NOT EXISTS idx_findings_job ON findings(job_id);
            CREATE INDEX IF NOT EXISTS idx_findings_ip ON findings(source_ip);
            """)

    def create_job(self, filename: str, file_path: str, file_size: int, file_hash: str, total_lines: int) -> str:
        job_id = str(uuid.uuid4())
        now = get_iso_now()
        with self.get_connection() as conn:
            conn.execute("""
            INSERT INTO analysis_jobs (
                id, filename, file_path, file_size, file_hash, total_lines,
                total_chunks, completed_chunks, failed_chunks, total_tokens,
                status, current_stage, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, 0, 0, 0, 0, 'PENDING', 'UPLOADED', ?, ?)
            """, (job_id, filename, file_path, file_size, file_hash, total_lines, now, now))
        return job_id

    def update_job(self, job_id: str, **kwargs):
        if not kwargs:
            return
        kwargs["updated_at"] = get_iso_now()
        fields = [f"{k} = ?" for k in kwargs.keys()]
        values = list(kwargs.values()) + [job_id]
        with self.get_connection() as conn:
            conn.execute(f"UPDATE analysis_jobs SET {', '.join(fields)} WHERE id = ?", values)

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            cur = conn.execute("SELECT * FROM analysis_jobs WHERE id = ?", (job_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def list_jobs(self) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cur = conn.execute("SELECT * FROM analysis_jobs ORDER BY created_at DESC")
            return [dict(row) for row in cur.fetchall()]

    def create_chunk(self, job_id: str, chunk_index: int, start_line: int, end_line: int,
                     input_tokens: int, reserved_output_tokens: int, total_budget: int) -> int:
        now = get_iso_now()
        with self.get_connection() as conn:
            cur = conn.execute("""
            INSERT INTO log_chunks (
                job_id, chunk_index, start_line, end_line, input_tokens,
                reserved_output_tokens, total_budget, status, retry_count, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING', 0, ?, ?)
            """, (job_id, chunk_index, start_line, end_line, input_tokens, reserved_output_tokens, total_budget, now, now))
            return cur.lastrowid

    def update_chunk(self, chunk_id: int, **kwargs):
        if not kwargs:
            return
        kwargs["updated_at"] = get_iso_now()
        fields = [f"{k} = ?" for k in kwargs.keys()]
        values = list(kwargs.values()) + [chunk_id]
        with self.get_connection() as conn:
            conn.execute(f"UPDATE log_chunks SET {', '.join(fields)} WHERE id = ?", values)

    def get_chunks_for_job(self, job_id: str) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cur = conn.execute("SELECT * FROM log_chunks WHERE job_id = ? ORDER BY chunk_index ASC", (job_id,))
            return [dict(row) for row in cur.fetchall()]

    def save_chunk_result(self, chunk_id: int, job_id: str, raw_model_response: str,
                          parsed_json: Dict[str, Any], compact_context_after: Dict[str, Any],
                          prompt_tokens: int, completion_tokens: int, duration_ms: int):
        now = get_iso_now()
        with self.get_connection() as conn:
            conn.execute("""
            INSERT INTO chunk_results (
                chunk_id, job_id, raw_model_response, parsed_json,
                compact_context_after, prompt_tokens, completion_tokens, duration_ms, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                chunk_id, job_id, raw_model_response,
                json.dumps(parsed_json), json.dumps(compact_context_after),
                prompt_tokens, completion_tokens, duration_ms, now
            ))

    def save_finding(self, job_id: str, chunk_id: Optional[int], finding: Dict[str, Any]) -> str:
        finding_id = str(uuid.uuid4())
        now = get_iso_now()
        evidence_json = json.dumps(finding.get("evidence", []))
        with self.get_connection() as conn:
            conn.execute("""
            INSERT INTO findings (
                id, job_id, chunk_id, fingerprint, attack_type, severity,
                source_ip, account, evidence, reason, suggested_action,
                confidence, disposition, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                finding_id, job_id, chunk_id,
                finding.get("fingerprint", str(uuid.uuid4())),
                finding.get("attack_type", "Unknown Anomaly"),
                finding.get("severity", "Low"),
                finding.get("source_ip", "Unknown"),
                finding.get("account"),
                evidence_json,
                finding.get("reason", ""),
                finding.get("suggested_action", ""),
                finding.get("confidence", 0.85),
                finding.get("disposition", "Suspicious activity"),
                now
            ))
        return finding_id

    def get_findings_for_job(self, job_id: str) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cur = conn.execute("SELECT * FROM findings WHERE job_id = ? ORDER BY created_at ASC", (job_id,))
            rows = [dict(r) for r in cur.fetchall()]
            for r in rows:
                if isinstance(r.get("evidence"), str):
                    try:
                        r["evidence"] = json.loads(r["evidence"])
                    except Exception:
                        r["evidence"] = []
            return rows

    def save_final_report(self, job_id: str, report_data: Dict[str, Any], summary: str, counts: Dict[str, int]) -> str:
        report_id = str(uuid.uuid4())
        now = get_iso_now()
        with self.get_connection() as conn:
            conn.execute("""
            INSERT INTO final_reports (
                id, job_id, report_data, total_findings, critical_count,
                high_count, medium_count, low_count, summary, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(job_id) DO UPDATE SET
                report_data = excluded.report_data,
                total_findings = excluded.total_findings,
                critical_count = excluded.critical_count,
                high_count = excluded.high_count,
                medium_count = excluded.medium_count,
                low_count = excluded.low_count,
                summary = excluded.summary,
                created_at = excluded.created_at
            """, (
                report_id, job_id, json.dumps(report_data),
                counts.get("total", 0), counts.get("critical", 0),
                counts.get("high", 0), counts.get("medium", 0),
                counts.get("low", 0), summary, now
            ))
        return report_id

    def get_final_report(self, job_id: str) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            cur = conn.execute("SELECT * FROM final_reports WHERE job_id = ?", (job_id,))
            row = cur.fetchone()
            if not row:
                return None
            res = dict(row)
            if isinstance(res.get("report_data"), str):
                res["report_data"] = json.loads(res["report_data"])
            return res

# Global database instance
db = Database()
