"""
Sequential Analysis Service & Worker Queue for Sentinel.
Enforces single-worker inference, sequential multi-pass chunk processing,
incremental finding persistence, compact context carrying, and final global correlation.
"""
import json
import asyncio
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
import psutil

from app.config import settings
from app.database.db import db
from app.database.models import JobStatus, Stage, ChunkStatus
from app.services.tokenizer_service import tokenizer_service
from app.services.log_chunker import log_chunker, LogChunk
from app.services.model_service import model_service
from app.services.compact_context import CompactContext
from app.services.json_parser import parse_and_validate_chunk_response
from app.services.correlation_engine import correlation_engine
from app.services.report_service import report_service
from app.services.log_parser import iter_log_entries

logger = logging.getLogger("sentinel.analysis")

class AnalysisService:
    def __init__(self):
        self.queue: asyncio.Queue[str] = asyncio.Queue()
        self._worker_task: Optional[asyncio.Task] = None
        self._current_job_id: Optional[str] = None

    def start_worker(self):
        if self._worker_task is None or self._worker_task.done():
            self._worker_task = asyncio.create_task(self._process_queue())

    async def enqueue_job(self, job_id: str):
        """Enqueue job ID for background processing."""
        job = db.get_job(job_id)
        if not job:
            raise ValueError(f"Job {job_id} not found.")
        db.update_job(job_id, status=JobStatus.PENDING.value, current_stage=Stage.UPLOADED.value)
        await self.queue.put(job_id)
        self.start_worker()

    async def _process_queue(self):
        """Single-worker queue loop processing one job at a time."""
        while True:
            job_id = await self.queue.get()
            self._current_job_id = job_id
            try:
                await self._run_analysis(job_id)
            except Exception as e:
                logger.exception(f"Unhandled error in analysis for job {job_id}: {e}")
                db.update_job(job_id, status=JobStatus.FAILED.value, current_stage=Stage.FAILED.value, error_message=str(e))
            finally:
                self._current_job_id = None
                self.queue.task_done()

    async def _run_analysis(self, job_id: str):
        job = db.get_job(job_id)
        if not job:
            return

        db.update_job(job_id, status=JobStatus.RUNNING.value, current_stage=Stage.CHUNKING.value)
        file_path = Path(job["file_path"])

        # Check memory headroom before starting
        mem_rss = psutil.virtual_memory().used / (1024 * 1024)
        if mem_rss > settings.max_ram_usage_mb:
            db.update_job(
                job_id,
                status=JobStatus.FAILED.value,
                error_message=f"System RAM threshold exceeded ({mem_rss:.1f} MB > {settings.max_ram_usage_mb} MB). Paused for safety."
            )
            return

        # 1. Pre-chunk or load existing chunks
        existing_chunks = db.get_chunks_for_job(job_id)
        if not existing_chunks:
            chunks: List[LogChunk] = list(log_chunker.chunk_log_file(file_path))
            for c in chunks:
                db.create_chunk(
                    job_id=job_id,
                    chunk_index=c.chunk_id,
                    start_line=c.start_line,
                    end_line=c.end_line,
                    input_tokens=c.input_tokens,
                    reserved_output_tokens=c.reserved_output_tokens,
                    total_budget=c.total_budget
                )
            db.update_job(job_id, total_chunks=len(chunks), current_stage=Stage.ANALYZING.value)
            existing_chunks = db.get_chunks_for_job(job_id)
        else:
            db.update_job(job_id, current_stage=Stage.ANALYZING.value)

        total_chunks = len(existing_chunks)
        compact_context = CompactContext()
        completed_count = sum(1 for c in existing_chunks if c["status"] == ChunkStatus.COMPLETED.value)
        failed_count = sum(1 for c in existing_chunks if c["status"] == ChunkStatus.FAILED.value)
        total_tokens_accumulated = 0

        # Read system and analysis prompt templates
        sys_prompt = (settings.prompts_dir / "system_prompt.txt").read_text(encoding="utf-8")
        analysis_template = (settings.prompts_dir / "analysis_prompt.txt").read_text(encoding="utf-8")

        # Reconstruct chunks text by re-reading or streaming
        chunk_dict_map = {c["chunk_index"]: c for c in existing_chunks}
        all_chunks_stream = list(log_chunker.chunk_log_file(file_path))

        # Collect event summaries for full-file correlation
        all_file_events = []

        # 2. Sequential Multi-Pass Inference
        for chunk in all_chunks_stream:
            chunk_record = chunk_dict_map.get(chunk.chunk_id)
            if not chunk_record:
                continue

            all_file_events.extend(chunk.events)

            # Skip already completed chunks for resumption resilience
            if chunk_record["status"] == ChunkStatus.COMPLETED.value:
                continue

            db.update_chunk(chunk_record["id"], status=ChunkStatus.PROCESSING.value)

            # Assemble analysis prompt with dynamic compact context
            rendered_user_prompt = analysis_template.format(
                chunk_id=chunk.chunk_id,
                start_line=chunk.start_line,
                end_line=chunk.end_line,
                compact_context_json=compact_context.to_json(),
                log_entries_text=chunk.log_text
            )

            messages = [
                {"role": "system", "content": sys_prompt},
                {"role": "user", "content": rendered_user_prompt}
            ]

            # Model Call with retry handling
            max_retries = 2
            success = False
            model_resp = None

            for attempt in range(max_retries):
                try:
                    model_resp = await model_service.generate_completion(
                        messages=messages,
                        max_tokens=settings.reserved_output_tokens,
                        temperature=0.1,
                        timeout_seconds=60.0
                    )
                    success = True
                    break
                except Exception as e:
                    logger.warning(f"Chunk {chunk.chunk_id} inference attempt {attempt + 1} failed: {e}")
                    db.update_chunk(chunk_record["id"], retry_count=attempt + 1)
                    await asyncio.sleep(1.0)

            if not success or not model_resp:
                db.update_chunk(chunk_record["id"], status=ChunkStatus.FAILED.value)
                failed_count += 1
                db.update_job(
                    job_id,
                    failed_chunks=failed_count,
                    completed_chunks=completed_count
                )
                continue

            # Safe JSON extraction and line-number validation
            parsed_output = parse_and_validate_chunk_response(
                raw_response=model_resp["content"],
                chunk_id=chunk.chunk_id,
                start_line=chunk.start_line,
                end_line=chunk.end_line
            )

            # Update compact context with AI updates + deterministic signals
            compact_context.update_from_chunk(
                ai_updates=parsed_output.context_updates,
                chunk_events=chunk.events
            )

            # Save individual findings immediately to database
            for f in parsed_output.findings:
                finding_data = f.model_dump()
                db.save_finding(job_id=job_id, chunk_id=chunk_record["id"], finding=finding_data)

            # Persist chunk result and token telemetry
            prompt_tok = model_resp.get("prompt_tokens", 0)
            comp_tok = model_resp.get("completion_tokens", 0)
            total_tokens_accumulated += (prompt_tok + comp_tok)

            db.save_chunk_result(
                chunk_id=chunk_record["id"],
                job_id=job_id,
                raw_model_response=model_resp["content"],
                parsed_json=parsed_output.model_dump(),
                compact_context_after=compact_context.model_dump(),
                prompt_tokens=prompt_tok,
                completion_tokens=comp_tok,
                duration_ms=model_resp.get("duration_ms", 0)
            )

            db.update_chunk(chunk_record["id"], status=ChunkStatus.COMPLETED.value)
            completed_count += 1

            db.update_job(
                job_id,
                completed_chunks=completed_count,
                failed_chunks=failed_count,
                total_tokens=total_tokens_accumulated
            )

        # 3. Global Finding Correlation & Consolidated Report Generation
        db.update_job(job_id, current_stage=Stage.CORRELATING.value)

        raw_findings = db.get_findings_for_job(job_id)

        # Perform global cross-chunk correlation
        correlated_findings = correlation_engine.correlate_and_synthesize(
            raw_findings=raw_findings,
            chunk_events_summary=all_file_events
        )

        # Generate final consolidated report
        final_report = report_service.generate_consolidated_report(
            job=job,
            correlated_findings=correlated_findings,
            chunks_metadata=existing_chunks
        )

        # Persist report
        db.save_final_report(
            job_id=job_id,
            report_data=final_report,
            summary=final_report["executive_summary"],
            counts=final_report["statistics"]
        )

        db.update_job(
            job_id,
            status=JobStatus.COMPLETED.value,
            current_stage=Stage.REPORT_READY.value
        )
        logger.info(f"Job {job_id} successfully completed. {len(correlated_findings)} correlated findings produced.")

# Singleton analysis service
analysis_service = AnalysisService()
