"""
Safe JSON parsing, repair, and evidence validation for Sentinel.
Recovers from markdown fences, surrounding text, unclosed brackets,
and enforces line-number bounds strictly against chunk boundaries.
"""
import re
import json
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

from app.database.models import Severity, Disposition

class RawEvidence(BaseModel):
    line: int
    excerpt: str = ""

class RawFinding(BaseModel):
    attack_type: str = "Suspicious Activity"
    severity: str = "Medium"
    source_ip: str = "Unknown"
    account: Optional[str] = None
    evidence: List[RawEvidence] = Field(default_factory=list)
    reason: str = "Security anomaly detected in logs."
    suggested_action: str = "Investigate source and affected account."
    confidence: float = 0.85
    disposition: Optional[str] = "Suspicious activity"

class ParsedChunkOutput(BaseModel):
    chunk_id: int
    findings: List[RawFinding] = Field(default_factory=list)
    context_updates: Dict[str, Any] = Field(default_factory=dict)


def clean_markdown_and_extract_json(text: str) -> str:
    """Extract substring that is most likely a JSON object."""
    if not text:
        return ""

    # 1. Check for ```json ... ``` or ``` ... ```
    fence_pattern = re.compile(r'```(?:json)?\s*(\{.*?\})\s*```', re.DOTALL)
    match = fence_pattern.search(text)
    if match:
        return match.group(1).strip()

    # 2. Find outermost curly braces { ... }
    first_brace = text.find("{")
    last_brace = text.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        return text[first_brace:last_brace + 1].strip()

    # 3. If missing closing brace, return from first brace to end
    if first_brace != -1:
        return text[first_brace:].strip()

    return text.strip()


def repair_json_string(json_str: str) -> str:
    """Attempt heuristic repairs on broken or truncated JSON."""
    s = json_str.strip()
    if not s:
        return "{}"

    # Remove trailing commas before closing braces/brackets
    s = re.sub(r',\s*([\]\}])', r'\1', s)

    # Balance unclosed curly braces and square brackets
    open_curly = s.count("{")
    close_curly = s.count("}")
    open_square = s.count("[")
    close_square = s.count("]")

    if open_square > close_square:
        s += "]" * (open_square - close_square)
    if open_curly > close_curly:
        s += "}" * (open_curly - close_curly)

    return s


def normalize_severity(sev: str) -> Severity:
    val = (sev or "").strip().capitalize()
    if val in {"Critical", "Crit"}:
        return Severity.CRITICAL
    elif val in {"High", "H"}:
        return Severity.HIGH
    elif val in {"Medium", "Med", "Moderate"}:
        return Severity.MEDIUM
    return Severity.LOW


def parse_and_validate_chunk_response(
    raw_response: str,
    chunk_id: int,
    start_line: int,
    end_line: int
) -> ParsedChunkOutput:
    """
    Safely parse model output, repair malformed JSON, normalize fields,
    and validate that evidence line numbers are within [start_line, end_line].
    """
    extracted_text = clean_markdown_and_extract_json(raw_response)
    data: Optional[Dict[str, Any]] = None

    # First attempt: direct json.loads
    try:
        data = json.loads(extracted_text)
    except Exception:
        # Second attempt: heuristic repair
        repaired = repair_json_string(extracted_text)
        try:
            data = json.loads(repaired)
        except Exception:
            # Fallback: empty structure, preventing crashes
            data = {"chunk_id": chunk_id, "findings": [], "context_updates": {}}

    if not isinstance(data, dict):
        data = {"chunk_id": chunk_id, "findings": [], "context_updates": {}}

    validated_findings: List[RawFinding] = []
    raw_findings = data.get("findings", [])
    if isinstance(raw_findings, list):
        for f in raw_findings:
            if not isinstance(f, dict):
                continue

            # Validate and filter evidence
            validated_evidence: List[RawEvidence] = []
            ev_list = f.get("evidence", [])
            if isinstance(ev_list, list):
                for ev in ev_list:
                    if isinstance(ev, dict) and "line" in ev:
                        try:
                            line_num = int(ev["line"])
                            # Line number validation: must fall within chunk bounds
                            if start_line <= line_num <= end_line:
                                validated_evidence.append(RawEvidence(
                                    line=line_num,
                                    excerpt=str(ev.get("excerpt", ""))[:200]
                                ))
                        except (ValueError, TypeError):
                            pass

            # If model didn't supply valid evidence line, default to chunk's start line as fallback
            if not validated_evidence:
                validated_evidence.append(RawEvidence(
                    line=start_line,
                    excerpt="Referenced from chunk logs"
                ))

            # Normalize severity
            sev_norm = normalize_severity(f.get("severity", "Medium"))

            validated_findings.append(RawFinding(
                attack_type=str(f.get("attack_type", "Security anomaly"))[:100],
                severity=sev_norm.value,
                source_ip=str(f.get("source_ip", "Unknown"))[:45],
                account=str(f.get("account")) if f.get("account") else None,
                evidence=validated_evidence,
                reason=str(f.get("reason", "Suspicious event recorded."))[:500],
                suggested_action=str(f.get("suggested_action", "Investigate and monitor."))[:500],
                confidence=float(f.get("confidence", 0.85)) if isinstance(f.get("confidence"), (int, float)) else 0.85,
                disposition=str(f.get("disposition", "Suspicious activity"))
            ))

    return ParsedChunkOutput(
        chunk_id=chunk_id,
        findings=validated_findings,
        context_updates=data.get("context_updates", {}) if isinstance(data.get("context_updates"), dict) else {}
    )
