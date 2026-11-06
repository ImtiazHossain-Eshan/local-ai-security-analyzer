"""
Finding Merger for Sentinel.
Deduplicates, groups, and merges repeated findings across chunks
while strictly preserving all original line references.
"""
import hashlib
from typing import List, Dict, Any
from app.database.models import Severity, Disposition

def normalize_attack_category(attack_type: str) -> str:
    """Normalize freeform attack descriptions into standard categories."""
    t = (attack_type or "").lower()
    if any(k in t for k in ["prompt", "ignore previous", "adversarial prompt"]):
        return "prompt_injection"
    if any(k in t for k in ["brute", "credential", "password", "login"]):
        return "brute_force"
    if any(k in t for k in ["sql", "sqli", "union select", "1=1"]):
        return "sql_injection"
    if any(k in t for k in ["scan", "probe", "wp-admin", "phpmyadmin", "directory", "backup", ".env", ".git"]):
        return "endpoint_scanning"
    if any(k in t for k in ["unauthorized", "privilege", "export", "compromise", "exfiltration"]):
        return "unauthorized_access"
    if any(k in t for k in ["rate", "flood", "429", "dos", "automation"]):
        return "unusual_rate"
    if any(k in t for k in ["supplier", "502", "timeout", "upstream", "operational"]):
        return "operational_anomaly"
    return "other_anomaly"


def compute_finding_fingerprint(category: str, source_ip: str, account: str = None) -> str:
    """Deterministic hash fingerprint for grouping matching findings."""
    raw = f"{category}:{source_ip or 'unknown'}:{(account or '').lower()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def merge_chunk_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Groups findings by category and entity, merges evidence arrays without duplicates,
    and sorts evidence strictly by original physical line number.
    """
    grouped: Dict[str, Dict[str, Any]] = {}

    for f in findings:
        cat = normalize_attack_category(f.get("attack_type", ""))
        ip = f.get("source_ip", "Unknown")
        acct = f.get("account")
        fp = compute_finding_fingerprint(cat, ip, acct)

        if fp not in grouped:
            grouped[fp] = {
                "fingerprint": fp,
                "category": cat,
                "attack_type": f.get("attack_type", "Security Finding"),
                "severity": f.get("severity", Severity.LOW.value),
                "source_ip": ip,
                "account": acct,
                "evidence": [],
                "reasons": set(),
                "suggested_actions": set(),
                "confidences": [],
                "dispositions": set(),
                "chunk_ids": set()
            }

        target = grouped[fp]
        if f.get("chunk_id"):
            target["chunk_ids"].add(f["chunk_id"])

        if f.get("reason"):
            target["reasons"].add(f["reason"].strip())
        if f.get("suggested_action"):
            target["suggested_actions"].add(f["suggested_action"].strip())
        if "confidence" in f and isinstance(f["confidence"], (int, float)):
            target["confidences"].append(float(f["confidence"]))
        if f.get("disposition"):
            target["dispositions"].add(f["disposition"])

        # Add evidence items
        ev_items = f.get("evidence", [])
        if isinstance(ev_items, list):
            for ev in ev_items:
                if isinstance(ev, dict) and "line" in ev:
                    target["evidence"].append({
                        "line": int(ev["line"]),
                        "excerpt": str(ev.get("excerpt", ""))
                    })

    # Consolidate and finalize merged findings
    merged: List[Dict[str, Any]] = []
    for fp, item in grouped.items():
        # Deduplicate evidence while preserving line order
        unique_ev = {}
        for ev in item["evidence"]:
            line = ev["line"]
            if line not in unique_ev or len(ev["excerpt"]) > len(unique_ev[line]["excerpt"]):
                unique_ev[line] = ev

        sorted_evidence = sorted(unique_ev.values(), key=lambda x: x["line"])

        # Aggregate reason and action
        combined_reason = " ".join(item["reasons"]) if item["reasons"] else "Suspicious behavior identified."
        combined_action = " ".join(item["suggested_actions"]) if item["suggested_actions"] else "Review audit logs and monitor."

        avg_confidence = (
            round(sum(item["confidences"]) / len(item["confidences"]), 2)
            if item["confidences"] else 0.85
        )

        merged.append({
            "fingerprint": fp,
            "category": item["category"],
            "attack_type": item["attack_type"],
            "severity": item["severity"],
            "source_ip": item["source_ip"],
            "account": item["account"],
            "evidence": sorted_evidence,
            "reason": combined_reason,
            "suggested_action": combined_action,
            "confidence": avg_confidence,
            "disposition": next(iter(item["dispositions"]), Disposition.SUSPICIOUS.value),
            "chunk_count": len(item["chunk_ids"]),
            "first_line": sorted_evidence[0]["line"] if sorted_evidence else 0,
            "last_line": sorted_evidence[-1]["line"] if sorted_evidence else 0
        })

    return merged
