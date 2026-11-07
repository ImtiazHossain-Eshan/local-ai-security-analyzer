"""
Compact Security Context manager for Sentinel.
Carries high-signal security state between sequential chunk analyses
without context-window bloat.
"""
import json
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

class IPContext(BaseModel):
    username: Optional[str] = None
    failed_logins: int = 0
    successful_logins: int = 0
    first_seen_line: int = 0
    last_seen_line: int = 0
    endpoints: List[str] = Field(default_factory=list)
    has_compromise_indicator: bool = False

class CompactContext(BaseModel):
    known_ips: Dict[str, IPContext] = Field(default_factory=dict)
    attack_indicators: List[str] = Field(default_factory=list)
    open_investigations: List[str] = Field(default_factory=list)

    def to_json(self) -> str:
        """Serialize to compact JSON string strictly bounded to <100 tokens."""
        # Ensure pruned before serializing
        self._prune_context()
        return self.model_dump_json(exclude_none=True)

    def _prune_context(self):
        """Strictly bound context size to prevent prompt token overflow."""
        # Cap known_ips to top 4 most critical entities
        if len(self.known_ips) > 4:
            # Score: failed_logins * 2 + (10 if has_compromise_indicator else 0) + last_seen_line / 1000.0
            def score_ip(item):
                ip, ctx = item
                score = (ctx.failed_logins * 2) + (10 if ctx.has_compromise_indicator else 0)
                if ctx.successful_logins > 0 and ctx.failed_logins > 0:
                    score += 15 # escalating breach candidate
                return (score, ctx.last_seen_line)

            sorted_ips = sorted(self.known_ips.items(), key=score_ip, reverse=True)
            self.known_ips = dict(sorted_ips[:4])

        # Cap indicators and investigations
        if len(self.attack_indicators) > 3:
            self.attack_indicators = self.attack_indicators[-3:]
        if len(self.open_investigations) > 2:
            self.open_investigations = self.open_investigations[-2:]

    def update_from_chunk(
        self,
        ai_updates: Optional[Dict[str, Any]],
        chunk_events: List[Dict[str, Any]]
    ):
        """
        Merge AI-reported updates and deterministic log events into the context.
        Ensures cross-chunk facts are preserved even if AI misses subtle state.
        """
        # 1. Deterministic log signal extraction for authentication and sensitive paths
        for ev in chunk_events:
            line = ev.get("start_line", 0)
            ip = ev.get("client_ip")
            user = ev.get("username")
            status_code = ev.get("status_code", 0)

            if not ip or ip == "Unknown":
                continue

            # Only track external suspicious/auth IPs to prevent cluttering context
            is_auth = (status_code in (401, 403, 200) and user) or ("login" in ev.get("raw_text", "").lower())
            is_suspicious = status_code in (401, 403, 500, 502) or ev.get("is_threat_indicator", False)

            if not is_auth and not is_suspicious and ip not in self.known_ips:
                continue

            if ip not in self.known_ips:
                self.known_ips[ip] = IPContext(
                    username=user,
                    first_seen_line=line,
                    last_seen_line=line
                )
            
            ip_entry = self.known_ips[ip]
            if line > ip_entry.last_seen_line:
                ip_entry.last_seen_line = line
            if not ip_entry.username and user:
                ip_entry.username = user
            if status_code == 401:
                ip_entry.failed_logins += 1
            elif status_code == 200 and ip_entry.failed_logins > 0:
                ip_entry.successful_logins += 1
                ip_entry.has_compromise_indicator = True

        # 2. Process AI context updates if provided
        if ai_updates:
            # IP activities
            for act in ai_updates.get("ip_activities", []):
                ip = act.get("ip")
                if not ip or ip == "Unknown":
                    continue
                if ip not in self.known_ips:
                    self.known_ips[ip] = IPContext(
                        username=act.get("account"),
                        failed_logins=act.get("failed_logins", 0),
                        successful_logins=act.get("successful_logins", 0),
                        first_seen_line=act.get("first_line", 0),
                        last_seen_line=act.get("last_line", 0)
                    )
                else:
                    entry = self.known_ips[ip]
                    entry.failed_logins += act.get("failed_logins", 0)
                    entry.successful_logins += act.get("successful_logins", 0)
                    if act.get("account") and not entry.username:
                        entry.username = act.get("account")
                    if act.get("last_line", 0) > entry.last_seen_line:
                        entry.last_seen_line = act.get("last_line", 0)
                    if entry.failed_logins > 0 and entry.successful_logins > 0:
                        entry.has_compromise_indicator = True

            # Attack indicators
            for ind in ai_updates.get("attack_indicators", []):
                if ind and ind not in self.attack_indicators:
                    self.attack_indicators.append(ind)

            # Open investigations
            for inv in ai_updates.get("open_investigations", []):
                if inv and inv not in self.open_investigations:
                    self.open_investigations.append(inv)

        # Enforce strict pruning after updates
        self._prune_context()
