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
        """Serialize to compact JSON string."""
        return self.model_dump_json(exclude_none=True)

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

            if not ip or ip == "Unknown":
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

            # Attack indicators
            for ind in ai_updates.get("attack_indicators", []):
                if ind and ind not in self.attack_indicators:
                    self.attack_indicators.append(ind)
            # Cap indicators to top 5 to prevent token bloat
            if len(self.attack_indicators) > 5:
                self.attack_indicators = self.attack_indicators[-5:]

            # Open investigations
            for inv in ai_updates.get("open_investigations", []):
                if inv and inv not in self.open_investigations:
                    self.open_investigations.append(inv)
            if len(self.open_investigations) > 4:
                self.open_investigations = self.open_investigations[-4:]
