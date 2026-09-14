from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class NormalizedEvent(BaseModel):
    timestamp: datetime
    src_ip: str
    dst_ip: str
    dst_port: int | None = None
    protocol: str | None = None
    bytes_out: int = 0
    event_type: str = "conn"
    raw: str = ""


class Finding(BaseModel):
    rule_id: str
    src_ip: str
    window_start: datetime
    window_end: datetime
    evidence: dict[str, Any] = Field(default_factory=dict)
    severity: Severity
    reputation_tags: list[str] = Field(default_factory=list)


class Alert(BaseModel):
    src_ip: str
    risk_score: int
    triggered_rules: list[str]
    hit_count: dict[str, int]
    reputation_tags: list[str] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime
