from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from lace.models import NormalizedEvent


def _parse_ts(value: object) -> datetime:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value)
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text)


def parse_jsonl(path: Path, stats) -> list[NormalizedEvent]:
    events: list[NormalizedEvent] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                payload = json.loads(stripped)
                if not isinstance(payload, dict):
                    raise ValueError("JSON line must be an object")
                events.append(
                    NormalizedEvent(
                        timestamp=_parse_ts(payload["timestamp"]),
                        src_ip=str(payload["src_ip"]),
                        dst_ip=str(payload["dst_ip"]),
                        dst_port=payload.get("dst_port"),
                        protocol=payload.get("protocol"),
                        bytes_out=int(payload.get("bytes_out") or 0),
                        event_type=str(payload.get("event_type") or "conn"),
                        raw=stripped,
                    )
                )
            except (json.JSONDecodeError, KeyError, ValueError, TypeError):
                stats.record(stripped)
    return events
