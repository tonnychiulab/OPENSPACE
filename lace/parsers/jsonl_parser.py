from __future__ import annotations

import json
from pathlib import Path

from lace.models import NormalizedEvent
from lace.timestamps import parse_timestamp


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
                src = payload.get("src_ip")
                dst = payload.get("dst_ip")
                if src is None or dst is None:
                    raise ValueError("src_ip and dst_ip are required")
                events.append(
                    NormalizedEvent(
                        timestamp=parse_timestamp(payload["timestamp"]),
                        src_ip=str(src),
                        dst_ip=str(dst),
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
