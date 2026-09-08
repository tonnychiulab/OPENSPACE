from __future__ import annotations

import re
from pathlib import Path

from lace.models import NormalizedEvent
from lace.timestamps import parse_timestamp

# RFC5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
RFC5424 = re.compile(
    r"^<(?P<pri>\d+)>(?P<ver>\d+)\s+"
    r"(?P<ts>\S+)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<app>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?P<rest>.*)$"
)

KV = re.compile(
    r"\b(?P<key>src_ip|dst_ip|dst_port|dpt|src|dst|protocol|proto|"
    r"bytes_out|event_type|type)=(?P<val>[^\s,;]+)"
)


def _extract(message: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for match in KV.finditer(message):
        found[match.group("key")] = match.group("val")
    return found


def _from_fields(fields: dict[str, str], raw: str, fallback_ts: str) -> NormalizedEvent:
    src = fields.get("src_ip") or fields.get("src") or ""
    dst = fields.get("dst_ip") or fields.get("dst") or ""
    if not src or not dst:
        raise ValueError("syslog message missing src or dst")
    port_raw = fields.get("dst_port") or fields.get("dpt")
    proto = fields.get("protocol") or fields.get("proto")
    event_type = fields.get("event_type") or fields.get("type") or "conn"
    ts_text = fields.get("timestamp") or fallback_ts
    return NormalizedEvent(
        timestamp=parse_timestamp(ts_text),
        src_ip=src,
        dst_ip=dst,
        dst_port=int(port_raw) if port_raw else None,
        protocol=proto,
        bytes_out=int(fields.get("bytes_out") or 0),
        event_type=event_type,
        raw=raw,
    )


def parse_syslog(path: Path, stats) -> list[NormalizedEvent]:
    events: list[NormalizedEvent] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            stripped = line.rstrip("\n")
            if not stripped.strip():
                continue
            match = RFC5424.match(stripped)
            if not match:
                stats.record(stripped)
                continue
            try:
                events.append(
                    _from_fields(_extract(match.group("rest")), stripped, match.group("ts"))
                )
            except (ValueError, TypeError, KeyError):
                stats.record(stripped)
    return events
