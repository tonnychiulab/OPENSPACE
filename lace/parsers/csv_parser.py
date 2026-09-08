from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path

from lace.config import CsvColumnMapping
from lace.models import NormalizedEvent


def _parse_ts(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text)


def _optional_int(value: str | None) -> int | None:
    if value is None or value.strip() == "":
        return None
    return int(value)


def _optional_str(value: str | None) -> str | None:
    if value is None or value.strip() == "":
        return None
    return value.strip()


def parse_csv(
    path: Path, columns: CsvColumnMapping, stats
) -> list[NormalizedEvent]:
    events: list[NormalizedEvent] = []
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            return events
        for row in reader:
            raw = ",".join(row.get(name, "") or "" for name in reader.fieldnames)
            try:
                events.append(
                    NormalizedEvent(
                        timestamp=_parse_ts(row[columns.timestamp]),
                        src_ip=row[columns.src_ip].strip(),
                        dst_ip=row[columns.dst_ip].strip(),
                        dst_port=_optional_int(row.get(columns.dst_port)),
                        protocol=_optional_str(row.get(columns.protocol)),
                        bytes_out=int(row.get(columns.bytes_out) or 0),
                        event_type=(row.get(columns.event_type) or "conn").strip()
                        or "conn",
                        raw=raw,
                    )
                )
            except (KeyError, ValueError, TypeError):
                stats.record(raw)
    return events
