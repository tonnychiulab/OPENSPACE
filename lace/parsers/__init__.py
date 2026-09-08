from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Literal

from lace.config import CsvColumnMapping
from lace.models import NormalizedEvent
from lace.parsers.csv_parser import parse_csv
from lace.parsers.jsonl_parser import parse_jsonl
from lace.parsers.syslog_parser import parse_syslog

LogFormat = Literal["csv", "jsonl", "syslog"]


@dataclass
class ParseStats:
    skipped: int = 0
    samples: list[str] = field(default_factory=list)

    def record(self, line: str, limit: int = 5) -> None:
        self.skipped += 1
        if len(self.samples) < limit:
            self.samples.append(line[:200])


def parse(
    path: str | Path,
    format: LogFormat,
    *,
    csv_columns: CsvColumnMapping | None = None,
    stats: ParseStats | None = None,
) -> Iterator[NormalizedEvent]:
    stats = stats if stats is not None else ParseStats()
    path = Path(path)
    if format == "csv":
        if csv_columns is None:
            raise ValueError("csv_columns is required when format=csv")
        yield from parse_csv(path, csv_columns, stats)
    elif format == "jsonl":
        yield from parse_jsonl(path, stats)
    elif format == "syslog":
        yield from parse_syslog(path, stats)
    else:
        raise ValueError(f"unsupported format: {format}")
