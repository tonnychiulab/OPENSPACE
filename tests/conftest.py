from datetime import datetime, timedelta, timezone

from lace.models import NormalizedEvent

BASE = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)


def event(
    offset_s: float,
    src: str,
    dst: str,
    *,
    dst_port: int | None = 443,
    protocol: str = "tcp",
    bytes_out: int = 100,
    event_type: str = "conn",
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=BASE + timedelta(seconds=offset_s),
        src_ip=src,
        dst_ip=dst,
        dst_port=dst_port,
        protocol=protocol,
        bytes_out=bytes_out,
        event_type=event_type,
        raw="",
    )
