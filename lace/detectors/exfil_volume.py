from __future__ import annotations

from lace.config import ExfilVolumeConfig
from lace.detectors.base import Detector
from lace.models import Finding, NormalizedEvent, Severity


class ExfilVolumeDetector(Detector):
    """Sum bytes_out in the window; fire when over the configured MB threshold."""

    def detect(
        self, window: list[NormalizedEvent], config: ExfilVolumeConfig
    ) -> list[Finding]:
        if not window:
            return []
        total = sum(max(0, e.bytes_out) for e in window)
        if total <= config.bytes_threshold:
            return []
        dst_ips = {e.dst_ip for e in window}
        return [
            Finding(
                rule_id="exfil_volume",
                src_ip=window[0].src_ip,
                window_start=window[0].timestamp,
                window_end=window[-1].timestamp,
                evidence={
                    "total_bytes_out": total,
                    "unique_dst_ips": len(dst_ips),
                    "dst_ips": sorted(dst_ips),
                },
                severity=Severity.HIGH,
            )
        ]
