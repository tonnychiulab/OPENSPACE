from __future__ import annotations

from lace.config import PortScanConfig
from lace.detectors.base import Detector
from lace.models import Finding, NormalizedEvent, Severity


class PortScanDetector(Detector):
    """Unique dst_port count in the window for one (src_ip, dst_ip) pair."""

    def detect(
        self, window: list[NormalizedEvent], config: PortScanConfig
    ) -> list[Finding]:
        if not window:
            return []
        ports = sorted(
            {
                event.dst_port
                for event in window
                if event.dst_port is not None
            }
        )
        if len(ports) <= config.unique_dst_ports:
            return []
        src_ip = window[0].src_ip
        dst_ips = sorted({e.dst_ip for e in window})
        return [
            Finding(
                rule_id="port_scan",
                src_ip=src_ip,
                window_start=window[0].timestamp,
                window_end=window[-1].timestamp,
                evidence={
                    "dst_ip": dst_ips[0] if len(dst_ips) == 1 else None,
                    "dst_ips": dst_ips,
                    "unique_dst_ports": len(ports),
                    "ports": ports,
                },
                severity=Severity.MEDIUM,
            )
        ]
