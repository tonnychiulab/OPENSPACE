from __future__ import annotations

import statistics

from lace.config import BeaconingConfig
from lace.detectors.base import Detector
from lace.models import Finding, NormalizedEvent, Severity


def coefficient_of_variation(intervals: list[float]) -> float | None:
    """Population stdev / mean of inter-arrival times. None if undefined."""
    if len(intervals) < 2:
        return None
    mean = statistics.mean(intervals)
    if mean == 0:
        return None
    return statistics.pstdev(intervals) / mean


class BeaconingDetector(Detector):
    """Low coefficient of variation on consecutive connection intervals → beaconing."""

    def detect(
        self, window: list[NormalizedEvent], config: BeaconingConfig
    ) -> list[Finding]:
        conns = [
            e
            for e in window
            if e.event_type not in ("auth_failure", "auth_success")
        ]
        if len(conns) < config.min_samples:
            return []
        timestamps = [e.timestamp for e in conns]
        intervals = [
            (timestamps[i] - timestamps[i - 1]).total_seconds()
            for i in range(1, len(timestamps))
        ]
        cv = coefficient_of_variation(intervals)
        if cv is None or cv >= config.cv_threshold:
            return []
        mean_interval = statistics.mean(intervals)
        return [
            Finding(
                rule_id="beaconing",
                src_ip=conns[0].src_ip,
                window_start=conns[0].timestamp,
                window_end=conns[-1].timestamp,
                evidence={
                    "dst_ip": conns[0].dst_ip,
                    "sample_count": len(conns),
                    "mean_interval_seconds": round(mean_interval, 4),
                    "coefficient_of_variation": round(cv, 6),
                },
                severity=Severity.MEDIUM,
            )
        ]
