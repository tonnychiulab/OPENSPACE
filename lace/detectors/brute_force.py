from __future__ import annotations

from lace.config import BruteForceConfig
from lace.detectors.base import Detector
from lace.models import Finding, NormalizedEvent, Severity


class BruteForceDetector(Detector):
    """Count auth_failure in the window; raise severity if auth_success follows."""

    def detect(
        self, window: list[NormalizedEvent], config: BruteForceConfig
    ) -> list[Finding]:
        failures = [e for e in window if e.event_type == "auth_failure"]
        if len(failures) <= config.failure_threshold:
            return []
        crossed_at = failures[config.failure_threshold].timestamp
        success_after = [
            e
            for e in window
            if e.event_type == "auth_success" and e.timestamp >= crossed_at
        ]
        evidence: dict = {
            "failure_count": len(failures),
            "dst_ip": failures[0].dst_ip,
        }
        severity = Severity.MEDIUM
        if success_after:
            severity = Severity.HIGH
            evidence["note"] = "failure streak followed by success"
        return [
            Finding(
                rule_id="brute_force",
                src_ip=window[0].src_ip,
                window_start=window[0].timestamp,
                window_end=window[-1].timestamp,
                evidence=evidence,
                severity=severity,
            )
        ]
