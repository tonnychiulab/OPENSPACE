from lace.config import (
    BeaconingConfig,
    BruteForceConfig,
    ExfilVolumeConfig,
    PortScanConfig,
)
from lace.detectors.beaconing import BeaconingDetector, coefficient_of_variation
from lace.detectors.brute_force import BruteForceDetector
from lace.detectors.exfil_volume import ExfilVolumeDetector
from lace.detectors.port_scan import PortScanDetector
from lace.models import Severity
from tests.conftest import event

SRC = "192.0.2.10"
DST = "198.51.100.1"


def test_port_scan_fires_when_unique_ports_exceed_threshold():
    config = PortScanConfig(window_seconds=60, unique_dst_ports=15)
    window = [
        event(i, SRC, DST, dst_port=1000 + i, bytes_out=1) for i in range(20)
    ]
    findings = PortScanDetector().detect(window, config)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "port_scan"
    assert finding.severity in (Severity.MEDIUM, Severity.HIGH)
    assert finding.evidence["unique_dst_ports"] == 20
    assert len(finding.evidence["ports"]) == 20


def test_port_scan_does_not_fire_on_normal_port_use():
    config = PortScanConfig(window_seconds=60, unique_dst_ports=15)
    window = [event(i, SRC, DST, dst_port=80 + i) for i in range(3)]
    assert PortScanDetector().detect(window, config) == []


def test_brute_force_fires_medium_on_failure_streak():
    config = BruteForceConfig(window_seconds=300, failure_threshold=10)
    window = [
        event(i * 5, SRC, DST, dst_port=22, event_type="auth_failure", bytes_out=0)
        for i in range(12)
    ]
    findings = BruteForceDetector().detect(window, config)
    assert len(findings) == 1
    assert findings[0].rule_id == "brute_force"
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].evidence["failure_count"] == 12


def test_brute_force_promotes_high_when_success_follows_failures():
    config = BruteForceConfig(window_seconds=300, failure_threshold=10)
    window = [
        event(i * 5, SRC, DST, dst_port=22, event_type="auth_failure", bytes_out=0)
        for i in range(12)
    ]
    window.append(
        event(70, SRC, DST, dst_port=22, event_type="auth_success", bytes_out=0)
    )
    findings = BruteForceDetector().detect(window, config)
    assert findings[0].severity == Severity.HIGH
    assert findings[0].evidence["note"] == "failure streak followed by success"


def test_beaconing_fires_on_regular_intervals():
    config = BeaconingConfig(window_seconds=600, cv_threshold=0.15, min_samples=6)
    # 8 connections, intervals clustered in 58–62s
    offsets = [0, 59, 120, 179, 241, 300, 361, 420]
    window = [event(t, SRC, DST, dst_port=443) for t in offsets]
    findings = BeaconingDetector().detect(window, config)
    assert len(findings) == 1
    cv = findings[0].evidence["coefficient_of_variation"]
    assert cv < 0.15
    assert "mean_interval_seconds" in findings[0].evidence


def test_beaconing_skips_when_sample_count_below_min():
    config = BeaconingConfig(window_seconds=600, cv_threshold=0.15, min_samples=6)
    window = [event(t * 60, SRC, DST) for t in range(3)]
    assert BeaconingDetector().detect(window, config) == []


def test_beaconing_does_not_fire_on_irregular_intervals():
    config = BeaconingConfig(window_seconds=600, cv_threshold=0.15, min_samples=6)
    offsets = [0, 10, 50, 200, 250, 400, 450, 748]
    window = [event(t, SRC, DST) for t in offsets]
    intervals = [float(offsets[i] - offsets[i - 1]) for i in range(1, len(offsets))]
    cv = coefficient_of_variation(intervals)
    assert cv is not None and cv > 0.15
    assert BeaconingDetector().detect(window, config) == []


def test_exfil_fires_when_bytes_exceed_threshold():
    config = ExfilVolumeConfig(window_seconds=600, bytes_threshold_mb=500)
    # 620 MiB split across a few flows
    chunk = int(620 * 1024 * 1024 / 4)
    window = [
        event(i * 30, SRC, f"198.51.100.{i+1}", bytes_out=chunk) for i in range(4)
    ]
    findings = ExfilVolumeDetector().detect(window, config)
    assert len(findings) == 1
    assert findings[0].rule_id == "exfil_volume"
    assert findings[0].evidence["total_bytes_out"] == chunk * 4
    assert findings[0].evidence["unique_dst_ips"] == 4


def test_exfil_does_not_fire_under_threshold():
    config = ExfilVolumeConfig(window_seconds=600, bytes_threshold_mb=500)
    window = [event(0, SRC, DST, bytes_out=1024)]
    assert ExfilVolumeDetector().detect(window, config) == []
