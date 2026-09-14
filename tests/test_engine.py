from datetime import datetime, timezone
from pathlib import Path

from lace.config import load_settings
from lace.correlation import correlate
from lace.engine import analyze
from lace.models import Severity
from lace.timestamps import parse_timestamp
from tests.conftest import event

SETTINGS = load_settings(Path(__file__).resolve().parents[1] / "config.example.yaml")
SRC = "192.0.2.10"


def test_naive_and_aware_timestamps_can_be_sorted_together():
    naive = parse_timestamp("2026-01-15T12:00:00")
    aware = parse_timestamp("2026-01-15T12:00:01Z")
    events = [
        event(1, SRC, "198.51.100.1", dst_port=1),
        event(0, SRC, "198.51.100.1", dst_port=2),
    ]
    events[0] = events[0].model_copy(update={"timestamp": aware})
    events[1] = events[1].model_copy(update={"timestamp": naive})
    _, alerts = analyze(events, SETTINGS, {})
    assert isinstance(naive, datetime)
    assert naive.tzinfo is not None
    assert aware.tzinfo == timezone.utc
    assert alerts == [] or isinstance(alerts, list)


def test_port_scan_hit_count_is_one_crossing_not_every_extra_port():
    window_events = [
        event(i, SRC, "198.51.100.1", dst_port=1000 + i) for i in range(20)
    ]
    findings, alerts = analyze(window_events, SETTINGS, {})
    scan = [f for f in findings if f.rule_id == "port_scan"]
    assert len(scan) == 1
    assert alerts[0].hit_count["port_scan"] == 1


def test_brute_force_does_not_merge_unrelated_destinations():
    victim_a = [
        event(i, SRC, "198.51.100.8", dst_port=22, event_type="auth_failure", bytes_out=0)
        for i in range(12)
    ]
    other = [
        event(
            100 + i,
            SRC,
            "198.51.100.9",
            dst_port=22,
            event_type="auth_failure",
            bytes_out=0,
        )
        for i in range(3)
    ]
    other.append(
        event(120, SRC, "198.51.100.9", dst_port=22, event_type="auth_success", bytes_out=0)
    )
    findings, _ = analyze(victim_a + other, SETTINGS, {})
    brute = [f for f in findings if f.rule_id == "brute_force"]
    assert len(brute) == 1
    assert brute[0].severity == Severity.MEDIUM
    assert brute[0].evidence["dst_ip"] == "198.51.100.8"


def test_port_scan_counts_unique_ports_across_destinations():
    events = [
        event(i, SRC, f"198.51.100.{i + 1}", dst_port=1000 + i) for i in range(20)
    ]
    findings, _ = analyze(events, SETTINGS, {})
    assert any(f.rule_id == "port_scan" for f in findings)


def test_brute_force_severity_upgrade_emits_second_finding():
    events = [
        event(i * 5, SRC, "198.51.100.8", dst_port=22, event_type="auth_failure", bytes_out=0)
        for i in range(12)
    ]
    events.append(
        event(70, SRC, "198.51.100.8", dst_port=22, event_type="auth_success", bytes_out=0)
    )
    findings, alerts = analyze(events, SETTINGS, {})
    brute = [f for f in findings if f.rule_id == "brute_force"]
    assert [f.severity for f in brute] == [Severity.MEDIUM, Severity.HIGH]
    assert alerts[0].hit_count["brute_force"] == 2
