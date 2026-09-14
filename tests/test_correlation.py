from pathlib import Path

from lace.config import load_settings
from lace.correlation import correlate
from lace.models import Finding, Severity
from tests.conftest import BASE

SETTINGS = load_settings(Path(__file__).resolve().parents[1] / "config.example.yaml")
SRC = "192.0.2.10"


def _finding(rule_id: str, tags: list[str] | None = None) -> Finding:
    return Finding(
        rule_id=rule_id,
        src_ip=SRC,
        window_start=BASE,
        window_end=BASE,
        evidence={},
        severity=Severity.MEDIUM,
        reputation_tags=tags or [],
    )


def test_multiple_rules_merge_into_one_alert():
    alerts = correlate([_finding("port_scan"), _finding("brute_force")], SETTINGS)
    assert len(alerts) == 1
    alert = alerts[0]
    assert set(alert.triggered_rules) == {"brute_force", "port_scan"}
    expected = SETTINGS.rule_weights.port_scan + SETTINGS.rule_weights.brute_force
    assert alert.risk_score == expected


def test_same_rule_counts_hits_but_weight_once():
    findings = [_finding("port_scan") for _ in range(3)]
    alerts = correlate(findings, SETTINGS)
    assert alerts[0].risk_score == SETTINGS.rule_weights.port_scan
    assert alerts[0].hit_count["port_scan"] == 3


def test_ioc_bonus_applied():
    findings = [_finding("beaconing", tags=["known_c2"])]
    alerts = correlate(findings, SETTINGS)
    assert alerts[0].risk_score == SETTINGS.rule_weights.beaconing + SETTINGS.ioc_bonus
    assert alerts[0].reputation_tags == ["known_c2"]


def test_score_capped_at_100():
    findings = [
        _finding("port_scan", tags=["known_c2"]),
        _finding("brute_force"),
        _finding("beaconing"),
        _finding("exfil_volume"),
    ]
    raw = (
        SETTINGS.rule_weights.port_scan
        + SETTINGS.rule_weights.brute_force
        + SETTINGS.rule_weights.beaconing
        + SETTINGS.rule_weights.exfil_volume
        + SETTINGS.ioc_bonus
    )
    assert raw > 100
    alerts = correlate(findings, SETTINGS)
    assert alerts[0].risk_score == 100
