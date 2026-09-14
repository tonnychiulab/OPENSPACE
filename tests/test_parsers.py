from pathlib import Path

from lace.config import load_settings
from lace.parsers import ParseStats, parse

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
SETTINGS = load_settings(ROOT / "config.example.yaml")


def test_csv_row_count_matches_data_rows():
    stats = ParseStats()
    events = list(
        parse(
            FIXTURES / "sample_firewall.csv",
            "csv",
            csv_columns=SETTINGS.csv_columns,
            stats=stats,
        )
    )
    data_rows = sum(
        1
        for line in (FIXTURES / "sample_firewall.csv").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ) - 1
    assert len(events) == data_rows
    assert stats.skipped == 0
    assert events[0].src_ip


def test_jsonl_skips_bad_line_and_keeps_rest():
    stats = ParseStats()
    events = list(parse(FIXTURES / "sample_events.jsonl", "jsonl", stats=stats))
    assert stats.skipped >= 1
    assert len(events) >= 1
    assert all(e.src_ip for e in events)


def test_syslog_rfc5424_extracts_addresses():
    stats = ParseStats()
    events = list(parse(FIXTURES / "sample_syslog.log", "syslog", stats=stats))
    assert stats.skipped == 0
    assert any(e.event_type == "auth_failure" for e in events)
    assert any(e.dst_port == 22 for e in events)
