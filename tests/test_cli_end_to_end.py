import json
from pathlib import Path

from lace.cli import main

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
CONFIG = ROOT / "config.example.yaml"


def test_cli_fail_fast_on_bad_config(tmp_path, capsys):
    raw = (ROOT / "config.example.yaml").read_text(encoding="utf-8")
    broken = tmp_path / "bad.yaml"
    broken.write_text(raw.replace("window_seconds: 60", "# window_seconds removed"), encoding="utf-8")
    input_file = tmp_path / "never-read.jsonl"
    input_file.write_text("{not even read}\n", encoding="utf-8")
    code = main(
        [
            "run",
            "--config",
            str(broken),
            "--input",
            str(input_file),
            "--format",
            "jsonl",
            "--output",
            str(tmp_path / "out.json"),
        ]
    )
    captured = capsys.readouterr()
    assert code == 1
    assert "port_scan.window_seconds" in captured.err
    assert not (tmp_path / "out.json").exists()


def test_cli_end_to_end_jsonl(tmp_path, capsys):
    out = tmp_path / "alerts.json"
    code = main(
        [
            "run",
            "--config",
            str(CONFIG),
            "--input",
            str(FIXTURES / "e2e_all_rules.jsonl"),
            "--format",
            "jsonl",
            "--ioc-list",
            str(FIXTURES / "sample_ioc_list.csv"),
            "--output",
            str(out),
        ]
    )
    assert code == 0
    alerts = json.loads(out.read_text(encoding="utf-8"))
    by_ip = {row["src_ip"]: row for row in alerts}
    assert "192.0.2.40" not in by_ip
    assert "port_scan" in by_ip["192.0.2.10"]["triggered_rules"]
    assert "brute_force" in by_ip["192.0.2.20"]["triggered_rules"]
    assert "beaconing" in by_ip["203.0.113.9"]["triggered_rules"]
    assert by_ip["203.0.113.9"]["reputation_tags"] == ["known_c2"]
    assert "exfil_volume" in by_ip["192.0.2.30"]["triggered_rules"]
    printed = capsys.readouterr().out
    assert "processed_events=" in printed
    assert "parse_errors=" in printed


def test_cli_benign_empty_output(tmp_path, capsys):
    out = tmp_path / "alerts.json"
    code = main(
        [
            "run",
            "--config",
            str(CONFIG),
            "--input",
            str(FIXTURES / "benign.jsonl"),
            "--format",
            "jsonl",
            "--ioc-list",
            str(FIXTURES / "sample_ioc_list.csv"),
            "--output",
            str(out),
        ]
    )
    assert code == 0
    assert json.loads(out.read_text(encoding="utf-8")) == []
    assert "無異常事件" in capsys.readouterr().out
