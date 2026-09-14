from pathlib import Path

import pytest
import yaml

from lace.config import ConfigError, load_settings

EXAMPLE = Path(__file__).resolve().parents[1] / "config.example.yaml"


def test_example_config_loads():
    settings = load_settings(EXAMPLE)
    assert settings.port_scan.window_seconds == 60
    assert settings.port_scan.unique_dst_ports == 15
    assert settings.exfil_volume.bytes_threshold == 500 * 1024 * 1024


def test_missing_port_scan_window_seconds_fails_fast(tmp_path):
    raw = yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))
    del raw["port_scan"]["window_seconds"]
    broken = tmp_path / "broken.yaml"
    broken.write_text(yaml.safe_dump(raw), encoding="utf-8")
    with pytest.raises(ConfigError) as exc:
        load_settings(broken)
    assert "port_scan.window_seconds" in str(exc.value)


def test_missing_file_mentions_path(tmp_path):
    missing = tmp_path / "nope.yaml"
    with pytest.raises(ConfigError, match="not found"):
        load_settings(missing)
