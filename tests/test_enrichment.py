from pathlib import Path

import pytest

from lace.enrichment import IocError, enrich, load_ioc_list
from lace.models import Finding, Severity
from tests.conftest import BASE

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _finding(src: str, dst: str | None = None) -> Finding:
    evidence = {"dst_ip": dst} if dst else {}
    return Finding(
        rule_id="beaconing",
        src_ip=src,
        window_start=BASE,
        window_end=BASE,
        evidence=evidence,
        severity=Severity.MEDIUM,
    )


def test_load_ioc_list_maps_ip_to_tags():
    mapping = load_ioc_list(FIXTURES / "sample_ioc_list.csv")
    assert mapping["203.0.113.9"] == ["known_c2"]


def test_enrich_hit_adds_reputation_tag():
    mapping = {"203.0.113.9": ["known_c2"]}
    result = enrich(_finding("203.0.113.9", "198.51.100.50"), mapping)
    assert result.reputation_tags == ["known_c2"]


def test_enrich_miss_leaves_empty_tags():
    mapping = {"203.0.113.9": ["known_c2"]}
    result = enrich(_finding("192.0.2.10"), mapping)
    assert result.reputation_tags == []


def test_enrich_empty_map():
    result = enrich(_finding("203.0.113.9"), {})
    assert result.reputation_tags == []


def test_missing_ioc_file_errors(tmp_path):
    with pytest.raises(IocError, match="not found"):
        load_ioc_list(tmp_path / "missing.csv")
