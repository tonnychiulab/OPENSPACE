import json

from lace.models import Alert
from lace.reporters.json_reporter import write_json
from lace.reporters.table_reporter import EMPTY_MESSAGE, render_table
from tests.conftest import BASE


def _alert(**kwargs) -> Alert:
    data = dict(
        src_ip="192.0.2.1",
        risk_score=40,
        triggered_rules=["port_scan"],
        hit_count={"port_scan": 1},
        reputation_tags=[],
        first_seen=BASE,
        last_seen=BASE,
    )
    data.update(kwargs)
    return Alert(**data)


def test_json_empty_list(tmp_path):
    out = tmp_path / "alerts.json"
    write_json([], out)
    assert json.loads(out.read_text(encoding="utf-8")) == []


def test_json_alert_fields(tmp_path):
    out = tmp_path / "alerts.json"
    write_json([_alert(reputation_tags=["known_c2"])], out)
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload[0].keys() >= {
        "src_ip",
        "risk_score",
        "triggered_rules",
        "hit_count",
        "reputation_tags",
        "first_seen",
        "last_seen",
    }


def test_table_sorts_by_score_desc():
    text = render_table(
        [_alert(src_ip="10.0.0.2", risk_score=10), _alert(src_ip="10.0.0.1", risk_score=90)]
    )
    assert text.splitlines()[2].startswith("10.0.0.1")


def test_table_empty_message():
    assert render_table([]) == EMPTY_MESSAGE
