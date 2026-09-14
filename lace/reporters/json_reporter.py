from __future__ import annotations

import json
from pathlib import Path

from lace.models import Alert


def _alert_dict(alert: Alert) -> dict:
    return {
        "src_ip": alert.src_ip,
        "risk_score": alert.risk_score,
        "triggered_rules": alert.triggered_rules,
        "hit_count": alert.hit_count,
        "reputation_tags": alert.reputation_tags,
        "first_seen": alert.first_seen.isoformat(),
        "last_seen": alert.last_seen.isoformat(),
    }


def write_json(alerts: list[Alert], path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = [_alert_dict(alert) for alert in alerts]
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
