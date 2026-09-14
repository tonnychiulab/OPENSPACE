from __future__ import annotations

from lace.models import Alert

EMPTY_MESSAGE = "無異常事件"


def render_table(alerts: list[Alert]) -> str:
    if not alerts:
        return EMPTY_MESSAGE
    ordered = sorted(alerts, key=lambda a: (-a.risk_score, a.src_ip))
    headers = ("src_ip", "risk_score", "triggered_rules", "reputation_tags")
    rows = [
        (
            alert.src_ip,
            str(alert.risk_score),
            ",".join(alert.triggered_rules),
            ",".join(alert.reputation_tags) or "-",
        )
        for alert in ordered
    ]
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    def fmt(cols: tuple[str, ...]) -> str:
        return "  ".join(col.ljust(widths[i]) for i, col in enumerate(cols))
    lines = [fmt(headers), "  ".join("-" * w for w in widths)]
    lines.extend(fmt(row) for row in rows)
    return "\n".join(lines)


def print_table(alerts: list[Alert], file=None) -> None:
    print(render_table(alerts), file=file)
