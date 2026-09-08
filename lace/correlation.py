from __future__ import annotations

from collections import defaultdict

from lace.config import Settings
from lace.models import Alert, Finding


def correlate(findings: list[Finding], settings: Settings) -> list[Alert]:
    """One Alert per src_ip: unique-rule weights + optional IOC bonus, capped at 100."""
    grouped: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        grouped[finding.src_ip].append(finding)

    weights = settings.rule_weights.model_dump()
    alerts: list[Alert] = []
    for src_ip, group in grouped.items():
        hit_count: dict[str, int] = defaultdict(int)
        for finding in group:
            hit_count[finding.rule_id] += 1
        triggered = sorted(hit_count)
        score = sum(weights.get(rule_id, 0) for rule_id in triggered)
        tags: list[str] = []
        for finding in group:
            for tag in finding.reputation_tags:
                if tag not in tags:
                    tags.append(tag)
        if tags:
            score += settings.ioc_bonus
        score = min(100, score)
        times = [finding.window_start for finding in group] + [
            finding.window_end for finding in group
        ]
        alerts.append(
            Alert(
                src_ip=src_ip,
                risk_score=score,
                triggered_rules=triggered,
                hit_count=dict(hit_count),
                reputation_tags=tags,
                first_seen=min(times),
                last_seen=max(times),
            )
        )
    alerts.sort(key=lambda a: (-a.risk_score, a.src_ip))
    return alerts
