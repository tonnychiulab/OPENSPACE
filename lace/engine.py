from __future__ import annotations

from lace.config import Settings
from lace.correlation import correlate
from lace.detectors.beaconing import BeaconingDetector
from lace.detectors.brute_force import BruteForceDetector
from lace.detectors.exfil_volume import ExfilVolumeDetector
from lace.detectors.port_scan import PortScanDetector
from lace.enrichment import enrich
from lace.models import Alert, Finding, NormalizedEvent, Severity
from lace.windowing import WindowManager

CONNECTION_TYPES = {"conn", "beacon"}
_SEV_RANK = {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3}


class RisingEdgeGate:
    """Emit a Finding when a rule first fires on a key, or when severity increases.

    Re-running detect() on every event would otherwise count window growth as
    extra hits. Clearing the key when the window falls back below threshold
    lets a later independent crossing increment hit_count.
    """

    def __init__(self) -> None:
        self._rank: dict[str, int] = {}

    def take(self, key: str, findings: list[Finding]) -> list[Finding]:
        if not findings:
            self._rank.pop(key, None)
            return []
        rank = _SEV_RANK[findings[0].severity]
        previous = self._rank.get(key)
        self._rank[key] = rank
        if previous is None or rank > previous:
            return findings
        return []


def analyze(
    events: list[NormalizedEvent],
    settings: Settings,
    ioc_map: dict[str, list[str]],
) -> tuple[list[Finding], list[Alert]]:
    ordered = sorted(events, key=lambda e: e.timestamp)
    port_windows = WindowManager()
    brute_windows = WindowManager()
    beacon_windows = WindowManager()
    exfil_windows = WindowManager()
    port_scan = PortScanDetector()
    brute_force = BruteForceDetector()
    beaconing = BeaconingDetector()
    exfil = ExfilVolumeDetector()
    edges = RisingEdgeGate()

    findings: list[Finding] = []
    for event in ordered:
        pair = f"{event.src_ip}|{event.dst_ip}"
        is_conn = event.event_type in CONNECTION_TYPES

        if is_conn:
            exfil_view = exfil_windows.add(
                event.src_ip, event, settings.exfil_volume.window_seconds
            )
            findings.extend(
                edges.take(
                    f"exfil|{event.src_ip}",
                    exfil.detect(exfil_view, settings.exfil_volume),
                )
            )
            beacon_view = beacon_windows.add(
                pair, event, settings.beaconing.window_seconds
            )
            findings.extend(
                edges.take(
                    f"beacon|{pair}",
                    beaconing.detect(beacon_view, settings.beaconing),
                )
            )
            if event.dst_port is not None:
                # Unique dest ports across all dest IPs for this source.
                scan_view = port_windows.add(
                    event.src_ip, event, settings.port_scan.window_seconds
                )
                findings.extend(
                    edges.take(
                        f"scan|{event.src_ip}",
                        port_scan.detect(scan_view, settings.port_scan),
                    )
                )

        if event.event_type in ("auth_failure", "auth_success"):
            brute_view = brute_windows.add(
                pair, event, settings.brute_force.window_seconds
            )
            findings.extend(
                edges.take(
                    f"brute|{pair}",
                    brute_force.detect(brute_view, settings.brute_force),
                )
            )

    enriched = [enrich(finding, ioc_map) for finding in findings]
    alerts = correlate(enriched, settings)
    return enriched, alerts
