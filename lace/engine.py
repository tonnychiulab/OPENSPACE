from __future__ import annotations

from lace.config import Settings
from lace.correlation import correlate
from lace.detectors.beaconing import BeaconingDetector
from lace.detectors.brute_force import BruteForceDetector
from lace.detectors.exfil_volume import ExfilVolumeDetector
from lace.detectors.port_scan import PortScanDetector
from lace.enrichment import enrich
from lace.models import Alert, Finding, NormalizedEvent
from lace.windowing import WindowManager


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

    findings: list[Finding] = []
    for event in ordered:
        pair = f"{event.src_ip}|{event.dst_ip}"
        exfil_view = exfil_windows.add(
            event.src_ip, event, settings.exfil_volume.window_seconds
        )
        findings.extend(exfil.detect(exfil_view, settings.exfil_volume))

        if event.dst_port is not None:
            scan_view = port_windows.add(
                pair, event, settings.port_scan.window_seconds
            )
            findings.extend(port_scan.detect(scan_view, settings.port_scan))

        if event.event_type in ("auth_failure", "auth_success"):
            brute_view = brute_windows.add(
                event.src_ip, event, settings.brute_force.window_seconds
            )
            findings.extend(brute_force.detect(brute_view, settings.brute_force))
        else:
            beacon_view = beacon_windows.add(
                pair, event, settings.beaconing.window_seconds
            )
            findings.extend(beaconing.detect(beacon_view, settings.beaconing))

    enriched = [enrich(finding, ioc_map) for finding in findings]
    alerts = correlate(enriched, settings)
    return enriched, alerts
