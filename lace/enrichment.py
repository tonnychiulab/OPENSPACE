from __future__ import annotations

import csv
from pathlib import Path

from lace.models import Finding


class IocError(Exception):
    """Raised when the IOC CSV cannot be loaded."""


def load_ioc_list(path: str | Path) -> dict[str, list[str]]:
    """Return IP → tags. Duplicate IPs accumulate tags in order, de-duplicated."""
    path = Path(path)
    if not path.is_file():
        raise IocError(f"IOC list not found: {path}")
    mapping: dict[str, list[str]] = {}
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise IocError(f"IOC list has no header: {path}")
        required = {"ip", "tag", "source"}
        missing = required - {name.strip() for name in reader.fieldnames}
        if missing:
            raise IocError(
                f"IOC list missing columns {sorted(missing)} in {path}"
            )
        for row_num, row in enumerate(reader, start=2):
            ip = (row.get("ip") or "").strip()
            tag = (row.get("tag") or "").strip()
            if not ip:
                raise IocError(f"IOC list row {row_num} has empty ip")
            tags = mapping.setdefault(ip, [])
            if tag and tag not in tags:
                tags.append(tag)
    return mapping


def _ips_from_finding(finding: Finding) -> set[str]:
    ips = {finding.src_ip}
    dst = finding.evidence.get("dst_ip")
    if isinstance(dst, str) and dst:
        ips.add(dst)
    dst_ips = finding.evidence.get("dst_ips")
    if isinstance(dst_ips, list):
        ips.update(str(item) for item in dst_ips)
    return ips


def enrich(finding: Finding, ioc_map: dict[str, list[str]]) -> Finding:
    tags: list[str] = []
    for ip in sorted(_ips_from_finding(finding)):
        for tag in ioc_map.get(ip, []):
            if tag not in tags:
                tags.append(tag)
    return finding.model_copy(update={"reputation_tags": tags})
