from __future__ import annotations

from abc import ABC, abstractmethod

from lace.config import (
    BeaconingConfig,
    BruteForceConfig,
    ExfilVolumeConfig,
    PortScanConfig,
)
from lace.models import Finding, NormalizedEvent

RuleConfig = PortScanConfig | BruteForceConfig | BeaconingConfig | ExfilVolumeConfig


class Detector(ABC):
    @abstractmethod
    def detect(
        self, window: list[NormalizedEvent], config: RuleConfig
    ) -> list[Finding]:
        raise NotImplementedError
