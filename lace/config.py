from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError


class ConfigError(Exception):
    """Raised when the YAML settings file is missing, malformed, or incomplete."""


class CsvColumnMapping(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: str
    src_ip: str
    dst_ip: str
    dst_port: str
    protocol: str
    bytes_out: str
    event_type: str


class PortScanConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    window_seconds: int = Field(gt=0)
    unique_dst_ports: int = Field(gt=0)


class BruteForceConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    window_seconds: int = Field(gt=0)
    failure_threshold: int = Field(gt=0)


class BeaconingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    window_seconds: int = Field(gt=0)
    cv_threshold: float = Field(gt=0)
    min_samples: int = Field(gt=1)


class ExfilVolumeConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    window_seconds: int = Field(gt=0)
    bytes_threshold_mb: float = Field(gt=0)

    @property
    def bytes_threshold(self) -> int:
        return int(self.bytes_threshold_mb * 1024 * 1024)


class RuleWeights(BaseModel):
    model_config = ConfigDict(extra="forbid")

    port_scan: int = Field(ge=0)
    brute_force: int = Field(ge=0)
    beaconing: int = Field(ge=0)
    exfil_volume: int = Field(ge=0)


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    port_scan: PortScanConfig
    brute_force: BruteForceConfig
    beaconing: BeaconingConfig
    exfil_volume: ExfilVolumeConfig
    rule_weights: RuleWeights
    ioc_bonus: int = Field(ge=0)
    ioc_list_path: str
    default_input: str
    default_output: str
    csv_columns: CsvColumnMapping


def _format_validation_error(exc: ValidationError) -> str:
    parts: list[str] = []
    for err in exc.errors():
        loc = ".".join(str(item) for item in err["loc"]) or "<root>"
        kind = err["type"]
        if kind == "missing":
            parts.append(f"missing required field: {loc}")
        else:
            parts.append(f"{loc}: {err['msg']}")
    return "; ".join(parts)


def load_settings(path: str | Path) -> Settings:
    path = Path(path)
    if not path.is_file():
        raise ConfigError(f"config file not found: {path}")
    try:
        raw: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}") from exc
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ConfigError(f"config root must be a mapping, got {type(raw).__name__}")
    try:
        return Settings.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(_format_validation_error(exc)) from exc
