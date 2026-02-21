"""Data models for Salus iT600 devices."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class GatewayDevice:
    """Salus gateway device info."""

    name: str
    unique_id: str
    data: dict[str, Any]
    manufacturer: str
    model: str | None
    sw_version: str | None


@dataclass(frozen=True, slots=True)
class ClimateDevice:
    """Thermostat / HVAC device."""

    available: bool
    name: str
    unique_id: str
    temperature_unit: str
    precision: float
    current_temperature: float
    target_temperature: float
    max_temp: float
    min_temp: float
    current_humidity: float | None
    hvac_mode: str
    hvac_action: str
    hvac_modes: list[str]
    preset_mode: str
    preset_modes: list[str]
    fan_mode: str | None
    fan_modes: list[str] | None
    locked: bool | None
    supported_features: int
    device_class: str
    data: dict[str, Any]
    manufacturer: str
    model: str | None
    sw_version: str | None


@dataclass(frozen=True, slots=True)
class BinarySensorDevice:
    """Door / window / smoke / leak sensor."""

    available: bool
    name: str
    unique_id: str
    is_on: bool
    device_class: str | None
    data: dict[str, Any]
    manufacturer: str
    model: str | None
    sw_version: str | None
    parent_unique_id: str | None = None


@dataclass(frozen=True, slots=True)
class SwitchDevice:
    """Smart plug / relay."""

    available: bool
    name: str
    unique_id: str
    is_on: bool
    device_class: str
    data: dict[str, Any]
    manufacturer: str
    model: str | None
    sw_version: str | None


@dataclass(frozen=True, slots=True)
class CoverDevice:
    """Roller shutter / blind."""

    available: bool
    name: str
    unique_id: str
    current_cover_position: int | None
    is_opening: bool | None
    is_closing: bool | None
    is_closed: bool
    supported_features: int
    device_class: str | None
    data: dict[str, Any]
    manufacturer: str
    model: str | None
    sw_version: str | None


@dataclass(frozen=True, slots=True)
class SensorDevice:
    """Temperature / generic sensor."""

    available: bool
    name: str
    unique_id: str
    state: Any
    unit_of_measurement: str
    device_class: str
    data: dict[str, Any]
    manufacturer: str
    model: str | None
    sw_version: str | None
    parent_unique_id: str | None = None
