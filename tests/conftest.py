"""Shared fixtures for Salus iT600 tests."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from custom_components.salus.const import (
    CURRENT_HVAC_HEAT,
    HVAC_MODE_AUTO,
    HVAC_MODE_HEAT,
    HVAC_MODE_OFF,
    PRESET_FOLLOW_SCHEDULE,
    PRESET_OFF,
    PRESET_PERMANENT_HOLD,
    SUPPORT_CLOSE,
    SUPPORT_OPEN,
    SUPPORT_PRESET_MODE,
    SUPPORT_SET_POSITION,
    SUPPORT_TARGET_TEMPERATURE,
)
from custom_components.salus.models import (
    BinarySensorDevice,
    ClimateDevice,
    CoverDevice,
    GatewayDevice,
    SensorDevice,
    SwitchDevice,
)


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    """Enable custom integrations for all tests."""
    yield


@pytest.fixture
def mock_gateway() -> AsyncMock:
    """Return a fully-mocked IT600Gateway."""
    gateway = AsyncMock()
    gateway.connect = AsyncMock(return_value="AA:BB:CC:DD:EE:FF")
    gateway.poll_status = AsyncMock()
    gateway.close = AsyncMock()
    gateway.get_gateway_device = MagicMock(return_value=None)
    gateway.get_climate_devices = MagicMock(return_value={})
    gateway.get_binary_sensor_devices = MagicMock(return_value={})
    gateway.get_switch_devices = MagicMock(return_value={})
    gateway.get_cover_devices = MagicMock(return_value={})
    gateway.get_sensor_devices = MagicMock(return_value={})
    return gateway


@pytest.fixture
def gateway_device() -> GatewayDevice:
    """Return a sample GatewayDevice."""
    return GatewayDevice(
        name="Salus Gateway",
        unique_id="AA:BB:CC:DD:EE:FF",
        data={"UniID": "gw001"},
        manufacturer="SALUS",
        model="SG600",
        sw_version="1.2.3",
    )


@pytest.fixture
def climate_device() -> ClimateDevice:
    """Return a sample ClimateDevice (iT600TH-style)."""
    return ClimateDevice(
        available=True,
        name="Living Room Thermostat",
        unique_id="climate_001",
        temperature_unit="°C",
        precision=0.1,
        current_temperature=21.5,
        target_temperature=22.0,
        max_temp=35.0,
        min_temp=5.0,
        current_humidity=None,
        hvac_mode=HVAC_MODE_HEAT,
        hvac_action=CURRENT_HVAC_HEAT,
        hvac_modes=[HVAC_MODE_OFF, HVAC_MODE_HEAT, HVAC_MODE_AUTO],
        preset_mode=PRESET_FOLLOW_SCHEDULE,
        preset_modes=[PRESET_FOLLOW_SCHEDULE, PRESET_PERMANENT_HOLD, PRESET_OFF],
        fan_mode=None,
        fan_modes=None,
        locked=None,
        supported_features=SUPPORT_TARGET_TEMPERATURE | SUPPORT_PRESET_MODE,
        device_class="temperature",
        data={"UniID": "climate_001", "Endpoint": 1},
        manufacturer="SALUS",
        model="iT600",
        sw_version="1.0.0",
    )


@pytest.fixture
def binary_sensor_device() -> BinarySensorDevice:
    """Return a sample BinarySensorDevice."""
    return BinarySensorDevice(
        available=True,
        name="Front Door",
        unique_id="binary_001",
        is_on=False,
        device_class="window",
        data={"UniID": "binary_001", "Endpoint": 1},
        manufacturer="SALUS",
        model="SW600",
        sw_version="2.0.0",
    )


@pytest.fixture
def switch_device() -> SwitchDevice:
    """Return a sample SwitchDevice."""
    return SwitchDevice(
        available=True,
        name="Kitchen Plug",
        unique_id="switch_001_1",
        is_on=True,
        device_class="outlet",
        data={"UniID": "switch_001", "Endpoint": 1},
        manufacturer="SALUS",
        model="SP600",
        sw_version="3.0.0",
    )


@pytest.fixture
def cover_device() -> CoverDevice:
    """Return a sample CoverDevice."""
    return CoverDevice(
        available=True,
        name="Bedroom Blinds",
        unique_id="cover_001",
        current_cover_position=75,
        is_opening=None,
        is_closing=None,
        is_closed=False,
        supported_features=SUPPORT_OPEN | SUPPORT_CLOSE | SUPPORT_SET_POSITION,
        device_class=None,
        data={"UniID": "cover_001", "Endpoint": 1},
        manufacturer="SALUS",
        model="RS600",
        sw_version="4.0.0",
    )


@pytest.fixture
def sensor_device() -> SensorDevice:
    """Return a sample SensorDevice."""
    return SensorDevice(
        available=True,
        name="Office Temperature",
        unique_id="sensor_001_temp",
        state=23.4,
        unit_of_measurement="°C",
        device_class="temperature",
        data={"UniID": "sensor_001", "Endpoint": 1},
        manufacturer="SALUS",
        model="TS600",
        sw_version="5.0.0",
    )
