"""Tests for Salus iT600 data models."""

from __future__ import annotations

import dataclasses

import pytest


class TestGatewayDevice:
    """Tests for GatewayDevice dataclass."""

    def test_creation(self, gateway_device):
        assert gateway_device.name == "Salus Gateway"
        assert gateway_device.unique_id == "AA:BB:CC:DD:EE:FF"
        assert gateway_device.manufacturer == "SALUS"
        assert gateway_device.model == "SG600"
        assert gateway_device.sw_version == "1.2.3"

    def test_frozen(self, gateway_device):
        with pytest.raises(dataclasses.FrozenInstanceError):
            gateway_device.name = "new"

    def test_slots(self, gateway_device):
        """Frozen + slots dataclasses reject arbitrary attributes."""
        with pytest.raises((AttributeError, TypeError)):
            gateway_device.nonexistent = True


class TestClimateDevice:
    """Tests for ClimateDevice dataclass."""

    def test_creation(self, climate_device):
        assert climate_device.available is True
        assert climate_device.name == "Living Room Thermostat"
        assert climate_device.current_temperature == 21.5
        assert climate_device.target_temperature == 22.0
        assert climate_device.hvac_mode == "heat"
        assert climate_device.precision == 0.1

    def test_frozen(self, climate_device):
        with pytest.raises(dataclasses.FrozenInstanceError):
            climate_device.target_temperature = 25.0

    def test_nullable_fields(self, climate_device):
        assert climate_device.current_humidity is None
        assert climate_device.fan_mode is None
        assert climate_device.fan_modes is None
        assert climate_device.locked is None


class TestBinarySensorDevice:
    """Tests for BinarySensorDevice dataclass."""

    def test_creation(self, binary_sensor_device):
        assert binary_sensor_device.name == "Front Door"
        assert binary_sensor_device.is_on is False
        assert binary_sensor_device.device_class == "window"

    def test_frozen(self, binary_sensor_device):
        with pytest.raises(dataclasses.FrozenInstanceError):
            binary_sensor_device.is_on = True


class TestSwitchDevice:
    """Tests for SwitchDevice dataclass."""

    def test_creation(self, switch_device):
        assert switch_device.name == "Kitchen Plug"
        assert switch_device.is_on is True
        assert switch_device.device_class == "outlet"

    def test_frozen(self, switch_device):
        with pytest.raises(dataclasses.FrozenInstanceError):
            switch_device.is_on = False


class TestCoverDevice:
    """Tests for CoverDevice dataclass."""

    def test_creation(self, cover_device):
        assert cover_device.name == "Bedroom Blinds"
        assert cover_device.current_cover_position == 75
        assert cover_device.is_closed is False

    def test_frozen(self, cover_device):
        with pytest.raises(dataclasses.FrozenInstanceError):
            cover_device.is_closed = True


class TestSensorDevice:
    """Tests for SensorDevice dataclass."""

    def test_creation(self, sensor_device):
        assert sensor_device.name == "Office Temperature"
        assert sensor_device.state == 23.4
        assert sensor_device.device_class == "temperature"

    def test_frozen(self, sensor_device):
        with pytest.raises(dataclasses.FrozenInstanceError):
            sensor_device.state = 99.0
