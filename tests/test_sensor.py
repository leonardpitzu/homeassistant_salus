"""Tests for the Salus sensor entity."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

from homeassistant.components.sensor import SensorDeviceClass, SensorStateClass

from custom_components.salus.models import SensorDevice
from custom_components.salus.sensor import SalusSensor


def _make_entity(device: SensorDevice) -> SalusSensor:
    coordinator = MagicMock()
    coordinator.data = {device.unique_id: device}
    coordinator.async_request_refresh = AsyncMock()
    coordinator.async_add_listener = MagicMock(return_value=lambda: None)
    return SalusSensor(coordinator, device.unique_id, AsyncMock())


class TestSalusSensorProperties:
    """Test sensor entity property delegation."""

    def test_unique_id(self, sensor_device):
        entity = _make_entity(sensor_device)
        assert entity.unique_id == "sensor_001_temp"

    def test_name(self, sensor_device):
        entity = _make_entity(sensor_device)
        assert entity.name == "Office Temperature"

    def test_available(self, sensor_device):
        entity = _make_entity(sensor_device)
        assert entity.available is True

    def test_native_value(self, sensor_device):
        entity = _make_entity(sensor_device)
        assert entity.native_value == 23.4

    def test_should_poll_false(self, sensor_device):
        entity = _make_entity(sensor_device)
        assert entity.should_poll is False

    def test_device_class_temperature(self, sensor_device):
        entity = _make_entity(sensor_device)
        assert entity.device_class == SensorDeviceClass.TEMPERATURE

    def test_state_class(self, sensor_device):
        entity = _make_entity(sensor_device)
        assert entity.state_class == SensorStateClass.MEASUREMENT

    def test_unit_of_measurement_temperature(self, sensor_device):
        entity = _make_entity(sensor_device)
        assert entity.native_unit_of_measurement == "°C"

    def test_device_info(self, sensor_device):
        entity = _make_entity(sensor_device)
        info = entity.device_info
        assert info["manufacturer"] == "SALUS"
        assert ("salus", "sensor_001_temp") in info["identifiers"]


class TestSalusBatterySensorProperties:
    """Test sensor entity for battery device class."""

    @staticmethod
    def _battery_device() -> SensorDevice:
        return SensorDevice(
            available=True,
            name="Living Room Battery",
            unique_id="climate_001_battery",
            state=80,
            unit_of_measurement="%",
            device_class="battery",
            data={"UniID": "climate_001", "Endpoint": 1},
            manufacturer="SALUS",
            model="iT600",
            sw_version="1.0.0",
            parent_unique_id="climate_001",
        )

    def test_device_class_battery(self):
        entity = _make_entity(self._battery_device())
        assert entity.device_class == SensorDeviceClass.BATTERY

    def test_unit_of_measurement_percent(self):
        entity = _make_entity(self._battery_device())
        assert entity.native_unit_of_measurement == "%"

    def test_native_value(self):
        entity = _make_entity(self._battery_device())
        assert entity.native_value == 80

    def test_name(self):
        entity = _make_entity(self._battery_device())
        assert entity.name == "Living Room Battery"

    def test_device_info_uses_parent_id(self):
        entity = _make_entity(self._battery_device())
        info = entity.device_info
        # Battery sensor should be grouped under the thermostat device
        assert ("salus", "climate_001") in info["identifiers"]
        assert ("salus", "climate_001_battery") not in info["identifiers"]
        # Should not override parent device name or other attributes
        assert "name" not in info
        assert "manufacturer" not in info
