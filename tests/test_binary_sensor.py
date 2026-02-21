"""Tests for the Salus binary sensor entity."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

from custom_components.salus.binary_sensor import SalusBinarySensor
from custom_components.salus.models import BinarySensorDevice


def _make_entity(device: BinarySensorDevice) -> SalusBinarySensor:
    coordinator = MagicMock()
    coordinator.data = {device.unique_id: device}
    coordinator.async_request_refresh = AsyncMock()
    coordinator.async_add_listener = MagicMock(return_value=lambda: None)
    return SalusBinarySensor(coordinator, device.unique_id, AsyncMock())


class TestSalusBinarySensorProperties:
    """Test binary sensor entity property delegation."""

    def test_unique_id(self, binary_sensor_device):
        entity = _make_entity(binary_sensor_device)
        assert entity.unique_id == "binary_001"

    def test_name(self, binary_sensor_device):
        entity = _make_entity(binary_sensor_device)
        assert entity.name == "Front Door"

    def test_available(self, binary_sensor_device):
        entity = _make_entity(binary_sensor_device)
        assert entity.available is True

    def test_is_on(self, binary_sensor_device):
        entity = _make_entity(binary_sensor_device)
        assert entity.is_on is False

    def test_device_class(self, binary_sensor_device):
        entity = _make_entity(binary_sensor_device)
        assert entity.device_class == "window"

    def test_should_poll_false(self, binary_sensor_device):
        entity = _make_entity(binary_sensor_device)
        assert entity.should_poll is False

    def test_device_info(self, binary_sensor_device):
        entity = _make_entity(binary_sensor_device)
        info = entity.device_info
        assert info["manufacturer"] == "SALUS"
        assert info["model"] == "SW600"
        assert ("salus", "binary_001") in info["identifiers"]

    def test_is_on_true(self):
        device = BinarySensorDevice(
            available=True,
            name="Window Open",
            unique_id="bs_open",
            is_on=True,
            device_class="window",
            data={"UniID": "bs_open", "Endpoint": 1},
            manufacturer="SALUS",
            model="SW600",
            sw_version="1.0",
        )
        entity = _make_entity(device)
        assert entity.is_on is True


class TestSalusBinarySensorParentDevice:
    """Test binary sensor entity with parent_unique_id (error sensors)."""

    @staticmethod
    def _error_device() -> BinarySensorDevice:
        return BinarySensorDevice(
            available=True,
            name="Living Room Low battery",
            unique_id="climate_001_error32",
            is_on=True,
            device_class="battery",
            data={"UniID": "climate_001", "Endpoint": 1},
            manufacturer="SALUS",
            model="iT600",
            sw_version="1.0",
            parent_unique_id="climate_001",
        )

    def test_device_info_uses_parent_id(self):
        entity = _make_entity(self._error_device())
        info = entity.device_info
        assert ("salus", "climate_001") in info["identifiers"]
        assert "name" not in info

    def test_device_class(self):
        entity = _make_entity(self._error_device())
        assert entity.device_class == "battery"

    def test_is_on(self):
        entity = _make_entity(self._error_device())
        assert entity.is_on is True
