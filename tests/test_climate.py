"""Tests for the Salus climate entity."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

from homeassistant.components.climate import ClimateEntityFeature, HVACAction, HVACMode

from custom_components.salus.climate import SalusThermostat
from custom_components.salus.const import (
    CURRENT_HVAC_HEAT,
    FAN_MODE_AUTO,
    FAN_MODE_HIGH,
    HVAC_MODE_AUTO,
    HVAC_MODE_COOL,
    HVAC_MODE_HEAT,
    PRESET_FOLLOW_SCHEDULE,
    PRESET_PERMANENT_HOLD,
    SUPPORT_FAN_MODE,
    SUPPORT_PRESET_MODE,
    SUPPORT_TARGET_TEMPERATURE,
)
from custom_components.salus.models import ClimateDevice


def _make_entity(device: ClimateDevice) -> tuple[SalusThermostat, AsyncMock]:
    """Create a SalusThermostat entity with a mocked coordinator + gateway."""
    coordinator = MagicMock()
    coordinator.async_request_refresh = AsyncMock()
    coordinator.async_add_listener = MagicMock(return_value=lambda: None)

    gateway = AsyncMock()
    gateway.get_climate_device = MagicMock(return_value=device)
    entity = SalusThermostat(coordinator, device.unique_id, gateway)
    return entity, gateway


class TestSalusThermostatProperties:
    """Test thermostat entity property delegation."""

    def test_unique_id(self, climate_device):
        entity, _ = _make_entity(climate_device)
        assert entity.unique_id == "climate_001"

    def test_name(self, climate_device):
        entity, _ = _make_entity(climate_device)
        assert entity.name == "Living Room Thermostat"

    def test_available(self, climate_device):
        entity, _ = _make_entity(climate_device)
        assert entity.available is True

    def test_current_temperature(self, climate_device):
        entity, _ = _make_entity(climate_device)
        assert entity.current_temperature == 21.5

    def test_target_temperature(self, climate_device):
        entity, _ = _make_entity(climate_device)
        assert entity.target_temperature == 22.0

    def test_min_max_temp(self, climate_device):
        entity, _ = _make_entity(climate_device)
        assert entity.min_temp == 5.0
        assert entity.max_temp == 35.0

    def test_precision(self, climate_device):
        entity, _ = _make_entity(climate_device)
        assert entity.precision == 0.1

    def test_hvac_mode(self, climate_device):
        entity, _ = _make_entity(climate_device)
        assert entity.hvac_mode == HVACMode.HEAT

    def test_hvac_modes(self, climate_device):
        entity, _ = _make_entity(climate_device)
        modes = entity.hvac_modes
        assert HVACMode.OFF in modes
        assert HVACMode.HEAT in modes
        assert HVACMode.AUTO in modes

    def test_hvac_action(self, climate_device):
        entity, _ = _make_entity(climate_device)
        assert entity.hvac_action == HVACAction.HEATING

    def test_preset_mode(self, climate_device):
        entity, _ = _make_entity(climate_device)
        assert entity.preset_mode == PRESET_FOLLOW_SCHEDULE

    def test_preset_modes(self, climate_device):
        entity, _ = _make_entity(climate_device)
        assert PRESET_FOLLOW_SCHEDULE in entity.preset_modes
        assert PRESET_PERMANENT_HOLD in entity.preset_modes

    def test_fan_mode_none(self, climate_device):
        entity, _ = _make_entity(climate_device)
        assert entity.fan_mode is None
        assert entity.fan_modes is None

    def test_humidity_none(self, climate_device):
        entity, _ = _make_entity(climate_device)
        assert entity.current_humidity is None

    def test_should_poll_false(self, climate_device):
        entity, _ = _make_entity(climate_device)
        assert entity.should_poll is False

    def test_temperature_unit(self, climate_device):
        from homeassistant.const import UnitOfTemperature

        entity, _ = _make_entity(climate_device)
        assert entity.temperature_unit == UnitOfTemperature.CELSIUS

    def test_supported_features_without_fan(self, climate_device):
        entity, _ = _make_entity(climate_device)
        features = entity.supported_features
        assert features & ClimateEntityFeature.TARGET_TEMPERATURE
        assert features & ClimateEntityFeature.PRESET_MODE
        assert not (features & ClimateEntityFeature.FAN_MODE)

    def test_supported_features_with_fan(self):
        """Test that FAN_MODE feature is exposed for FC600-type devices."""
        device = ClimateDevice(
            available=True,
            name="FC Unit",
            unique_id="fc_001",
            temperature_unit="°C",
            precision=0.1,
            current_temperature=23.0,
            target_temperature=24.0,
            max_temp=40.0,
            min_temp=5.0,
            current_humidity=None,
            hvac_mode=HVAC_MODE_HEAT,
            hvac_action=CURRENT_HVAC_HEAT,
            hvac_modes=[HVAC_MODE_HEAT, HVAC_MODE_COOL, HVAC_MODE_AUTO],
            preset_mode=PRESET_FOLLOW_SCHEDULE,
            preset_modes=[PRESET_FOLLOW_SCHEDULE, PRESET_PERMANENT_HOLD],
            fan_mode=FAN_MODE_AUTO,
            fan_modes=[FAN_MODE_AUTO, FAN_MODE_HIGH],
            locked=False,
            supported_features=(
                SUPPORT_TARGET_TEMPERATURE
                | SUPPORT_PRESET_MODE
                | SUPPORT_FAN_MODE
            ),
            device_class="temperature",
            data={"UniID": "fc_001", "Endpoint": 1},
            manufacturer="SALUS",
            model="FC600",
            sw_version="2.0",
        )
        entity, _ = _make_entity(device)
        assert entity.supported_features & ClimateEntityFeature.FAN_MODE

    def test_device_info(self, climate_device):
        entity, _ = _make_entity(climate_device)
        info = entity.device_info
        assert info["manufacturer"] == "SALUS"
        assert info["model"] == "iT600"
        assert ("salus", "climate_001") in info["identifiers"]


class TestSalusThermostatCommands:
    """Test thermostat command forwarding."""

    async def test_set_temperature(self, climate_device):
        entity, gw = _make_entity(climate_device)
        await entity.async_set_temperature(temperature=23.5)
        gw.set_climate_device_temperature.assert_awaited_once_with(
            "climate_001", 23.5
        )

    async def test_set_temperature_no_value(self, climate_device):
        entity, gw = _make_entity(climate_device)
        await entity.async_set_temperature()
        gw.set_climate_device_temperature.assert_not_awaited()

    async def test_set_hvac_mode(self, climate_device):
        entity, gw = _make_entity(climate_device)
        await entity.async_set_hvac_mode(HVACMode.OFF)
        gw.set_climate_device_mode.assert_awaited_once_with(
            "climate_001", HVACMode.OFF
        )

    async def test_set_preset_mode(self, climate_device):
        entity, gw = _make_entity(climate_device)
        await entity.async_set_preset_mode(PRESET_PERMANENT_HOLD)
        gw.set_climate_device_preset.assert_awaited_once_with(
            "climate_001", PRESET_PERMANENT_HOLD
        )

    async def test_set_fan_mode(self, climate_device):
        entity, gw = _make_entity(climate_device)
        await entity.async_set_fan_mode(FAN_MODE_HIGH)
        gw.set_climate_device_fan_mode.assert_awaited_once_with(
            "climate_001", FAN_MODE_HIGH
        )

    async def test_commands_trigger_refresh(self, climate_device):
        entity, gw = _make_entity(climate_device)
        coordinator = entity.coordinator

        await entity.async_set_temperature(temperature=20.0)
        assert coordinator.async_request_refresh.await_count == 1

        await entity.async_set_hvac_mode(HVACMode.AUTO)
        assert coordinator.async_request_refresh.await_count == 2
