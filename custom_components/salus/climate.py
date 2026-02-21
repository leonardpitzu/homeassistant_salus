"""Support for Salus iT600 climate devices (thermostats)."""

from __future__ import annotations

import logging

from homeassistant.components.climate import (
    ClimateEntity,
    ClimateEntityFeature,
    HVACAction,
    HVACMode,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import ATTR_TEMPERATURE, UnitOfTemperature
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .const import DOMAIN
from .entity import SalusEntity
from .gateway import IT600Gateway

_LOGGER = logging.getLogger(__name__)

_HVAC_ACTION_MAP: dict[str, HVACAction] = {
    "off": HVACAction.OFF,
    "heating": HVACAction.HEATING,
    "cooling": HVACAction.COOLING,
    "idle": HVACAction.IDLE,
}


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Salus thermostats from a config entry."""
    data = hass.data[DOMAIN][config_entry.entry_id]
    gateway: IT600Gateway = data["gateway"]
    coordinator: DataUpdateCoordinator = data["coordinator"]

    tracked: set[str] = set()

    @callback
    def _async_add_new() -> None:
        devices = gateway.get_climate_devices()
        new_ids = set(devices) - tracked
        if new_ids:
            tracked.update(new_ids)
            async_add_entities(
                SalusThermostat(coordinator, idx, gateway) for idx in new_ids
            )

    _async_add_new()
    config_entry.async_on_unload(
        coordinator.async_add_listener(_async_add_new)
    )


class SalusThermostat(SalusEntity, ClimateEntity):
    """Representation of a Salus thermostat."""

    @property
    def _device(self):
        return self._gateway.get_climate_device(self._idx)

    # ── Climate specifics ───────────────────────────────────────────

    @property
    def supported_features(self) -> ClimateEntityFeature:
        features = (
            ClimateEntityFeature.TURN_ON
            | ClimateEntityFeature.TURN_OFF
            | ClimateEntityFeature.TARGET_TEMPERATURE
            | ClimateEntityFeature.PRESET_MODE
        )
        if self._device.fan_modes is not None:
            features |= ClimateEntityFeature.FAN_MODE
        return features

    @property
    def temperature_unit(self) -> str:
        return UnitOfTemperature.CELSIUS

    @property
    def precision(self) -> float:
        return self._device.precision

    @property
    def current_temperature(self) -> float | None:
        return self._device.current_temperature

    @property
    def current_humidity(self) -> float | None:
        return self._device.current_humidity

    @property
    def target_temperature(self) -> float | None:
        return self._device.target_temperature

    @property
    def max_temp(self) -> float:
        return self._device.max_temp

    @property
    def min_temp(self) -> float:
        return self._device.min_temp

    @property
    def hvac_mode(self) -> HVACMode:
        return HVACMode(self._device.hvac_mode)

    @property
    def hvac_modes(self) -> list[HVACMode]:
        return [HVACMode(m) for m in self._device.hvac_modes]

    @property
    def hvac_action(self) -> HVACAction | None:
        raw = self._device.hvac_action
        return _HVAC_ACTION_MAP.get(raw)

    @property
    def preset_mode(self) -> str | None:
        return self._device.preset_mode

    @property
    def preset_modes(self) -> list[str]:
        return self._device.preset_modes

    @property
    def fan_mode(self) -> str | None:
        return self._device.fan_mode

    @property
    def fan_modes(self) -> list[str] | None:
        return self._device.fan_modes

    # ── Commands ────────────────────────────────────────────────────

    async def async_set_temperature(self, **kwargs) -> None:
        temperature = kwargs.get(ATTR_TEMPERATURE)
        if temperature is None:
            return
        await self._gateway.set_climate_device_temperature(
            self._idx, temperature
        )
        await self.coordinator.async_request_refresh()

    async def async_set_hvac_mode(self, hvac_mode: HVACMode) -> None:
        await self._gateway.set_climate_device_mode(self._idx, hvac_mode)
        await self.coordinator.async_request_refresh()

    async def async_set_preset_mode(self, preset_mode: str) -> None:
        await self._gateway.set_climate_device_preset(self._idx, preset_mode)
        await self.coordinator.async_request_refresh()

    async def async_set_fan_mode(self, fan_mode: str) -> None:
        await self._gateway.set_climate_device_fan_mode(self._idx, fan_mode)
        await self.coordinator.async_request_refresh()

