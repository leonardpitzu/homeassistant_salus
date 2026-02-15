"""Support for Salus iT600 climate devices (thermostats)."""

from __future__ import annotations

import asyncio
import logging
from datetime import timedelta

from homeassistant.components.climate import (
    ClimateEntity,
    ClimateEntityFeature,
    HVACAction,
    HVACMode,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import ATTR_TEMPERATURE, UnitOfTemperature
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .const import DOMAIN, SUPPORT_FAN_MODE
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
    gateway: IT600Gateway = hass.data[DOMAIN][config_entry.entry_id]

    async def async_update_data() -> dict:
        async with asyncio.timeout(10):
            await gateway.poll_status()
            return gateway.get_climate_devices()

    coordinator = DataUpdateCoordinator(
        hass,
        _LOGGER,
        config_entry=config_entry,
        name="salus_climate",
        update_method=async_update_data,
        update_interval=timedelta(seconds=30),
    )

    await coordinator.async_refresh()

    async_add_entities(
        SalusThermostat(coordinator, idx, gateway) for idx in coordinator.data
    )


class SalusThermostat(ClimateEntity):
    """Representation of a Salus thermostat."""

    _attr_has_entity_name = False

    def __init__(
        self,
        coordinator: DataUpdateCoordinator,
        idx: str,
        gateway: IT600Gateway,
    ) -> None:
        self._coordinator = coordinator
        self._idx = idx
        self._gateway = gateway

    # ── HA plumbing ─────────────────────────────────────────────────

    async def async_update(self) -> None:
        await self._coordinator.async_request_refresh()

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(
            self._coordinator.async_add_listener(self.async_write_ha_state)
        )

    @property
    def _device(self):
        return self._coordinator.data.get(self._idx)

    @property
    def should_poll(self) -> bool:
        return False

    @property
    def available(self) -> bool:
        return self._device.available

    @property
    def unique_id(self) -> str:
        return self._device.unique_id

    @property
    def name(self) -> str:
        return self._device.name

    @property
    def device_info(self) -> dict:
        d = self._device
        return {
            "name": d.name,
            "identifiers": {(DOMAIN, d.unique_id)},
            "manufacturer": d.manufacturer,
            "model": d.model,
            "sw_version": d.sw_version,
        }

    # ── Climate specifics ───────────────────────────────────────────

    @property
    def supported_features(self) -> ClimateEntityFeature:
        features = (
            ClimateEntityFeature.TURN_ON
            | ClimateEntityFeature.TURN_OFF
            | ClimateEntityFeature.TARGET_TEMPERATURE
            | ClimateEntityFeature.PRESET_MODE
        )
        if self._device.supported_features & SUPPORT_FAN_MODE:
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
        await self._coordinator.async_request_refresh()

    async def async_set_hvac_mode(self, hvac_mode: HVACMode) -> None:
        await self._gateway.set_climate_device_mode(self._idx, hvac_mode)
        await self._coordinator.async_request_refresh()

    async def async_set_preset_mode(self, preset_mode: str) -> None:
        await self._gateway.set_climate_device_preset(self._idx, preset_mode)
        await self._coordinator.async_request_refresh()

    async def async_set_fan_mode(self, fan_mode: str) -> None:
        await self._gateway.set_climate_device_fan_mode(self._idx, fan_mode)
        await self._coordinator.async_request_refresh()

