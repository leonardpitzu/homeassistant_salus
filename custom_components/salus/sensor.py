"""Support for Salus iT600 temperature sensors."""

from __future__ import annotations

import asyncio
import logging
from datetime import timedelta

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .const import DOMAIN
from .gateway import IT600Gateway

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Salus sensors from a config entry."""
    gateway: IT600Gateway = hass.data[DOMAIN][config_entry.entry_id]

    async def async_update_data() -> dict:
        async with asyncio.timeout(10):
            await gateway.poll_status()
            return gateway.get_sensor_devices()

    coordinator = DataUpdateCoordinator(
        hass,
        _LOGGER,
        config_entry=config_entry,
        name="salus_sensor",
        update_method=async_update_data,
        update_interval=timedelta(seconds=30),
    )

    await coordinator.async_refresh()

    async_add_entities(
        SalusSensor(coordinator, idx, gateway) for idx in coordinator.data
    )


class SalusSensor(SensorEntity):
    """Representation of a Salus sensor (temperature, battery, etc.)."""

    _attr_has_entity_name = False
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(
        self,
        coordinator: DataUpdateCoordinator,
        idx: str,
        gateway: IT600Gateway,
    ) -> None:
        self._coordinator = coordinator
        self._idx = idx
        self._gateway = gateway

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
    def device_class(self) -> str | None:
        dc = self._device.device_class
        if dc == "temperature":
            return SensorDeviceClass.TEMPERATURE
        if dc == "battery":
            return SensorDeviceClass.BATTERY
        return dc

    @property
    def entity_category(self) -> EntityCategory | None:
        ec = self._device.entity_category
        if ec == "diagnostic":
            return EntityCategory.DIAGNOSTIC
        return None

    @property
    def native_unit_of_measurement(self) -> str | None:
        return self._device.unit_of_measurement

    @property
    def native_value(self) -> float | None:
        return self._device.state

    @property
    def device_info(self) -> dict:
        d = self._device
        if d.parent_unique_id:
            # Child sensor (e.g. battery) — attach to the parent device
            # without overriding its name or other attributes.
            return {
                "identifiers": {(DOMAIN, d.parent_unique_id)},
            }
        return {
            "name": d.name,
            "identifiers": {(DOMAIN, d.unique_id)},
            "manufacturer": d.manufacturer,
            "model": d.model,
            "sw_version": d.sw_version,
        }

