"""Support for Salus iT600 temperature sensors."""

from __future__ import annotations

import logging

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .const import DOMAIN
from .entity import SalusEntity
from .gateway import IT600Gateway

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Salus sensors from a config entry."""
    data = hass.data[DOMAIN][config_entry.entry_id]
    gateway: IT600Gateway = data["gateway"]
    coordinator: DataUpdateCoordinator = data["coordinator"]

    tracked: set[str] = set()

    @callback
    def _async_add_new() -> None:
        devices = gateway.get_sensor_devices()
        new_ids = set(devices) - tracked
        if new_ids:
            tracked.update(new_ids)
            async_add_entities(
                SalusSensor(coordinator, idx, gateway) for idx in new_ids
            )

    _async_add_new()
    config_entry.async_on_unload(
        coordinator.async_add_listener(_async_add_new)
    )


class SalusSensor(SalusEntity, SensorEntity):
    """Representation of a Salus sensor (temperature, battery, etc.)."""

    _attr_state_class = SensorStateClass.MEASUREMENT

    @property
    def _device(self):
        return self._gateway.get_sensor_device(self._idx)

    @property
    def device_class(self) -> str | None:
        dc = self._device.device_class
        if dc == "temperature":
            return SensorDeviceClass.TEMPERATURE
        if dc == "battery":
            return SensorDeviceClass.BATTERY
        if dc == "humidity":
            return SensorDeviceClass.HUMIDITY
        if dc == "power":
            return SensorDeviceClass.POWER
        if dc == "energy":
            return SensorDeviceClass.ENERGY
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
            return {
                "identifiers": {(DOMAIN, d.parent_unique_id)},
            }
        # Use the physical device ID (UniID) so that
        # child sensors (battery, humidity) share the same HA device.
        device_id = d.data.get("UniID", d.unique_id)
        return {
            "name": d.name,
            "identifiers": {(DOMAIN, device_id)},
            "manufacturer": d.manufacturer,
            "model": d.model,
            "sw_version": d.sw_version,
        }

