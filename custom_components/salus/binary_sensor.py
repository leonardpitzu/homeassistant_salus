"""Support for Salus iT600 binary sensors (door/window/smoke/leak)."""

from __future__ import annotations

import logging

from homeassistant.components.binary_sensor import BinarySensorEntity
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
    """Set up Salus binary sensors from a config entry."""
    data = hass.data[DOMAIN][config_entry.entry_id]
    gateway: IT600Gateway = data["gateway"]
    coordinator: DataUpdateCoordinator = data["coordinator"]

    tracked: set[str] = set()

    @callback
    def _async_add_new() -> None:
        devices = gateway.get_binary_sensor_devices()
        new_ids = set(devices) - tracked
        if new_ids:
            tracked.update(new_ids)
            async_add_entities(
                SalusBinarySensor(coordinator, idx, gateway)
                for idx in new_ids
            )

    _async_add_new()
    config_entry.async_on_unload(
        coordinator.async_add_listener(_async_add_new)
    )


class SalusBinarySensor(SalusEntity, BinarySensorEntity):
    """Representation of a Salus binary sensor."""

    @property
    def _device(self):
        return self._gateway.get_binary_sensor_device(self._idx)

    @property
    def is_on(self) -> bool:
        return self._device.is_on

    @property
    def device_class(self) -> str | None:
        return self._device.device_class

    @property
    def entity_category(self) -> EntityCategory | None:
        ec = self._device.entity_category
        if ec == "diagnostic":
            return EntityCategory.DIAGNOSTIC
        return None

    @property
    def extra_state_attributes(self) -> dict | None:
        return self._device.extra_state_attributes

