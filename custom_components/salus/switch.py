"""Support for Salus iT600 switches (smart plug / relay)."""

from __future__ import annotations

import logging

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
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
    """Set up Salus switches from a config entry."""
    data = hass.data[DOMAIN][config_entry.entry_id]
    gateway: IT600Gateway = data["gateway"]
    coordinator: DataUpdateCoordinator = data["coordinator"]

    tracked: set[str] = set()

    @callback
    def _async_add_new() -> None:
        devices = gateway.get_switch_devices()
        new_ids = set(devices) - tracked
        if new_ids:
            tracked.update(new_ids)
            async_add_entities(
                SalusSwitch(coordinator, idx, gateway) for idx in new_ids
            )

    _async_add_new()
    config_entry.async_on_unload(
        coordinator.async_add_listener(_async_add_new)
    )


class SalusSwitch(SalusEntity, SwitchEntity):
    """Representation of a Salus switch."""

    @property
    def _device(self):
        return self._gateway.get_switch_device(self._idx)

    @property
    def is_on(self) -> bool:
        return self._device.is_on

    @property
    def device_class(self) -> str:
        return self._device.device_class

    async def async_turn_on(self, **kwargs) -> None:
        await self._gateway.turn_on_switch_device(self._idx)
        await self.coordinator.async_request_refresh()

    async def async_turn_off(self, **kwargs) -> None:
        await self._gateway.turn_off_switch_device(self._idx)
        await self.coordinator.async_request_refresh()

