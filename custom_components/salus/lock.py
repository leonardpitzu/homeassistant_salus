"""Support for Salus iT600 thermostat child lock."""

from __future__ import annotations

import logging

from homeassistant.components.lock import LockEntity
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
    """Set up Salus thermostat lock entities from a config entry."""
    data = hass.data[DOMAIN][config_entry.entry_id]
    gateway: IT600Gateway = data["gateway"]
    coordinator: DataUpdateCoordinator = data["coordinator"]

    tracked: set[str] = set()

    @callback
    def _async_add_new() -> None:
        devices = gateway.get_climate_devices()
        new_ids = {
            k for k, v in devices.items()
            if v.locked is not None and k not in tracked
        }
        if new_ids:
            tracked.update(new_ids)
            async_add_entities(
                SalusThermostatLock(coordinator, idx, gateway)
                for idx in new_ids
            )

    _async_add_new()
    config_entry.async_on_unload(
        coordinator.async_add_listener(_async_add_new)
    )


class SalusThermostatLock(SalusEntity, LockEntity):
    """Thermostat child-lock entity."""

    _attr_entity_category = EntityCategory.CONFIG

    @property
    def _device(self):
        return self._gateway.get_climate_device(self._idx)

    @property
    def unique_id(self) -> str:
        return f"{self._device.unique_id}_lock"

    @property
    def name(self) -> str:
        return f"{self._device.name} Child lock"

    @property
    def is_locked(self) -> bool:
        return self._device.locked is True

    @property
    def device_info(self) -> dict:
        d = self._device
        # Attach to the thermostat device
        return {
            "identifiers": {(DOMAIN, d.unique_id)},
        }

    async def async_lock(self, **kwargs) -> None:
        await self._gateway.set_climate_device_locked(self._idx, True)
        await self.coordinator.async_request_refresh()

    async def async_unlock(self, **kwargs) -> None:
        await self._gateway.set_climate_device_locked(self._idx, False)
        await self.coordinator.async_request_refresh()
