"""Support for Salus iT600 covers (roller shutters / blinds)."""

from __future__ import annotations

import logging

from homeassistant.components.cover import (
    ATTR_POSITION,
    CoverEntity,
    CoverEntityFeature,
)
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
    """Set up Salus cover devices from a config entry."""
    data = hass.data[DOMAIN][config_entry.entry_id]
    gateway: IT600Gateway = data["gateway"]
    coordinator: DataUpdateCoordinator = data["coordinator"]

    tracked: set[str] = set()

    @callback
    def _async_add_new() -> None:
        devices = gateway.get_cover_devices()
        new_ids = set(devices) - tracked
        if new_ids:
            tracked.update(new_ids)
            async_add_entities(
                SalusCover(coordinator, idx, gateway) for idx in new_ids
            )

    _async_add_new()
    config_entry.async_on_unload(
        coordinator.async_add_listener(_async_add_new)
    )


class SalusCover(SalusEntity, CoverEntity):
    """Representation of a Salus cover."""

    @property
    def _device(self):
        return self._gateway.get_cover_device(self._idx)

    @property
    def supported_features(self) -> CoverEntityFeature:
        return (
            CoverEntityFeature.OPEN
            | CoverEntityFeature.CLOSE
            | CoverEntityFeature.SET_POSITION
        )

    @property
    def device_class(self) -> str | None:
        return self._device.device_class

    @property
    def current_cover_position(self) -> int | None:
        return self._device.current_cover_position

    @property
    def is_opening(self) -> bool | None:
        return self._device.is_opening

    @property
    def is_closing(self) -> bool | None:
        return self._device.is_closing

    @property
    def is_closed(self) -> bool:
        return self._device.is_closed

    async def async_open_cover(self, **kwargs) -> None:
        await self._gateway.open_cover(self._idx)
        await self.coordinator.async_request_refresh()

    async def async_close_cover(self, **kwargs) -> None:
        await self._gateway.close_cover(self._idx)
        await self.coordinator.async_request_refresh()

    async def async_set_cover_position(self, **kwargs) -> None:
        position = kwargs.get(ATTR_POSITION)
        if position is None:
            return
        await self._gateway.set_cover_position(self._idx, position)
        await self.coordinator.async_request_refresh()

