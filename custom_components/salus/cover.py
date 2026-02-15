"""Support for Salus iT600 covers (roller shutters / blinds)."""

from __future__ import annotations

import asyncio
import logging
from datetime import timedelta

from homeassistant.components.cover import (
    ATTR_POSITION,
    CoverEntity,
    CoverEntityFeature,
)
from homeassistant.config_entries import ConfigEntry
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
    """Set up Salus cover devices from a config entry."""
    gateway: IT600Gateway = hass.data[DOMAIN][config_entry.entry_id]

    async def async_update_data() -> dict:
        async with asyncio.timeout(10):
            await gateway.poll_status()
            return gateway.get_cover_devices()

    coordinator = DataUpdateCoordinator(
        hass,
        _LOGGER,
        config_entry=config_entry,
        name="salus_cover",
        update_method=async_update_data,
        update_interval=timedelta(seconds=30),
    )

    await coordinator.async_refresh()

    async_add_entities(
        SalusCover(coordinator, idx, gateway) for idx in coordinator.data
    )


class SalusCover(CoverEntity):
    """Representation of a Salus cover."""

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
    def supported_features(self) -> CoverEntityFeature:
        return CoverEntityFeature(self._device.supported_features)

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

    async def async_open_cover(self, **kwargs) -> None:
        await self._gateway.open_cover(self._idx)
        await self._coordinator.async_request_refresh()

    async def async_close_cover(self, **kwargs) -> None:
        await self._gateway.close_cover(self._idx)
        await self._coordinator.async_request_refresh()

    async def async_set_cover_position(self, **kwargs) -> None:
        position = kwargs.get(ATTR_POSITION)
        if position is None:
            return
        await self._gateway.set_cover_position(self._idx, position)
        await self._coordinator.async_request_refresh()

