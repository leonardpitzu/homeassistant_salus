"""Support for Salus iT600 switches (smart plug / relay)."""

from __future__ import annotations

import asyncio
import logging
from datetime import timedelta

from homeassistant.components.switch import SwitchEntity
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
    """Set up Salus switches from a config entry."""
    gateway: IT600Gateway = hass.data[DOMAIN][config_entry.entry_id]

    async def async_update_data() -> dict:
        async with asyncio.timeout(10):
            await gateway.poll_status()
            return gateway.get_switch_devices()

    coordinator = DataUpdateCoordinator(
        hass,
        _LOGGER,
        config_entry=config_entry,
        name="salus_switch",
        update_method=async_update_data,
        update_interval=timedelta(seconds=30),
    )

    await coordinator.async_refresh()

    async_add_entities(
        SalusSwitch(coordinator, idx, gateway) for idx in coordinator.data
    )


class SalusSwitch(SwitchEntity):
    """Representation of a Salus switch."""

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
    def is_on(self) -> bool:
        return self._device.is_on

    @property
    def device_class(self) -> str:
        return self._device.device_class

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

    async def async_turn_on(self, **kwargs) -> None:
        await self._gateway.turn_on_switch_device(self._idx)
        await self._coordinator.async_request_refresh()

    async def async_turn_off(self, **kwargs) -> None:
        await self._gateway.turn_off_switch_device(self._idx)
        await self._coordinator.async_request_refresh()

