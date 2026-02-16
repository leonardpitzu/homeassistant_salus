"""Support for Salus iT600 gateway and devices."""

from __future__ import annotations

import logging

from homeassistant import config_entries, core
from homeassistant.const import CONF_HOST, CONF_TOKEN
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.config_validation import config_entry_only_config_schema

from .config_flow import CONF_FLOW_TYPE, CONF_USER
from .const import DOMAIN

CONFIG_SCHEMA = config_entry_only_config_schema(DOMAIN)
from .exceptions import IT600AuthenticationError, IT600ConnectionError
from .gateway import IT600Gateway

_LOGGER = logging.getLogger(__name__)

GATEWAY_PLATFORMS = ["climate", "binary_sensor", "switch", "cover", "sensor"]


async def async_setup(hass: core.HomeAssistant, config: dict) -> bool:
    """Set up the Salus iT600 component."""
    return True


async def async_setup_entry(
    hass: core.HomeAssistant, entry: config_entries.ConfigEntry
) -> bool:
    """Set up components from a config entry."""
    hass.data.setdefault(DOMAIN, {})

    if entry.data.get(CONF_FLOW_TYPE) == CONF_USER:
        if not await async_setup_gateway_entry(hass, entry):
            return False

    return True


async def async_setup_gateway_entry(
    hass: core.HomeAssistant, entry: config_entries.ConfigEntry
) -> bool:
    """Set up the Gateway component from a config entry."""
    host = entry.data[CONF_HOST]
    euid = entry.data[CONF_TOKEN]

    gateway = IT600Gateway(host=host, euid=euid)

    try:
        for remaining in reversed(range(3)):
            try:
                await gateway.connect()
                await gateway.poll_status()
                break
            except Exception:
                if remaining == 0:
                    raise
                import asyncio
                await asyncio.sleep(3)
    except IT600ConnectionError:
        _LOGGER.error(
            "Connection error: check if you have specified "
            "gateway's HOST correctly."
        )
        return False
    except IT600AuthenticationError:
        _LOGGER.error(
            "Authentication error: check if you have specified "
            "gateway's EUID correctly."
        )
        return False

    hass.data[DOMAIN][entry.entry_id] = gateway

    gateway_info = gateway.get_gateway_device()
    if gateway_info is not None:
        device_registry = dr.async_get(hass)
        device_registry.async_get_or_create(
            config_entry_id=entry.entry_id,
            connections={
                (dr.CONNECTION_NETWORK_MAC, gateway_info.unique_id)
            },
            identifiers={(DOMAIN, gateway_info.unique_id)},
            manufacturer=gateway_info.manufacturer,
            name=gateway_info.name,
            model=gateway_info.model,
            sw_version=gateway_info.sw_version,
        )

    await hass.config_entries.async_forward_entry_setups(
        entry, GATEWAY_PLATFORMS
    )

    return True


async def async_unload_entry(
    hass: core.HomeAssistant,
    config_entry: config_entries.ConfigEntry,
) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(
        config_entry, GATEWAY_PLATFORMS
    )

    if unload_ok:
        gateway: IT600Gateway | None = hass.data[DOMAIN].pop(
            config_entry.entry_id, None
        )
        if gateway is not None:
            await gateway.close()

    return unload_ok

