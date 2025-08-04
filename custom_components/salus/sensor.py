"""Support for (temperature, not thermostat) sensors."""
from datetime import timedelta
import logging
import async_timeout

import voluptuous as vol
from homeassistant.components.sensor import SensorEntity, SensorEntityDescription,PLATFORM_SCHEMA

from homeassistant.const import (
    CONF_HOST,
    CONF_TOKEN
)

import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend(
    {
        vol.Required(CONF_HOST): cv.string,
        vol.Required(CONF_TOKEN): cv.string,
    }
)

ENTITY_DESCRIPTIONS = (
    SensorEntityDescription(
        key="salus_sensor",
        name=None,  # Dynamic
        device_class=None,  # From API
        native_unit_of_measurement=None,  # From API
    ),
)


async def async_setup_entry(hass, config_entry, async_add_entities):
    """Set up Salus sensors from a config entry."""

    gateway = hass.data[DOMAIN][config_entry.entry_id]

    async def async_update_data():
        """Fetch data from API endpoint.

        This is the place to pre-process the data to lookup tables
        so entities can quickly look up their data.
        """
        async with async_timeout.timeout(10):
            await gateway.poll_status()
            return gateway.get_sensor_devices()

    coordinator = DataUpdateCoordinator(
        config_entry=config_entry,
        hass,
        _LOGGER,
        name="sensor",
        update_method=async_update_data,
        update_interval=timedelta(seconds=30),
    )

    # Fetch initial data so we have data when entities subscribe
    await coordinator.async_refresh()

    async_add_entities(
    SalusSensor(coordinator, idx, gateway, ENTITY_DESCRIPTIONS[0])
        for idx in coordinator.data
    )


async def async_setup_platform(hass, config, async_add_entities, discovery_info=None):
    """Set up the sensor platform."""
    pass


class SalusSensor(SensorEntity):
    """Representation of a Salus sensor."""

    def __init__(self, coordinator, idx, gateway, description: SensorEntityDescription) -> None:
        """Initialize the Salus sensor."""
        self.entity_description = description
        self._coordinator = coordinator
        self._idx = idx
        self._gateway = gateway

        device = coordinator.data.get(idx)
        self._attr_name = device.name
        self._attr_unique_id = device.unique_id
        self._attr_unit_of_measurement = device.unit_of_measurement
        self._attr_device_class = device.device_class

    async def async_update(self):
        """Request coordinator refresh."""
        await self._coordinator.async_request_refresh()

    async def async_added_to_hass(self):
        """Handle entity being added to Home Assistant."""
        self.async_on_remove(
            self._coordinator.async_add_listener(self.async_write_ha_state)
        )

    @property
    def available(self) -> bool:
        """Return True if entity is available."""
        return self._coordinator.data.get(self._idx).available

    @property
    def should_poll(self) -> bool:
        """No polling needed, coordinator handles it."""
        return False

    @property
    def state(self):
        """Return current sensor state."""
        return self._coordinator.data.get(self._idx).state

    @property
    def device_info(self):
        """Return device metadata."""
        device = self._coordinator.data.get(self._idx)
        return {
            "name": device.name,
            "identifiers": {("salus", device.unique_id)},
            "manufacturer": device.manufacturer,
            "model": device.model,
            "sw_version": device.sw_version
        }
