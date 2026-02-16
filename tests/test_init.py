"""Tests for the Salus integration __init__ (setup / unload)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

from homeassistant.const import CONF_HOST, CONF_TOKEN
from homeassistant.core import HomeAssistant
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.salus import (
    async_setup,
    async_setup_entry,
    async_unload_entry,
)
from custom_components.salus.const import DOMAIN
from custom_components.salus.exceptions import (
    IT600AuthenticationError,
    IT600ConnectionError,
)

GATEWAY_PATCH = "custom_components.salus.IT600Gateway"


def _mock_config_entry(hass: HomeAssistant) -> MockConfigEntry:
    """Return a MockConfigEntry wired up for gateway flow."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="Test Gateway",
        data={
            "config_flow_device": "user",
            CONF_HOST: "192.168.1.100",
            CONF_TOKEN: "001E5E0D32906128",
        },
        unique_id="AA:BB:CC:DD:EE:FF",
    )
    entry.add_to_hass(hass)
    return entry


async def test_async_setup(hass: HomeAssistant) -> None:
    """Test that async_setup returns True (no YAML config needed)."""
    assert await async_setup(hass, {}) is True


async def test_setup_entry_success(hass: HomeAssistant) -> None:
    """Test successful setup of a gateway config entry."""
    entry = _mock_config_entry(hass)

    with (
        patch(GATEWAY_PATCH) as mock_gw_cls,
        patch(
            "homeassistant.config_entries.ConfigEntries.async_forward_entry_setups",
        ) as mock_forward,
    ):
        mock_gw = AsyncMock()
        mock_gw.connect = AsyncMock()
        mock_gw.poll_status = AsyncMock()
        mock_gw.close = AsyncMock()
        mock_gw.get_gateway_device = MagicMock(return_value=None)
        mock_gw.get_climate_devices = MagicMock(return_value={})
        mock_gw.get_binary_sensor_devices = MagicMock(return_value={})
        mock_gw.get_switch_devices = MagicMock(return_value={})
        mock_gw.get_cover_devices = MagicMock(return_value={})
        mock_gw.get_sensor_devices = MagicMock(return_value={})
        mock_gw_cls.return_value = mock_gw

        result = await async_setup_entry(hass, entry)

    assert result is True
    assert entry.entry_id in hass.data[DOMAIN]
    mock_forward.assert_awaited_once()


async def test_setup_entry_connection_error(hass: HomeAssistant) -> None:
    """Test that a connection error returns False and doesn't crash."""
    entry = _mock_config_entry(hass)

    with patch(GATEWAY_PATCH) as mock_gw_cls:
        mock_gw = AsyncMock()
        mock_gw.connect = AsyncMock(side_effect=IT600ConnectionError("fail"))
        mock_gw.close = AsyncMock()
        mock_gw_cls.return_value = mock_gw

        result = await async_setup_entry(hass, entry)

    assert result is False


async def test_setup_entry_auth_error(hass: HomeAssistant) -> None:
    """Test that an auth error returns False and doesn't crash."""
    entry = _mock_config_entry(hass)

    with patch(GATEWAY_PATCH) as mock_gw_cls:
        mock_gw = AsyncMock()
        mock_gw.connect = AsyncMock(
            side_effect=IT600AuthenticationError("bad")
        )
        mock_gw.close = AsyncMock()
        mock_gw_cls.return_value = mock_gw

        result = await async_setup_entry(hass, entry)

    assert result is False


async def test_unload_entry(hass: HomeAssistant) -> None:
    """Test that unload tears down the gateway."""
    entry = _mock_config_entry(hass)

    mock_gw = AsyncMock()
    mock_gw.close = AsyncMock()

    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = mock_gw

    with patch.object(
        hass.config_entries,
        "async_unload_platforms",
        return_value=True,
    ):
        result = await async_unload_entry(hass, entry)

    assert result is True
    mock_gw.close.assert_awaited_once()
    assert entry.entry_id not in hass.data[DOMAIN]
