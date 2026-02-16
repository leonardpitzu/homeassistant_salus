"""Tests for the Salus config flow."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_NAME, CONF_TOKEN
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType

from custom_components.salus.const import DOMAIN
from custom_components.salus.exceptions import (
    IT600AuthenticationError,
    IT600ConnectionError,
)

GATEWAY_PATCH = "custom_components.salus.config_flow.IT600Gateway"


async def test_show_form(hass: HomeAssistant) -> None:
    """Test that the user step shows the form initially."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "user"
    assert result["errors"] == {}


async def test_user_flow_success(hass: HomeAssistant) -> None:
    """Test successful gateway configuration."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )

    with patch(GATEWAY_PATCH) as mock_gw_cls:
        mock_gw = AsyncMock()
        mock_gw.connect = AsyncMock(return_value="AA:BB:CC:DD:EE:FF")
        mock_gw.close = AsyncMock()
        mock_gw_cls.return_value = mock_gw

        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {
                CONF_HOST: "192.168.1.100",
                CONF_TOKEN: "001E5E0D32906128",
                CONF_NAME: "My Gateway",
            },
        )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == "My Gateway"
    assert result["data"][CONF_HOST] == "192.168.1.100"
    assert result["data"][CONF_TOKEN] == "001E5E0D32906128"
    assert result["data"]["mac"] == "AA:BB:CC:DD:EE:FF"


async def test_user_flow_connection_error(hass: HomeAssistant) -> None:
    """Test config flow when the gateway cannot be reached."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )

    with patch(GATEWAY_PATCH) as mock_gw_cls:
        mock_gw = AsyncMock()
        mock_gw.connect = AsyncMock(side_effect=IT600ConnectionError("nope"))
        mock_gw.close = AsyncMock()
        mock_gw_cls.return_value = mock_gw

        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {
                CONF_HOST: "192.168.1.100",
                CONF_TOKEN: "001E5E0D32906128",
                CONF_NAME: "My Gateway",
            },
        )

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "connect_error"}


async def test_user_flow_auth_error(hass: HomeAssistant) -> None:
    """Test config flow when the EUID is wrong."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )

    with patch(GATEWAY_PATCH) as mock_gw_cls:
        mock_gw = AsyncMock()
        mock_gw.connect = AsyncMock(
            side_effect=IT600AuthenticationError("bad euid")
        )
        mock_gw.close = AsyncMock()
        mock_gw_cls.return_value = mock_gw

        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {
                CONF_HOST: "192.168.1.100",
                CONF_TOKEN: "001E5E0D32906128",
                CONF_NAME: "My Gateway",
            },
        )

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "auth_error"}


async def test_user_flow_already_configured(hass: HomeAssistant) -> None:
    """Test that duplicate gateways are rejected."""
    from pytest_homeassistant_custom_component.common import MockConfigEntry

    entry = MockConfigEntry(
        domain=DOMAIN,
        title="Existing Gateway",
        data={
            "config_flow_device": "user",
            CONF_HOST: "192.168.1.100",
            CONF_TOKEN: "001E5E0D32906128",
        },
        unique_id="AA:BB:CC:DD:EE:FF",
    )
    entry.add_to_hass(hass)

    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )

    with patch(GATEWAY_PATCH) as mock_gw_cls:
        mock_gw = AsyncMock()
        mock_gw.connect = AsyncMock(return_value="AA:BB:CC:DD:EE:FF")
        mock_gw.close = AsyncMock()
        mock_gw_cls.return_value = mock_gw

        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {
                CONF_HOST: "192.168.1.200",
                CONF_TOKEN: "001E5E0D32906128",
                CONF_NAME: "Duplicate",
            },
        )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"


async def test_gateway_close_called_on_success(hass: HomeAssistant) -> None:
    """Ensure gateway.close() is always called (finally block)."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )

    with patch(GATEWAY_PATCH) as mock_gw_cls:
        mock_gw = AsyncMock()
        mock_gw.connect = AsyncMock(return_value="11:22:33:44:55:66")
        mock_gw.close = AsyncMock()
        mock_gw_cls.return_value = mock_gw

        await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {
                CONF_HOST: "10.0.0.1",
                CONF_TOKEN: "ABCDEF0123456789",
                CONF_NAME: "Test",
            },
        )

    mock_gw.close.assert_awaited_once()


async def test_gateway_close_called_on_error(hass: HomeAssistant) -> None:
    """Ensure gateway.close() is called even when connect fails."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )

    with patch(GATEWAY_PATCH) as mock_gw_cls:
        mock_gw = AsyncMock()
        mock_gw.connect = AsyncMock(side_effect=IT600ConnectionError("fail"))
        mock_gw.close = AsyncMock()
        mock_gw_cls.return_value = mock_gw

        await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {
                CONF_HOST: "10.0.0.1",
                CONF_TOKEN: "ABCDEF0123456789",
                CONF_NAME: "Test",
            },
        )

    mock_gw.close.assert_awaited_once()
