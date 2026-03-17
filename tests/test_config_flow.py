"""Tests for the Salus config flow."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_NAME, CONF_TOKEN
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType

from custom_components.salus.const import (
    CONF_POLL_FAILURE_THRESHOLD,
    DEFAULT_POLL_FAILURE_THRESHOLD,
    DOMAIN,
)
from custom_components.salus.exceptions import (
    IT600AuthenticationError,
    IT600ConnectionError,
    IT600UnsupportedFirmwareError,
)

GATEWAY_PATCH = "custom_components.salus.config_flow.IT600Gateway"
SETUP_ENTRY_PATCH = "custom_components.salus.async_setup_entry"


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

    with (
        patch(GATEWAY_PATCH) as mock_gw_cls,
        patch(SETUP_ENTRY_PATCH, return_value=True),
    ):
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


async def test_user_flow_unsupported_firmware(hass: HomeAssistant) -> None:
    """Test config flow when gateway has new unsupported firmware."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )

    with patch(GATEWAY_PATCH) as mock_gw_cls:
        mock_gw = AsyncMock()
        mock_gw.connect = AsyncMock(
            side_effect=IT600UnsupportedFirmwareError("reject frames")
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
    assert result["errors"] == {"base": "unsupported_firmware"}


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

    with (
        patch(GATEWAY_PATCH) as mock_gw_cls,
        patch(SETUP_ENTRY_PATCH, return_value=True),
    ):
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


# ── Options flow tests ──────────────────────────────────────────────


async def test_options_flow_shows_form(hass: HomeAssistant) -> None:
    """Test that the options flow shows the form with the current value."""
    from pytest_homeassistant_custom_component.common import MockConfigEntry

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

    result = await hass.config_entries.options.async_init(entry.entry_id)
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "init"


async def test_options_flow_saves_threshold(hass: HomeAssistant) -> None:
    """Test that submitting the options form saves the threshold."""
    from pytest_homeassistant_custom_component.common import MockConfigEntry

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

    result = await hass.config_entries.options.async_init(entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"],
        user_input={CONF_POLL_FAILURE_THRESHOLD: 5},
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"][CONF_POLL_FAILURE_THRESHOLD] == 5


async def test_options_flow_default_value(hass: HomeAssistant) -> None:
    """Test that the default threshold matches the constant."""
    from pytest_homeassistant_custom_component.common import MockConfigEntry

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

    # Submit with the default (no changes)
    result = await hass.config_entries.options.async_init(entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"],
        user_input={CONF_POLL_FAILURE_THRESHOLD: DEFAULT_POLL_FAILURE_THRESHOLD},
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"][CONF_POLL_FAILURE_THRESHOLD] == DEFAULT_POLL_FAILURE_THRESHOLD
