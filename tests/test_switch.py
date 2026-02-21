"""Tests for the Salus switch entity."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

from custom_components.salus.models import SwitchDevice
from custom_components.salus.switch import SalusSwitch


def _make_entity(
    device: SwitchDevice,
) -> tuple[SalusSwitch, AsyncMock]:
    coordinator = MagicMock()
    coordinator.async_request_refresh = AsyncMock()
    coordinator.async_add_listener = MagicMock(return_value=lambda: None)
    gateway = AsyncMock()
    gateway.get_switch_device = MagicMock(return_value=device)
    entity = SalusSwitch(coordinator, device.unique_id, gateway)
    return entity, gateway


class TestSalusSwitchProperties:
    """Test switch entity property delegation."""

    def test_unique_id(self, switch_device):
        entity, _ = _make_entity(switch_device)
        assert entity.unique_id == "switch_001_1"

    def test_name(self, switch_device):
        entity, _ = _make_entity(switch_device)
        assert entity.name == "Kitchen Plug"

    def test_available(self, switch_device):
        entity, _ = _make_entity(switch_device)
        assert entity.available is True

    def test_is_on(self, switch_device):
        entity, _ = _make_entity(switch_device)
        assert entity.is_on is True

    def test_device_class(self, switch_device):
        entity, _ = _make_entity(switch_device)
        assert entity.device_class == "outlet"

    def test_should_poll_false(self, switch_device):
        entity, _ = _make_entity(switch_device)
        assert entity.should_poll is False

    def test_device_info(self, switch_device):
        entity, _ = _make_entity(switch_device)
        info = entity.device_info
        assert info["manufacturer"] == "SALUS"
        assert info["model"] == "SP600"


class TestSalusSwitchCommands:
    """Test switch command forwarding."""

    async def test_turn_on(self, switch_device):
        entity, gw = _make_entity(switch_device)
        await entity.async_turn_on()
        gw.turn_on_switch_device.assert_awaited_once_with("switch_001_1")

    async def test_turn_off(self, switch_device):
        entity, gw = _make_entity(switch_device)
        await entity.async_turn_off()
        gw.turn_off_switch_device.assert_awaited_once_with("switch_001_1")

    async def test_turn_on_triggers_refresh(self, switch_device):
        entity, _ = _make_entity(switch_device)
        await entity.async_turn_on()
        entity.coordinator.async_request_refresh.assert_awaited_once()

    async def test_turn_off_triggers_refresh(self, switch_device):
        entity, _ = _make_entity(switch_device)
        await entity.async_turn_off()
        entity.coordinator.async_request_refresh.assert_awaited_once()
