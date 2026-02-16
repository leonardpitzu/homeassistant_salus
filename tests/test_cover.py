"""Tests for the Salus cover entity."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

from homeassistant.components.cover import CoverEntityFeature

from custom_components.salus.const import (
    SUPPORT_CLOSE,
    SUPPORT_OPEN,
    SUPPORT_SET_POSITION,
)
from custom_components.salus.cover import SalusCover
from custom_components.salus.models import CoverDevice


def _make_entity(
    device: CoverDevice,
) -> tuple[SalusCover, AsyncMock]:
    coordinator = MagicMock()
    coordinator.data = {device.unique_id: device}
    coordinator.async_request_refresh = AsyncMock()
    coordinator.async_add_listener = MagicMock(return_value=lambda: None)
    gateway = AsyncMock()
    entity = SalusCover(coordinator, device.unique_id, gateway)
    return entity, gateway


class TestSalusCoverProperties:
    """Test cover entity property delegation."""

    def test_unique_id(self, cover_device):
        entity, _ = _make_entity(cover_device)
        assert entity.unique_id == "cover_001"

    def test_name(self, cover_device):
        entity, _ = _make_entity(cover_device)
        assert entity.name == "Bedroom Blinds"

    def test_available(self, cover_device):
        entity, _ = _make_entity(cover_device)
        assert entity.available is True

    def test_current_cover_position(self, cover_device):
        entity, _ = _make_entity(cover_device)
        assert entity.current_cover_position == 75

    def test_is_closed(self, cover_device):
        entity, _ = _make_entity(cover_device)
        assert entity.is_closed is False

    def test_is_opening(self, cover_device):
        entity, _ = _make_entity(cover_device)
        assert entity.is_opening is None

    def test_is_closing(self, cover_device):
        entity, _ = _make_entity(cover_device)
        assert entity.is_closing is None

    def test_should_poll_false(self, cover_device):
        entity, _ = _make_entity(cover_device)
        assert entity.should_poll is False

    def test_supported_features(self, cover_device):
        entity, _ = _make_entity(cover_device)
        features = entity.supported_features
        assert features & CoverEntityFeature.OPEN
        assert features & CoverEntityFeature.CLOSE
        assert features & CoverEntityFeature.SET_POSITION

    def test_device_info(self, cover_device):
        entity, _ = _make_entity(cover_device)
        info = entity.device_info
        assert info["manufacturer"] == "SALUS"
        assert ("salus", "cover_001") in info["identifiers"]

    def test_closed_cover(self):
        device = CoverDevice(
            available=True,
            name="Closed Blind",
            unique_id="cov_closed",
            current_cover_position=0,
            is_opening=None,
            is_closing=None,
            is_closed=True,
            supported_features=SUPPORT_OPEN | SUPPORT_CLOSE | SUPPORT_SET_POSITION,
            device_class=None,
            data={"UniID": "cov_closed", "Endpoint": 1},
            manufacturer="SALUS",
            model="RS600",
            sw_version="1.0",
        )
        entity, _ = _make_entity(device)
        assert entity.is_closed is True
        assert entity.current_cover_position == 0


class TestSalusCoverCommands:
    """Test cover command forwarding."""

    async def test_open_cover(self, cover_device):
        entity, gw = _make_entity(cover_device)
        await entity.async_open_cover()
        gw.open_cover.assert_awaited_once_with("cover_001")

    async def test_close_cover(self, cover_device):
        entity, gw = _make_entity(cover_device)
        await entity.async_close_cover()
        gw.close_cover.assert_awaited_once_with("cover_001")

    async def test_set_cover_position(self, cover_device):
        entity, gw = _make_entity(cover_device)
        await entity.async_set_cover_position(position=50)
        gw.set_cover_position.assert_awaited_once_with("cover_001", 50)

    async def test_set_cover_position_none(self, cover_device):
        """No-op when position kwarg is missing."""
        entity, gw = _make_entity(cover_device)
        await entity.async_set_cover_position()
        gw.set_cover_position.assert_not_awaited()

    async def test_commands_trigger_refresh(self, cover_device):
        entity, _ = _make_entity(cover_device)
        await entity.async_open_cover()
        entity._coordinator.async_request_refresh.assert_awaited_once()
