"""Tests for the Salus thermostat child-lock entity."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from homeassistant.const import EntityCategory

from custom_components.salus.const import DOMAIN
from custom_components.salus.lock import SalusThermostatLock
from custom_components.salus.models import ClimateDevice

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def lockable_climate_device(climate_device: ClimateDevice) -> ClimateDevice:
    """Return a climate device that supports the child lock (locked != None)."""
    # climate_device fixture has locked=None; override with a locked variant
    from dataclasses import replace
    return replace(climate_device, locked=False)


def _make_entity(
    device: ClimateDevice,
) -> tuple[SalusThermostatLock, AsyncMock]:
    coordinator = MagicMock()
    coordinator.async_request_refresh = AsyncMock()
    coordinator.async_add_listener = MagicMock(return_value=lambda: None)
    gateway = AsyncMock()
    gateway.get_climate_device = MagicMock(return_value=device)
    entity = SalusThermostatLock(coordinator, device.unique_id, gateway)
    return entity, gateway


# ---------------------------------------------------------------------------
# Property tests
# ---------------------------------------------------------------------------

class TestSalusThermostatLockProperties:
    """Test lock entity property delegation."""

    def test_unique_id(self, lockable_climate_device):
        entity, _ = _make_entity(lockable_climate_device)
        assert entity.unique_id == f"{lockable_climate_device.unique_id}_lock"

    def test_name(self, lockable_climate_device):
        entity, _ = _make_entity(lockable_climate_device)
        assert entity.name == f"{lockable_climate_device.name} Child lock"

    def test_entity_category(self, lockable_climate_device):
        entity, _ = _make_entity(lockable_climate_device)
        assert entity.entity_category == EntityCategory.CONFIG

    def test_is_locked_when_locked(self, lockable_climate_device):
        from dataclasses import replace
        locked_dev = replace(lockable_climate_device, locked=True)
        entity, _ = _make_entity(locked_dev)
        # Override the gateway mock return to return locked device
        entity._gateway.get_climate_device.return_value = locked_dev
        assert entity.is_locked is True

    def test_is_locked_when_unlocked(self, lockable_climate_device):
        entity, _ = _make_entity(lockable_climate_device)
        assert entity.is_locked is False

    def test_device_info(self, lockable_climate_device):
        entity, _ = _make_entity(lockable_climate_device)
        info = entity.device_info
        assert info == {
            "identifiers": {(DOMAIN, lockable_climate_device.unique_id)},
        }


# ---------------------------------------------------------------------------
# Command tests
# ---------------------------------------------------------------------------

class TestSalusThermostatLockCommands:
    """Test lock/unlock forwarding to the gateway."""

    async def test_async_lock(self, lockable_climate_device):
        entity, gw = _make_entity(lockable_climate_device)
        await entity.async_lock()
        gw.set_climate_device_locked.assert_awaited_once_with(
            lockable_climate_device.unique_id, True,
        )
        entity.coordinator.async_request_refresh.assert_awaited_once()

    async def test_async_unlock(self, lockable_climate_device):
        entity, gw = _make_entity(lockable_climate_device)
        await entity.async_unlock()
        gw.set_climate_device_locked.assert_awaited_once_with(
            lockable_climate_device.unique_id, False,
        )
        entity.coordinator.async_request_refresh.assert_awaited_once()
