"""Base entity for the Salus iT600 integration."""

from __future__ import annotations

from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
    DataUpdateCoordinator,
)

from .const import DOMAIN
from .gateway import IT600Gateway


class SalusEntity(CoordinatorEntity):
    """Base class for all Salus entities.

    Provides shared plumbing: unique_id, name, available, device_info,
    should_poll (False), and coordinator listener registration.
    """

    _attr_has_entity_name = False

    def __init__(
        self,
        coordinator: DataUpdateCoordinator,
        idx: str,
        gateway: IT600Gateway,
    ) -> None:
        """Initialise the entity."""
        super().__init__(coordinator)
        self._idx = idx
        self._gateway = gateway

    # Subclasses MUST override this to return the appropriate model object.
    @property
    def _device(self):  # noqa: D401 – first line imperative
        """Underlying device model (gateway dataclass)."""
        raise NotImplementedError

    # -- common properties ------------------------------------------------

    @property
    def available(self) -> bool:
        """Entity available when coordinator succeeded *and* device online."""
        if not super().available:
            return False
        d = self._device
        return d is not None and d.available

    @property
    def unique_id(self) -> str:
        return self._device.unique_id

    @property
    def name(self) -> str:
        return self._device.name

    @property
    def device_info(self) -> dict:
        d = self._device
        parent = getattr(d, "parent_unique_id", None)
        if parent:
            return {"identifiers": {(DOMAIN, parent)}}
        return {
            "name": d.name,
            "identifiers": {(DOMAIN, d.unique_id)},
            "manufacturer": d.manufacturer,
            "model": d.model,
            "sw_version": d.sw_version,
        }
