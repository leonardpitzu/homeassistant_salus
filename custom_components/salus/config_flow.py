"""Config flow to configure Salus iT600 component."""

from __future__ import annotations

import logging

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_NAME, CONF_TOKEN

from .const import DOMAIN
from .exceptions import IT600AuthenticationError, IT600ConnectionError
from .gateway import IT600Gateway

_LOGGER = logging.getLogger(__name__)

CONF_FLOW_TYPE = "config_flow_device"
CONF_USER = "user"
DEFAULT_GATEWAY_NAME = "Salus iT600 Gateway"

GATEWAY_SETTINGS = {
    vol.Required(CONF_HOST): str,
    vol.Required(CONF_TOKEN): vol.All(str, vol.Length(min=16, max=16)),
    vol.Optional(CONF_NAME, default=DEFAULT_GATEWAY_NAME): str,
}


class SalusFlowHandler(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a Salus config flow."""

    VERSION = 1
    CONNECTION_CLASS = config_entries.CONN_CLASS_LOCAL_POLL

    async def async_step_user(
        self, user_input: dict[str, str] | None = None
    ) -> config_entries.ConfigFlowResult:
        """Handle a flow initialized by the user to configure a gateway."""
        errors: dict[str, str] = {}

        if user_input is not None:
            host = user_input[CONF_HOST]
            token = user_input[CONF_TOKEN]

            gateway = IT600Gateway(host=host, euid=token)
            try:
                unique_id = await gateway.connect()
                await self.async_set_unique_id(unique_id)
                self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title=user_input[CONF_NAME],
                    data={
                        CONF_FLOW_TYPE: CONF_USER,
                        CONF_HOST: host,
                        CONF_TOKEN: token,
                        "mac": unique_id,
                    },
                )
            except IT600ConnectionError:
                errors["base"] = "connect_error"
            except IT600AuthenticationError:
                errors["base"] = "auth_error"
            finally:
                await gateway.close()

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(GATEWAY_SETTINGS),
            errors=errors,
        )

