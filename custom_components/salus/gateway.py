"""Salus iT600 gateway API — local encrypted HTTP communication."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Callable, Awaitable

import aiohttp
from aiohttp import client_exceptions

from .const import (
    BATTERY_ERROR_CODES,
    BATTERY_LEVEL_MAP,
    BATTERY_OEM_MODELS,
    BATTERY_VOLTAGE_THRESHOLDS,
    COVER_DEVICE_CLASS_MAP,
    CURRENT_HVAC_COOL,
    CURRENT_HVAC_COOL_IDLE,
    CURRENT_HVAC_HEAT,
    CURRENT_HVAC_HEAT_IDLE,
    CURRENT_HVAC_IDLE,
    CURRENT_HVAC_OFF,
    DOOR_VOLTAGE_MODELS,
    ENERGY_METER_VOLTAGE_MODELS,
    FAN_MODE_AUTO,
    FAN_MODE_HIGH,
    FAN_MODE_LOW,
    FAN_MODE_MEDIUM,
    FAN_MODE_OFF,
    HVAC_MODE_AUTO,
    HVAC_MODE_COOL,
    HVAC_MODE_HEAT,
    HVAC_MODE_OFF,
    PRESET_ECO,
    PRESET_FOLLOW_SCHEDULE,
    PRESET_OFF,
    PRESET_PERMANENT_HOLD,
    PRESET_TEMPORARY_HOLD,
    SUPPORT_CLOSE,
    SUPPORT_FAN_MODE,
    SUPPORT_OPEN,
    SUPPORT_PRESET_MODE,
    SUPPORT_SET_POSITION,
    SUPPORT_TARGET_TEMPERATURE,
    TEMP_CELSIUS,
    THERMOSTAT_ERROR_CODES,
    WINDOW_VOLTAGE_MODELS,
)
from .encryptor import IT600Encryptor
from .exceptions import (
    IT600AuthenticationError,
    IT600CommandError,
    IT600ConnectionError,
)
from .models import (
    BinarySensorDevice,
    ClimateDevice,
    CoverDevice,
    GatewayDevice,
    SensorDevice,
    SwitchDevice,
)

_LOGGER = logging.getLogger(__name__)


class IT600Gateway:
    """Async client for the Salus iT600 universal gateway (local mode)."""

    def __init__(
        self,
        euid: str,
        host: str,
        port: int = 80,
        request_timeout: int = 5,
        session: aiohttp.ClientSession | None = None,
        debug: bool = False,
    ) -> None:
        self._encryptor = IT600Encryptor(euid)
        self._host = host
        self._port = port
        self._request_timeout = request_timeout
        self._debug = debug
        self._lock = asyncio.Lock()

        self._session = session
        self._close_session = False

        self._gateway_device: GatewayDevice | None = None

        self._climate_devices: dict[str, ClimateDevice] = {}
        self._climate_update_callbacks: list[Callable[..., Awaitable[None]]] = []

        self._binary_sensor_devices: dict[str, BinarySensorDevice] = {}
        self._binary_sensor_update_callbacks: list[Callable[..., Awaitable[None]]] = []

        self._switch_devices: dict[str, SwitchDevice] = {}
        self._switch_update_callbacks: list[Callable[..., Awaitable[None]]] = []

        self._cover_devices: dict[str, CoverDevice] = {}
        self._cover_update_callbacks: list[Callable[..., Awaitable[None]]] = []

        self._sensor_devices: dict[str, SensorDevice] = {}
        self._battery_sensor_devices: dict[str, SensorDevice] = {}
        self._humidity_sensor_devices: dict[str, SensorDevice] = {}
        self._energy_sensor_devices: dict[str, SensorDevice] = {}
        self._sensor_update_callbacks: list[Callable[..., Awaitable[None]]] = []

        self._error_binary_sensor_devices: dict[str, BinarySensorDevice] = {}

    # ------------------------------------------------------------------
    #  Connection
    # ------------------------------------------------------------------

    async def connect(self) -> str:
        """Connect to the gateway and return its MAC address."""
        _LOGGER.debug("Trying to connect to gateway at %s", self._host)

        if self._session is None:
            self._session = aiohttp.ClientSession()
            self._close_session = True

        try:
            all_devices = await self._make_encrypted_request(
                "read", {"requestAttr": "readall"}
            )

            gateway = next(
                (
                    x
                    for x in all_devices["id"]
                    if x.get("sGateway", {}).get("NetworkLANMAC", "")
                ),
                None,
            )

            if gateway is None:
                raise IT600CommandError(
                    "Gateway response did not contain gateway information"
                )

            return gateway["sGateway"]["NetworkLANMAC"]

        except IT600ConnectionError as exc:
            # Distinguish bad host from bad EUID: if a plain GET succeeds the
            # host is reachable but the EUID must be wrong.
            try:
                async with asyncio.timeout(self._request_timeout):
                    await self._session.get(
                        f"http://{self._host}:{self._port}/"
                    )
            except Exception:
                raise IT600ConnectionError(
                    "Cannot reach iT600 gateway — check host / IP address"
                ) from exc

            raise IT600AuthenticationError(
                "Gateway reachable but authentication failed — check EUID"
            ) from exc

    # ------------------------------------------------------------------
    #  Polling
    # ------------------------------------------------------------------

    async def poll_status(self, send_callback: bool = False) -> None:
        """Poll every device category from the gateway."""
        all_devices = await self._make_encrypted_request(
            "read", {"requestAttr": "readall"}
        )

        for label, key, refresher in (
            ("gateway", "sGateway", self._refresh_gateway_device),
            ("climate", ("sIT600TH", "sTherS"), self._refresh_climate_devices),
            ("binary_sensor", "sIASZS", None),  # handled specially below
            ("sensor", "sTempS", self._refresh_sensor_devices),
            ("switch", "sOnOffS", self._refresh_switch_devices),
            ("cover", "sLevelS", self._refresh_cover_devices),
        ):
            try:
                if label == "climate":
                    filtered = [
                        x
                        for x in all_devices["id"]
                        if "sIT600TH" in x or "sTherS" in x
                    ]
                    await self._refresh_climate_devices(filtered, send_callback)
                elif label == "binary_sensor":
                    filtered = [
                        x
                        for x in all_devices["id"]
                        if "sIASZS" in x
                        or (
                            "sBasicS" in x
                            and x["sBasicS"].get("ModelIdentifier")
                            in ("it600MINITRV", "it600Receiver")
                        )
                    ]
                    await self._refresh_binary_sensor_devices(
                        filtered, send_callback
                    )
                elif label == "gateway":
                    filtered = [
                        x for x in all_devices["id"] if "sGateway" in x
                    ]
                    await self._refresh_gateway_device(filtered, send_callback)
                else:
                    filtered = [
                        x for x in all_devices["id"] if key in x
                    ]
                    await refresher(filtered, send_callback)
            except Exception:
                _LOGGER.exception("Failed to poll %s devices", label)

    # ------------------------------------------------------------------
    #  Per-category refresh helpers
    # ------------------------------------------------------------------

    async def _refresh_gateway_device(
        self, devices: list[Any], send_callback: bool = False
    ) -> None:
        if not devices:
            return

        status = await self._make_encrypted_request(
            "read",
            {
                "requestAttr": "deviceid",
                "id": [{"data": d["data"]} for d in devices],
            },
        )

        for ds in status["id"]:
            unique_id = ds.get("sGateway", {}).get("NetworkLANMAC")
            if unique_id is None:
                continue

            model = ds.get("sGateway", {}).get("ModelIdentifier")
            try:
                self._gateway_device = GatewayDevice(
                    name=model or "Salus Gateway",
                    unique_id=unique_id,
                    data=ds["data"],
                    manufacturer=ds.get("sBasicS", {}).get(
                        "ManufactureName", "SALUS"
                    ),
                    model=model,
                    sw_version=ds.get("sOTA", {}).get(
                        "OTAFirmwareVersion_d"
                    ),
                )
            except Exception:
                _LOGGER.exception("Failed to parse gateway %s", unique_id)

        _LOGGER.debug("Refreshed gateway device")

    # ---- covers ----

    async def _refresh_cover_devices(
        self, devices: list[Any], send_callback: bool = False
    ) -> None:
        local: dict[str, CoverDevice] = {}

        if not devices:
            self._cover_devices = local
            return

        status = await self._make_encrypted_request(
            "read",
            {
                "requestAttr": "deviceid",
                "id": [{"data": d["data"]} for d in devices],
            },
        )

        for ds in status["id"]:
            unique_id = ds.get("data", {}).get("UniID")
            if unique_id is None:
                continue
            try:
                if ds.get("sButtonS", {}).get("Mode") == 0:
                    continue  # disabled endpoint

                model_id = ds.get("DeviceL", {}).get(
                    "ModelIdentifier_i"
                )

                current_position = ds.get("sLevelS", {}).get("CurrentLevel")

                move_raw = ds.get("sLevelS", {}).get("MoveToLevel_f")
                set_position: int | None = None
                if move_raw and len(move_raw) >= 2:
                    set_position = int(move_raw[:2], 16)

                device = CoverDevice(
                    available=ds.get("sZDOInfo", {}).get("OnlineStatus_i", 1)
                    == 1,
                    name=self._device_name(ds, "Unknown"),
                    unique_id=unique_id,
                    current_cover_position=current_position,
                    is_opening=(
                        None
                        if set_position is None
                        else current_position < set_position
                    ),
                    is_closing=(
                        None
                        if set_position is None
                        else current_position > set_position
                    ),
                    is_closed=current_position == 0,
                    supported_features=(
                        SUPPORT_OPEN | SUPPORT_CLOSE | SUPPORT_SET_POSITION
                    ),
                    device_class=COVER_DEVICE_CLASS_MAP.get(model_id),
                    data=ds["data"],
                    manufacturer=ds.get("sBasicS", {}).get(
                        "ManufactureName", "SALUS"
                    ),
                    model=model_id,
                    sw_version=ds.get("sZDO", {}).get("FirmwareVersion"),
                )
                local[device.unique_id] = device

                if send_callback:
                    self._cover_devices[device.unique_id] = device
                    await self._send_cover_update_callback(device.unique_id)
            except Exception:
                _LOGGER.exception("Failed to poll cover %s", unique_id)

        self._cover_devices = local
        _LOGGER.debug("Refreshed %s cover devices", len(local))

    # ---- switches ----

    async def _refresh_switch_devices(
        self, devices: list[Any], send_callback: bool = False
    ) -> None:
        local: dict[str, SwitchDevice] = {}
        energy_local: dict[str, SensorDevice] = {}

        if not devices:
            self._switch_devices = local
            self._energy_sensor_devices = energy_local
            return

        status = await self._make_encrypted_request(
            "read",
            {
                "requestAttr": "deviceid",
                "id": [{"data": d["data"]} for d in devices],
            },
        )

        for ds in status["id"]:
            unique_id = ds.get("data", {}).get("UniID")
            if unique_id is None:
                continue

            # Double switches share UniID — disambiguate via endpoint
            unique_id = f"{unique_id}_{ds['data']['Endpoint']}"

            try:
                if ds.get("sLevelS") is not None:
                    continue  # skip roller-shutter endpoint in combo device

                is_on = ds.get("sOnOffS", {}).get("OnOff")
                if is_on is None:
                    continue

                model = ds.get("DeviceL", {}).get("ModelIdentifier_i")

                device = SwitchDevice(
                    available=ds.get("sZDOInfo", {}).get("OnlineStatus_i", 1)
                    == 1,
                    name=self._device_name(ds, unique_id),
                    unique_id=unique_id,
                    is_on=is_on == 1,
                    device_class=(
                        "outlet"
                        if model in ("SP600", "SPE600")
                        else "switch"
                    ),
                    data=ds["data"],
                    manufacturer=ds.get("sBasicS", {}).get(
                        "ManufactureName", "SALUS"
                    ),
                    model=model,
                    sw_version=ds.get("sZDO", {}).get("FirmwareVersion"),
                )
                local[device.unique_id] = device

                # sMeteringS → power & energy sensors for smart plugs
                metering = ds.get("sMeteringS", {})
                power_raw = metering.get("InstantaneousDemand")
                if power_raw is not None:
                    pwr_uid = f"{unique_id}_power"
                    energy_local[pwr_uid] = SensorDevice(
                        available=device.available,
                        name=f"{device.name} Power",
                        unique_id=pwr_uid,
                        state=power_raw,
                        unit_of_measurement="W",
                        device_class="power",
                        data=ds["data"],
                        manufacturer=device.manufacturer,
                        model=device.model,
                        sw_version=device.sw_version,
                        parent_unique_id=unique_id,
                        entity_category=None,
                    )
                energy_raw = metering.get("CurrentSummationDelivered")
                if energy_raw is not None:
                    nrg_uid = f"{unique_id}_energy"
                    energy_local[nrg_uid] = SensorDevice(
                        available=device.available,
                        name=f"{device.name} Energy",
                        unique_id=nrg_uid,
                        state=energy_raw / 1000,
                        unit_of_measurement="kWh",
                        device_class="energy",
                        data=ds["data"],
                        manufacturer=device.manufacturer,
                        model=device.model,
                        sw_version=device.sw_version,
                        parent_unique_id=unique_id,
                        entity_category=None,
                    )

                if send_callback:
                    self._switch_devices[device.unique_id] = device
                    await self._send_switch_update_callback(device.unique_id)
            except Exception:
                _LOGGER.exception("Failed to poll switch %s", unique_id)

        self._switch_devices = local
        self._energy_sensor_devices = energy_local
        _LOGGER.debug("Refreshed %s switch devices", len(local))

    # ---- sensors ----

    async def _refresh_sensor_devices(
        self, devices: list[Any], send_callback: bool = False
    ) -> None:
        local: dict[str, SensorDevice] = {}

        if not devices:
            self._sensor_devices = local
            return

        status = await self._make_encrypted_request(
            "read",
            {
                "requestAttr": "deviceid",
                "id": [{"data": d["data"]} for d in devices],
            },
        )

        for ds in status["id"]:
            unique_id = ds.get("data", {}).get("UniID")
            if unique_id is None:
                continue
            try:
                temperature = ds.get("sTempS", {}).get("MeasuredValue_x100")
                if temperature is None:
                    continue

                sensor_uid = f"{unique_id}_temp"
                model = ds.get("DeviceL", {}).get("ModelIdentifier_i")

                device = SensorDevice(
                    available=ds.get("sZDOInfo", {}).get("OnlineStatus_i", 1)
                    == 1,
                    name=self._device_name(ds, "Unknown"),
                    unique_id=sensor_uid,
                    state=temperature / 100,
                    unit_of_measurement=TEMP_CELSIUS,
                    device_class="temperature",
                    data=ds["data"],
                    manufacturer=ds.get("sBasicS", {}).get(
                        "ManufactureName", "SALUS"
                    ),
                    model=model,
                    sw_version=ds.get("sZDO", {}).get("FirmwareVersion"),
                )
                local[device.unique_id] = device

                if send_callback:
                    self._sensor_devices[device.unique_id] = device
                    await self._send_sensor_update_callback(device.unique_id)

                # sRelativeHumidity (standard Zigbee 0x0405 cluster) — present on
                # standalone multi-sensors such as TS600 but NOT on thermostats.
                # For thermostats (sIT600TH) humidity is read in
                # _refresh_climate_devices from SunnySetpoint_x100 instead.
                humidity_raw = (
                    ds.get("sRelativeHumidity", {}).get("MeasuredValue_x100")
                )
                if humidity_raw is not None:
                    hum_uid = f"{unique_id}_humidity"
                    hum = SensorDevice(
                        available=device.available,
                        name=f"{device.name} Humidity",
                        unique_id=hum_uid,
                        state=humidity_raw / 100,
                        unit_of_measurement="%",
                        device_class="humidity",
                        data=ds["data"],
                        manufacturer=device.manufacturer,
                        model=device.model,
                        sw_version=device.sw_version,
                        parent_unique_id=unique_id,
                        entity_category=None,
                    )
                    local[hum_uid] = hum

                    if send_callback:
                        self._sensor_devices[hum_uid] = hum
                        await self._send_sensor_update_callback(hum_uid)

                # BatteryVoltage_x10 → percentage battery sensor
                voltage_raw = ds.get("sPowerS", {}).get(
                    "BatteryVoltage_x10"
                )
                if voltage_raw is not None:
                    voltage = voltage_raw / 10
                    pct = self._voltage_to_battery_pct(voltage, model)
                    if pct is not None:
                        bat_uid = f"{unique_id}_battery"
                        bat = SensorDevice(
                            available=device.available,
                            name=f"{device.name} Battery",
                            unique_id=bat_uid,
                            state=pct,
                            unit_of_measurement="%",
                            device_class="battery",
                            data=ds["data"],
                            manufacturer=device.manufacturer,
                            model=device.model,
                            sw_version=device.sw_version,
                            parent_unique_id=unique_id,
                            entity_category="diagnostic",
                        )
                        local[bat_uid] = bat

            except Exception:
                _LOGGER.exception("Failed to poll sensor %s", unique_id)

        self._sensor_devices = local
        _LOGGER.debug("Refreshed %s sensor devices", len(local))

    # ---- binary sensors ----

    async def _refresh_binary_sensor_devices(
        self, devices: list[Any], send_callback: bool = False
    ) -> None:
        local: dict[str, BinarySensorDevice] = {}

        if not devices:
            self._binary_sensor_devices = local
            return

        status = await self._make_encrypted_request(
            "read",
            {
                "requestAttr": "deviceid",
                "id": [{"data": d["data"]} for d in devices],
            },
        )

        for ds in status["id"]:
            unique_id = ds.get("data", {}).get("UniID")
            if unique_id is None:
                continue
            try:
                model = ds.get("DeviceL", {}).get("ModelIdentifier_i")

                if model in ("it600MINITRV", "it600Receiver"):
                    is_on = ds.get("sIT600I", {}).get("RelayStatus")
                else:
                    is_on = ds.get("sIASZS", {}).get("ErrorIASZSAlarmed1")

                if is_on is None:
                    continue
                if model == "SB600":
                    continue  # skip button device

                device_class: str | None
                if model in ("SW600", "OS600"):
                    device_class = "window"
                elif model == "WLS600":
                    device_class = "moisture"
                elif model == "SmokeSensor-EM":
                    device_class = "smoke"
                elif model == "it600MINITRV":
                    device_class = "heat"
                elif model == "it600Receiver":
                    device_class = "running"
                else:
                    device_class = None

                device = BinarySensorDevice(
                    available=ds.get("sZDOInfo", {}).get("OnlineStatus_i", 1)
                    == 1,
                    name=self._device_name(ds, "Unknown"),
                    unique_id=unique_id,
                    is_on=is_on == 1,
                    device_class=device_class,
                    data=ds["data"],
                    manufacturer=ds.get("sBasicS", {}).get(
                        "ManufactureName", "SALUS"
                    ),
                    model=model,
                    sw_version=ds.get("sZDO", {}).get("FirmwareVersion"),
                )
                local[device.unique_id] = device

                # Low-battery binary sensors from sPowerS / sIASZS
                low_batt_iaszs = ds.get("sIASZS", {}).get(
                    "ErrorIASZSLowBattery"
                )
                low_batt_power = ds.get("sPowerS", {}).get(
                    "ErrorPowerSLowBattery"
                )
                if low_batt_iaszs is not None:
                    lb_uid = f"{unique_id}_low_battery"
                    local[lb_uid] = BinarySensorDevice(
                        available=device.available,
                        name=f"{device.name} Low battery",
                        unique_id=lb_uid,
                        is_on=low_batt_iaszs == 1,
                        device_class="battery",
                        data=ds["data"],
                        manufacturer=device.manufacturer,
                        model=device.model,
                        sw_version=device.sw_version,
                        parent_unique_id=unique_id,
                        entity_category="diagnostic",
                    )
                elif low_batt_power is not None:
                    lb_uid = f"{unique_id}_low_battery"
                    local[lb_uid] = BinarySensorDevice(
                        available=device.available,
                        name=f"{device.name} Low battery",
                        unique_id=lb_uid,
                        is_on=low_batt_power == 1,
                        device_class="battery",
                        data=ds["data"],
                        manufacturer=device.manufacturer,
                        model=device.model,
                        sw_version=device.sw_version,
                        parent_unique_id=unique_id,
                        entity_category="diagnostic",
                    )

                if send_callback:
                    self._binary_sensor_devices[device.unique_id] = device
                    await self._send_binary_sensor_update_callback(
                        device.unique_id
                    )
            except Exception:
                _LOGGER.exception(
                    "Failed to poll binary sensor %s", unique_id
                )

        self._binary_sensor_devices = local
        _LOGGER.debug(
            "Refreshed %s binary sensor devices", len(local)
        )

    # ---- climate ----

    async def _refresh_climate_devices(
        self, devices: list[Any], send_callback: bool = False
    ) -> None:
        local: dict[str, ClimateDevice] = {}
        battery_local: dict[str, SensorDevice] = {}
        humidity_local: dict[str, SensorDevice] = {}
        error_local: dict[str, BinarySensorDevice] = {}

        if not devices:
            self._climate_devices = local
            self._battery_sensor_devices = battery_local
            self._humidity_sensor_devices = humidity_local
            self._error_binary_sensor_devices = error_local
            return

        status = await self._make_encrypted_request(
            "read",
            {
                "requestAttr": "deviceid",
                "id": [{"data": d["data"]} for d in devices],
            },
        )

        for ds in status["id"]:
            unique_id = ds.get("data", {}).get("UniID")
            if unique_id is None:
                continue
            try:
                model = ds.get("DeviceL", {}).get("ModelIdentifier_i")

                th = ds.get("sIT600TH")
                ther = ds.get("sTherS")
                scomm = ds.get("sComm")
                sfans = ds.get("sFanS")

                _LOGGER.debug(
                    "Climate device %s: model=%r keys=%s th=%s",
                    unique_id,
                    model,
                    sorted(k for k in ds if not k.startswith("_")),
                    th is not None,
                )

                common = {
                    "available": ds.get("sZDOInfo", {}).get(
                        "OnlineStatus_i", 1
                    )
                    == 1,
                    "name": self._device_name(ds, "Unknown"),
                    "unique_id": unique_id,
                    "temperature_unit": TEMP_CELSIUS,
                    "precision": 0.1,
                    "device_class": "temperature",
                    "data": ds["data"],
                    "manufacturer": ds.get("sBasicS", {}).get(
                        "ManufactureName", "SALUS"
                    ),
                    "model": model,
                    "sw_version": ds.get("sZDO", {}).get("FirmwareVersion"),
                }

                if th is not None:
                    humidity: float | None = None
                    # HeatingControl is stored in Status_d at hex positions
                    # 32-33 (propStart:32, propLen:2 per official Salus cloud
                    # app JS).  A value of 1 means the device has a humidity
                    # sensor; SunnySetpoint_x100 then holds the current
                    # relative humidity as a plain integer (0-100 %).
                    # This applies to SQ610 / SQ610RF / SQ610(WB) family.
                    # SQ610RFNH and plain iT600 thermostats have
                    # HeatingControl == 0 and are correctly excluded.
                    status_d = th.get("Status_d", "")
                    heating_ctrl = (
                        int(status_d[32:34], 16)
                        if len(status_d) >= 34
                        else 0
                    )
                    # Fall back to model-name check if Status_d is absent or
                    # HeatingControl is 0: SQ610/SQ610RF/SQ610(WB) all have a
                    # humidity sensor; SQ610RFNH ("No Humidity") does not.
                    model_str = model or ""
                    model_has_humidity = (
                        "SQ610" in model_str and "RFNH" not in model_str
                    )
                    _LOGGER.debug(
                        "Humidity gate for %s: model=%r status_d=%r "
                        "heating_ctrl=%d model_has_humidity=%s "
                        "SunnySetpoint_x100=%s",
                        unique_id,
                        model_str,
                        status_d,
                        heating_ctrl,
                        model_has_humidity,
                        th.get("SunnySetpoint_x100"),
                    )
                    if heating_ctrl == 1 or model_has_humidity:
                        sunny = th.get("SunnySetpoint_x100")
                        if sunny is not None:
                            humidity = float(sunny)
                            hum_uid = f"{unique_id}_humidity"
                            humidity_local[hum_uid] = SensorDevice(
                                available=ds.get("sZDOInfo", {}).get(
                                    "OnlineStatus_i", 1
                                ) == 1,
                                name=f"{self._device_name(ds, 'Unknown')} Humidity",
                                unique_id=hum_uid,
                                state=humidity,
                                unit_of_measurement="%",
                                device_class="humidity",
                                data=ds["data"],
                                manufacturer=ds.get("sBasicS", {}).get(
                                    "ManufactureName", "SALUS"
                                ),
                                model=model,
                                sw_version=ds.get("sZDO", {}).get(
                                    "FirmwareVersion"
                                ),
                                parent_unique_id=unique_id,
                                entity_category=None,
                            )

                    hold = th["HoldType"]
                    running = th["RunningState"]

                    device = ClimateDevice(
                        **common,
                        current_humidity=humidity,
                        current_temperature=th["LocalTemperature_x100"] / 100,
                        target_temperature=th["HeatingSetpoint_x100"] / 100,
                        max_temp=th.get("MaxHeatSetpoint_x100", 3500) / 100,
                        min_temp=th.get("MinHeatSetpoint_x100", 500) / 100,
                        hvac_mode=(
                            HVAC_MODE_OFF
                            if hold == 7
                            else HVAC_MODE_HEAT
                            if hold == 2
                            else HVAC_MODE_AUTO
                        ),
                        hvac_action=(
                            CURRENT_HVAC_OFF
                            if hold == 7
                            else CURRENT_HVAC_IDLE
                            if running % 2 == 0
                            else CURRENT_HVAC_HEAT
                        ),
                        hvac_modes=[
                            HVAC_MODE_OFF,
                            HVAC_MODE_HEAT,
                            HVAC_MODE_AUTO,
                        ],
                        preset_mode=(
                            PRESET_OFF
                            if hold == 7
                            else PRESET_PERMANENT_HOLD
                            if hold == 2
                            else PRESET_FOLLOW_SCHEDULE
                        ),
                        preset_modes=[
                            PRESET_FOLLOW_SCHEDULE,
                            PRESET_PERMANENT_HOLD,
                            PRESET_OFF,
                        ],
                        fan_mode=None,
                        fan_modes=None,
                        locked=None,
                        supported_features=(
                            SUPPORT_TARGET_TEMPERATURE | SUPPORT_PRESET_MODE
                        ),
                    )

                elif ther is not None and scomm is not None and sfans is not None:
                    is_heating = ther["SystemMode"] == 4
                    fan_raw: int = sfans.get("FanMode", 5)
                    hold = scomm["HoldType"]
                    running = ther["RunningState"]

                    if is_heating:
                        target = ther["HeatingSetpoint_x100"] / 100
                        max_t = ther.get("MaxHeatSetpoint_x100", 4000) / 100
                        min_t = ther.get("MinHeatSetpoint_x100", 500) / 100
                    else:
                        target = ther["CoolingSetpoint_x100"] / 100
                        max_t = ther.get("MaxCoolSetpoint_x100", 4000) / 100
                        min_t = ther.get("MinCoolSetpoint_x100", 500) / 100

                    # Determine hvac_action
                    if hold == 7:
                        action = CURRENT_HVAC_OFF
                    elif running == 0:
                        action = CURRENT_HVAC_IDLE
                    elif is_heating and running == 33:
                        action = CURRENT_HVAC_HEAT
                    elif is_heating:
                        action = CURRENT_HVAC_HEAT_IDLE
                    elif running == 66:
                        action = CURRENT_HVAC_COOL
                    else:
                        action = CURRENT_HVAC_COOL_IDLE

                    device = ClimateDevice(
                        **common,
                        current_humidity=None,
                        current_temperature=ther["LocalTemperature_x100"]
                        / 100,
                        target_temperature=target,
                        max_temp=max_t,
                        min_temp=min_t,
                        hvac_mode=(
                            HVAC_MODE_HEAT
                            if ther["SystemMode"] == 4
                            else HVAC_MODE_COOL
                            if ther["SystemMode"] == 3
                            else HVAC_MODE_AUTO
                        ),
                        hvac_action=action,
                        hvac_modes=[
                            HVAC_MODE_HEAT,
                            HVAC_MODE_COOL,
                            HVAC_MODE_AUTO,
                        ],
                        preset_mode=(
                            PRESET_OFF
                            if hold == 7
                            else PRESET_PERMANENT_HOLD
                            if hold == 2
                            else PRESET_ECO
                            if hold == 10
                            else PRESET_TEMPORARY_HOLD
                            if hold == 1
                            else PRESET_FOLLOW_SCHEDULE
                        ),
                        preset_modes=[
                            PRESET_OFF,
                            PRESET_PERMANENT_HOLD,
                            PRESET_ECO,
                            PRESET_TEMPORARY_HOLD,
                            PRESET_FOLLOW_SCHEDULE,
                        ],
                        fan_mode=(
                            FAN_MODE_OFF
                            if fan_raw == 0
                            else FAN_MODE_HIGH
                            if fan_raw == 3
                            else FAN_MODE_MEDIUM
                            if fan_raw == 2
                            else FAN_MODE_LOW
                            if fan_raw == 1
                            else FAN_MODE_AUTO
                        ),
                        fan_modes=[
                            FAN_MODE_AUTO,
                            FAN_MODE_HIGH,
                            FAN_MODE_MEDIUM,
                            FAN_MODE_LOW,
                            FAN_MODE_OFF,
                        ],
                        locked=ds.get("sTherUIS", {}).get("LockKey", 0) == 1,
                        supported_features=(
                            SUPPORT_TARGET_TEMPERATURE
                            | SUPPORT_PRESET_MODE
                            | SUPPORT_FAN_MODE
                        ),
                    )
                else:
                    continue

                local[device.unique_id] = device

                # Extract battery level from Status_d character 99 (0-5).
                # Only models in BATTERY_OEM_MODELS (SQ610RF etc.) are
                # battery-powered and report meaningful values.
                # All other IT600 devices are mains-powered and always
                # report 0 — skip those.  A value of 0 on a battery
                # model means critical; the HA battery entity will show
                # the low-battery warning automatically.
                status_d = (th or {}).get("Status_d", "")
                is_battery_model = model in BATTERY_OEM_MODELS
                if is_battery_model and len(status_d) > 99:
                    try:
                        raw_battery = int(status_d[99])
                        if 0 <= raw_battery <= 5:
                            battery_uid = f"{unique_id}_battery"
                            battery_sensor = SensorDevice(
                                available=device.available,
                                name=f"{device.name} Battery",
                                unique_id=battery_uid,
                                state=BATTERY_LEVEL_MAP.get(raw_battery, 0),
                                unit_of_measurement="%",
                                device_class="battery",
                                data=ds["data"],
                                manufacturer=device.manufacturer,
                                model=device.model,
                                sw_version=device.sw_version,
                                parent_unique_id=unique_id,
                                entity_category="diagnostic",
                            )
                            battery_local[battery_uid] = battery_sensor
                    except (ValueError, IndexError):
                        pass

                # Parse thermostat error flags (Error01 … Error32)
                # and aggregate into one "problem" sensor + one "low battery"
                # sensor per thermostat, with active errors as attributes.
                if th is not None:
                    active_problems: list[str] = []
                    active_battery: list[str] = []
                    for error_key, description in THERMOSTAT_ERROR_CODES.items():
                        value = th.get(error_key)
                        if value == 1:
                            if error_key in BATTERY_ERROR_CODES:
                                active_battery.append(description)
                            else:
                                active_problems.append(description)

                    # Always create the aggregated problem sensor so
                    # it is visible (off = no problems).
                    problem_uid = f"{unique_id}_problem"
                    error_local[problem_uid] = BinarySensorDevice(
                        available=device.available,
                        name=f"{device.name} Problem",
                        unique_id=problem_uid,
                        is_on=len(active_problems) > 0,
                        device_class="problem",
                        data=ds["data"],
                        manufacturer=device.manufacturer,
                        model=device.model,
                        sw_version=device.sw_version,
                        parent_unique_id=unique_id,
                        entity_category="diagnostic",
                        extra_state_attributes={
                            "errors": active_problems,
                        },
                    )

                    # Aggregated battery-error sensor
                    battery_err_uid = f"{unique_id}_battery_error"
                    error_local[battery_err_uid] = BinarySensorDevice(
                        available=device.available,
                        name=f"{device.name} Battery problem",
                        unique_id=battery_err_uid,
                        is_on=len(active_battery) > 0,
                        device_class="battery",
                        data=ds["data"],
                        manufacturer=device.manufacturer,
                        model=device.model,
                        sw_version=device.sw_version,
                        parent_unique_id=unique_id,
                        entity_category="diagnostic",
                        extra_state_attributes={
                            "errors": active_battery,
                        },
                    )

                if send_callback:
                    self._climate_devices[device.unique_id] = device
                    await self._send_climate_update_callback(device.unique_id)
            except Exception:
                _LOGGER.exception("Failed to poll climate %s", unique_id)

        self._climate_devices = local
        self._battery_sensor_devices = battery_local
        self._humidity_sensor_devices = humidity_local
        self._error_binary_sensor_devices = error_local
        _LOGGER.debug("Refreshed %s climate devices", len(local))

    # ------------------------------------------------------------------
    #  Callbacks
    # ------------------------------------------------------------------

    async def _send_climate_update_callback(self, device_id: str) -> None:
        for cb in self._climate_update_callbacks:
            await cb(device_id=device_id)

    async def _send_binary_sensor_update_callback(self, device_id: str) -> None:
        for cb in self._binary_sensor_update_callbacks:
            await cb(device_id=device_id)

    async def _send_switch_update_callback(self, device_id: str) -> None:
        for cb in self._switch_update_callbacks:
            await cb(device_id=device_id)

    async def _send_cover_update_callback(self, device_id: str) -> None:
        for cb in self._cover_update_callbacks:
            await cb(device_id=device_id)

    async def _send_sensor_update_callback(self, device_id: str) -> None:
        for cb in self._sensor_update_callbacks:
            await cb(device_id=device_id)

    async def add_climate_update_callback(
        self, method: Callable[..., Awaitable[None]]
    ) -> None:
        self._climate_update_callbacks.append(method)

    async def add_binary_sensor_update_callback(
        self, method: Callable[..., Awaitable[None]]
    ) -> None:
        self._binary_sensor_update_callbacks.append(method)

    async def add_switch_update_callback(
        self, method: Callable[..., Awaitable[None]]
    ) -> None:
        self._switch_update_callbacks.append(method)

    async def add_cover_update_callback(
        self, method: Callable[..., Awaitable[None]]
    ) -> None:
        self._cover_update_callbacks.append(method)

    async def add_sensor_update_callback(
        self, method: Callable[..., Awaitable[None]]
    ) -> None:
        self._sensor_update_callbacks.append(method)

    # ------------------------------------------------------------------
    #  Getters
    # ------------------------------------------------------------------

    def get_gateway_device(self) -> GatewayDevice | None:
        return self._gateway_device

    def get_climate_devices(self) -> dict[str, ClimateDevice]:
        return self._climate_devices

    def get_climate_device(self, device_id: str) -> ClimateDevice | None:
        return self._climate_devices.get(device_id)

    def get_binary_sensor_devices(self) -> dict[str, BinarySensorDevice]:
        return {**self._binary_sensor_devices, **self._error_binary_sensor_devices}

    def get_binary_sensor_device(
        self, device_id: str
    ) -> BinarySensorDevice | None:
        return (self._binary_sensor_devices.get(device_id)
                or self._error_binary_sensor_devices.get(device_id))

    def get_switch_devices(self) -> dict[str, SwitchDevice]:
        return self._switch_devices

    def get_switch_device(self, device_id: str) -> SwitchDevice | None:
        return self._switch_devices.get(device_id)

    def get_cover_devices(self) -> dict[str, CoverDevice]:
        return self._cover_devices

    def get_cover_device(self, device_id: str) -> CoverDevice | None:
        return self._cover_devices.get(device_id)

    def get_sensor_devices(self) -> dict[str, SensorDevice]:
        return {
            **self._sensor_devices,
            **self._battery_sensor_devices,
            **self._humidity_sensor_devices,
            **self._energy_sensor_devices,
        }

    def get_sensor_device(self, device_id: str) -> SensorDevice | None:
        return (self._sensor_devices.get(device_id)
                or self._battery_sensor_devices.get(device_id)
                or self._humidity_sensor_devices.get(device_id)
                or self._energy_sensor_devices.get(device_id))

    # ------------------------------------------------------------------
    #  Commands — covers
    # ------------------------------------------------------------------

    async def set_cover_position(self, device_id: str, position: int) -> None:
        """Set cover position: 0 = closed, 100 = fully open."""
        if not 0 <= position <= 100:
            raise ValueError("position must be 0-100 inclusive")

        device = self.get_cover_device(device_id)
        if device is None:
            _LOGGER.error("Cover device not found: %s", device_id)
            return

        await self._make_encrypted_request(
            "write",
            {
                "requestAttr": "write",
                "id": [
                    {
                        "data": device.data,
                        "sLevelS": {
                            "SetMoveToLevel": f"{position:02x}FFFF"
                        },
                    }
                ],
            },
        )

    async def open_cover(self, device_id: str) -> None:
        await self.set_cover_position(device_id, 100)

    async def close_cover(self, device_id: str) -> None:
        await self.set_cover_position(device_id, 0)

    # ------------------------------------------------------------------
    #  Commands — switches
    # ------------------------------------------------------------------

    async def turn_on_switch_device(self, device_id: str) -> None:
        device = self.get_switch_device(device_id)
        if device is None:
            _LOGGER.error("Switch device not found: %s", device_id)
            return
        await self._make_encrypted_request(
            "write",
            {
                "requestAttr": "write",
                "id": [{"data": device.data, "sOnOffS": {"SetOnOff": 1}}],
            },
        )

    async def turn_off_switch_device(self, device_id: str) -> None:
        device = self.get_switch_device(device_id)
        if device is None:
            _LOGGER.error("Switch device not found: %s", device_id)
            return
        await self._make_encrypted_request(
            "write",
            {
                "requestAttr": "write",
                "id": [{"data": device.data, "sOnOffS": {"SetOnOff": 0}}],
            },
        )

    # ------------------------------------------------------------------
    #  Commands — climate
    # ------------------------------------------------------------------

    async def set_climate_device_preset(
        self, device_id: str, preset: str
    ) -> None:
        device = self.get_climate_device(device_id)
        if device is None:
            _LOGGER.error("Climate device not found: %s", device_id)
            return

        if device.model == "FC600":
            hold = (
                7
                if preset == PRESET_OFF
                else 10
                if preset == PRESET_ECO
                else 2
                if preset == PRESET_PERMANENT_HOLD
                else 1
                if preset == PRESET_TEMPORARY_HOLD
                else 0
            )
            payload = {"sComm": {"SetHoldType": hold}}
        else:
            hold = (
                7
                if preset == PRESET_OFF
                else 2
                if preset == PRESET_PERMANENT_HOLD
                else 0
            )
            payload = {"sIT600TH": {"SetHoldType": hold}}

        await self._make_encrypted_request(
            "write",
            {
                "requestAttr": "write",
                "id": [{"data": device.data, **payload}],
            },
        )

    async def set_climate_device_mode(
        self, device_id: str, mode: str
    ) -> None:
        device = self.get_climate_device(device_id)
        if device is None:
            _LOGGER.error("Climate device not found: %s", device_id)
            return

        if device.model == "FC600":
            # FC600: 4 = heat, 3 = cool, 1 = auto
            sys_mode = (
                4
                if mode == HVAC_MODE_HEAT
                else 3
                if mode == HVAC_MODE_COOL
                else 1
            )
            payload = {"sTherS": {"SetSystemMode": sys_mode}}
        else:
            # iT600: HoldType 7 = off, 0 = follow schedule (auto/heat)
            hold = 7 if mode == HVAC_MODE_OFF else 0
            payload = {"sIT600TH": {"SetHoldType": hold}}

        await self._make_encrypted_request(
            "write",
            {
                "requestAttr": "write",
                "id": [{"data": device.data, **payload}],
            },
        )

    async def set_climate_device_fan_mode(
        self, device_id: str, mode: str
    ) -> None:
        device = self.get_climate_device(device_id)
        if device is None:
            _LOGGER.error("Climate device not found: %s", device_id)
            return

        # Map fan mode string → protocol value
        fan_val = (
            5
            if mode == FAN_MODE_AUTO
            else 3
            if mode == FAN_MODE_HIGH
            else 2
            if mode == FAN_MODE_MEDIUM  # BUG FIX: was FAN_MODE_MID (undefined)
            else 1
            if mode == FAN_MODE_LOW
            else 0
        )

        await self._make_encrypted_request(
            "write",
            {
                "requestAttr": "write",
                "id": [
                    {"data": device.data, "sFanS": {"FanMode": fan_val}}
                ],
            },
        )

    async def set_climate_device_locked(
        self, device_id: str, locked: bool
    ) -> None:
        device = self.get_climate_device(device_id)
        if device is None:
            _LOGGER.error("Climate device not found: %s", device_id)
            return

        await self._make_encrypted_request(
            "write",
            {
                "requestAttr": "write",
                "id": [
                    {
                        "data": device.data,
                        "sTherUIS": {"LockKey": 1 if locked else 0},
                    }
                ],
            },
        )

    async def set_climate_device_temperature(
        self, device_id: str, setpoint_celsius: float
    ) -> None:
        device = self.get_climate_device(device_id)
        if device is None:
            _LOGGER.error("Climate device not found: %s", device_id)
            return

        value = int(self.round_to_half(setpoint_celsius) * 100)

        if device.model == "FC600":
            if device.hvac_mode == HVAC_MODE_COOL:
                payload = {"sTherS": {"SetCoolingSetpoint_x100": value}}
            else:
                payload = {"sTherS": {"SetHeatingSetpoint_x100": value}}
        else:
            payload = {"sIT600TH": {"SetHeatingSetpoint_x100": value}}

        await self._make_encrypted_request(
            "write",
            {
                "requestAttr": "write",
                "id": [{"data": device.data, **payload}],
            },
        )

    # ------------------------------------------------------------------
    #  Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def round_to_half(number: float) -> float:
        """Round to nearest 0.5 (e.g. 1.01→1.0, 1.4→1.5, 1.8→2.0)."""
        return round(number * 2) / 2

    @staticmethod
    def _device_name(device_status: dict, fallback: str) -> str:
        """Extract human-friendly device name from gateway JSON."""
        raw = device_status.get("sZDO", {}).get(
            "DeviceName", json.dumps({"deviceName": fallback})
        )
        try:
            return json.loads(raw)["deviceName"]
        except (json.JSONDecodeError, KeyError):
            return fallback

    @staticmethod
    def _voltage_to_battery_pct(
        voltage: float, model: str | None
    ) -> int | None:
        """Convert BatteryVoltage_x10 (in volts) to a percentage.

        Uses thresholds extracted from the official Salus web-app JS.
        Returns *None* when the model is unknown / has no mapping.
        """
        if model in WINDOW_VOLTAGE_MODELS:
            curve = "window"
        elif model in DOOR_VOLTAGE_MODELS:
            curve = "door"
        elif model in ENERGY_METER_VOLTAGE_MODELS:
            curve = "energy_meter"
        else:
            # Use door curve as a safe default for any battery device
            curve = "door"

        thresholds = BATTERY_VOLTAGE_THRESHOLDS.get(curve)
        if thresholds is None:
            return None

        for threshold_v, pct, _status in thresholds:
            if voltage >= threshold_v:
                return pct
        return 0

    # ------------------------------------------------------------------
    #  Encrypted HTTP transport
    # ------------------------------------------------------------------

    async def _make_encrypted_request(
        self, command: str, request_body: dict[str, Any]
    ) -> Any:
        async with self._lock:
            if self._session is None:
                self._session = aiohttp.ClientSession()
                self._close_session = True

            url = f"http://{self._host}:{self._port}/deviceid/{command}"
            body_json = json.dumps(request_body)

            if self._debug:
                _LOGGER.debug("Gateway request: POST %s\n%s", url, body_json)

            try:
                async with asyncio.timeout(self._request_timeout):
                    resp = await self._session.post(
                        url,
                        data=self._encryptor.encrypt(body_json),
                        headers={"content-type": "application/json"},
                    )
                    raw = await resp.read()
                    decrypted = self._encryptor.decrypt(raw)

                    if self._debug:
                        _LOGGER.debug("Gateway response:\n%s", decrypted)

                    result = json.loads(decrypted)

                    if result.get("status") != "success":
                        _LOGGER.error(
                            "%s failed: %s", command, repr(request_body)
                        )
                        raise IT600CommandError(
                            f"Gateway rejected '{command}': {repr(request_body)}"
                        )

                    return result

            except TimeoutError as exc:
                _LOGGER.error("Timeout connecting to gateway: %s", exc)
                raise IT600ConnectionError(
                    "Timeout communicating with iT600 gateway"
                ) from exc
            except client_exceptions.ClientConnectorError as exc:
                raise IT600ConnectionError(
                    "Cannot reach iT600 gateway — check host / IP address"
                ) from exc
            except (IT600CommandError, IT600ConnectionError,
                    IT600AuthenticationError):
                raise
            except Exception as exc:
                _LOGGER.error(
                    "Unexpected error: %s / %s", type(exc).__name__, exc
                )
                raise IT600CommandError(
                    "Unknown error communicating with iT600 gateway"
                ) from exc

    # ------------------------------------------------------------------
    #  Session lifecycle
    # ------------------------------------------------------------------

    async def close(self) -> None:
        """Close the HTTP session if we own it."""
        if self._session and self._close_session:
            await self._session.close()

    async def __aenter__(self) -> IT600Gateway:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.close()
