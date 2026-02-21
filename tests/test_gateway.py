"""Tests for the IT600Gateway class."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from custom_components.salus.const import (
    CURRENT_HVAC_COOL,
    CURRENT_HVAC_HEAT,
    CURRENT_HVAC_IDLE,
    CURRENT_HVAC_OFF,
    FAN_MODE_AUTO,
    FAN_MODE_HIGH,
    FAN_MODE_LOW,
    FAN_MODE_MEDIUM,
    FAN_MODE_OFF,
    HVAC_MODE_AUTO,
    HVAC_MODE_COOL,
    HVAC_MODE_HEAT,
    HVAC_MODE_OFF,
    PRESET_FOLLOW_SCHEDULE,
    PRESET_OFF,
    PRESET_PERMANENT_HOLD,
    SUPPORT_CLOSE,
    SUPPORT_FAN_MODE,
    SUPPORT_OPEN,
    SUPPORT_PRESET_MODE,
    SUPPORT_SET_POSITION,
    SUPPORT_TARGET_TEMPERATURE,
)
from custom_components.salus.exceptions import (
    IT600CommandError,
)
from custom_components.salus.gateway import IT600Gateway

# ---------------------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------------------


def _make_gateway(**kwargs) -> IT600Gateway:
    """Create a gateway with a fake session so no real HTTP happens."""
    gw = IT600Gateway(
        host=kwargs.get("host", "192.168.1.100"),
        euid=kwargs.get("euid", "0000000000000000"),
    )
    gw._session = MagicMock()  # prevent real aiohttp session creation
    return gw


# ---------------------------------------------------------------------------
#  Static / pure helpers
# ---------------------------------------------------------------------------


class TestRoundToHalf:
    """Test IT600Gateway.round_to_half static method."""

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (1.0, 1.0),
            (1.1, 1.0),
            (1.24, 1.0),
            (1.25, 1.0),  # banker's rounding: round(2.5) == 2
            (1.3, 1.5),
            (1.5, 1.5),
            (1.7, 1.5),
            (1.74, 1.5),
            (1.75, 2.0),
            (1.8, 2.0),
            (2.0, 2.0),
            (0.0, 0.0),
            (22.3, 22.5),
            (22.6, 22.5),
            (22.8, 23.0),
        ],
    )
    def test_round_to_half(self, value, expected):
        assert IT600Gateway.round_to_half(value) == expected


class TestVoltageToBatteryPct:
    """Test IT600Gateway._voltage_to_battery_pct static method."""

    @pytest.mark.parametrize(
        ("voltage", "model", "expected"),
        [
            # Window-curve models (thresholds 2.6 / 2.3 / 2.1)
            (3.0, "SW600", 100),   # well above 2.6 V
            (2.6, "SW600", 100),   # exactly high
            (2.5, "SW600", 50),    # between high and medium
            (2.3, "SW600", 50),    # exactly medium
            (2.2, "SW600", 25),    # between medium and low
            (2.1, "SW600", 25),    # exactly low
            (2.0, "SW600", 0),     # below low
            (0.0, "SW600", 0),     # zero voltage
            # Door-curve models (thresholds 2.9 / 2.8 / 2.2)
            (3.0, "SmokeSensor-EM", 100),
            (2.9, "SmokeSensor-EM", 100),
            (2.85, "SmokeSensor-EM", 50),
            (2.8, "SmokeSensor-EM", 50),
            (2.5, "SmokeSensor-EM", 25),
            (2.2, "SmokeSensor-EM", 25),
            (2.1, "SmokeSensor-EM", 0),
            # Unknown model falls back to door curve
            (2.9, "UNKNOWN", 100),
            (2.85, "UNKNOWN", 50),
        ],
    )
    def test_voltage_levels(self, voltage, model, expected):
        assert IT600Gateway._voltage_to_battery_pct(voltage, model) == expected


class TestDeviceName:
    """Test IT600Gateway._device_name static method."""

    def test_valid_json_name(self):
        ds = {"sZDO": {"DeviceName": '{"deviceName": "Living Room"}'}}
        assert IT600Gateway._device_name(ds, "fallback") == "Living Room"

    def test_missing_szdo_uses_fallback(self):
        assert IT600Gateway._device_name({}, "Unknown") == "Unknown"

    def test_invalid_json_uses_fallback(self):
        ds = {"sZDO": {"DeviceName": "not-json"}}
        assert IT600Gateway._device_name(ds, "Fallback") == "Fallback"

    def test_missing_key_in_json_uses_fallback(self):
        ds = {"sZDO": {"DeviceName": '{"other": "value"}'}}
        assert IT600Gateway._device_name(ds, "Default") == "Default"


# ---------------------------------------------------------------------------
#  Connection
# ---------------------------------------------------------------------------


class TestConnect:
    """Test gateway connection logic."""

    async def test_connect_returns_mac(self):
        gw = _make_gateway()
        response = {
            "status": "success",
            "id": [
                {
                    "sGateway": {"NetworkLANMAC": "AA:BB:CC:DD:EE:FF"},
                    "data": {"UniID": "gw001"},
                }
            ],
        }
        with patch.object(
            gw,
            "_make_encrypted_request",
            new_callable=AsyncMock,
            return_value=response,
        ):
            mac = await gw.connect()

        assert mac == "AA:BB:CC:DD:EE:FF"

    async def test_connect_no_gateway_raises(self):
        gw = _make_gateway()
        response = {
            "status": "success",
            "id": [{"data": {"UniID": "dev001"}}],
        }
        with patch.object(
            gw,
            "_make_encrypted_request",
            new_callable=AsyncMock,
            return_value=response,
        ):
            with pytest.raises(IT600CommandError):
                await gw.connect()


# ---------------------------------------------------------------------------
#  Refresh — gateway device
# ---------------------------------------------------------------------------


class TestRefreshGatewayDevice:
    """Test _refresh_gateway_device parsing."""

    async def test_parses_gateway_info(self):
        gw = _make_gateway()
        devices = [{"data": {"UniID": "gw001"}}]
        detail_response = {
            "status": "success",
            "id": [
                {
                    "data": {"UniID": "gw001"},
                    "sGateway": {
                        "NetworkLANMAC": "AA:BB:CC:DD:EE:FF",
                        "ModelIdentifier": "SG600",
                    },
                    "sBasicS": {"ManufactureName": "SALUS"},
                    "sOTA": {"OTAFirmwareVersion_d": "2.0"},
                }
            ],
        }
        with patch.object(
            gw,
            "_make_encrypted_request",
            new_callable=AsyncMock,
            return_value=detail_response,
        ):
            await gw._refresh_gateway_device(devices)

        dev = gw.get_gateway_device()
        assert dev is not None
        assert dev.unique_id == "AA:BB:CC:DD:EE:FF"
        assert dev.model == "SG600"
        assert dev.sw_version == "2.0"

    async def test_empty_devices_no_op(self):
        gw = _make_gateway()
        await gw._refresh_gateway_device([])
        assert gw.get_gateway_device() is None


# ---------------------------------------------------------------------------
#  Refresh — climate devices
# ---------------------------------------------------------------------------


class TestRefreshClimateDevices:
    """Test _refresh_climate_devices for both iT600TH and FC600 branches."""

    @staticmethod
    def _it600th_response(
        hold: int = 0,
        running: int = 1,
        temp: int = 2150,
        setpoint: int = 2200,
    ) -> dict:
        return {
            "status": "success",
            "id": [
                {
                    "data": {"UniID": "thermo_001", "Endpoint": 1},
                    "sIT600TH": {
                        "LocalTemperature_x100": temp,
                        "HeatingSetpoint_x100": setpoint,
                        "MaxHeatSetpoint_x100": 3500,
                        "MinHeatSetpoint_x100": 500,
                        "HoldType": hold,
                        "RunningState": running,
                    },
                    "sZDOInfo": {"OnlineStatus_i": 1},
                    "sZDO": {
                        "DeviceName": '{"deviceName": "Living Room"}',
                        "FirmwareVersion": "1.0",
                    },
                    "sBasicS": {"ManufactureName": "SALUS"},
                    "DeviceL": {"ModelIdentifier_i": "iT600"},
                }
            ],
        }

    async def test_it600th_auto_mode(self):
        gw = _make_gateway()
        devices = [{"data": {"UniID": "thermo_001"}, "sIT600TH": {}}]
        resp = self._it600th_response(hold=0, running=1)
        with patch.object(
            gw,
            "_make_encrypted_request",
            new_callable=AsyncMock,
            return_value=resp,
        ):
            await gw._refresh_climate_devices(devices)

        devs = gw.get_climate_devices()
        assert len(devs) == 1
        dev = devs["thermo_001"]
        assert dev.current_temperature == 21.5
        assert dev.target_temperature == 22.0
        assert dev.hvac_mode == HVAC_MODE_AUTO
        assert dev.hvac_action == CURRENT_HVAC_HEAT
        assert dev.preset_mode == PRESET_FOLLOW_SCHEDULE

    async def test_it600th_heat_mode(self):
        gw = _make_gateway()
        devices = [{"data": {"UniID": "thermo_001"}, "sIT600TH": {}}]
        resp = self._it600th_response(hold=2, running=0)
        with patch.object(
            gw,
            "_make_encrypted_request",
            new_callable=AsyncMock,
            return_value=resp,
        ):
            await gw._refresh_climate_devices(devices)

        dev = gw.get_climate_device("thermo_001")
        assert dev.hvac_mode == HVAC_MODE_HEAT
        assert dev.hvac_action == CURRENT_HVAC_IDLE
        assert dev.preset_mode == PRESET_PERMANENT_HOLD

    async def test_it600th_off_mode(self):
        gw = _make_gateway()
        devices = [{"data": {"UniID": "thermo_001"}, "sIT600TH": {}}]
        resp = self._it600th_response(hold=7, running=0)
        with patch.object(
            gw,
            "_make_encrypted_request",
            new_callable=AsyncMock,
            return_value=resp,
        ):
            await gw._refresh_climate_devices(devices)

        dev = gw.get_climate_device("thermo_001")
        assert dev.hvac_mode == HVAC_MODE_OFF
        assert dev.hvac_action == CURRENT_HVAC_OFF
        assert dev.preset_mode == PRESET_OFF

    async def test_fc600_heating(self):
        gw = _make_gateway()
        devices = [{"data": {"UniID": "fc_001"}, "sTherS": {}}]
        resp = {
            "status": "success",
            "id": [
                {
                    "data": {"UniID": "fc_001", "Endpoint": 1},
                    "sTherS": {
                        "LocalTemperature_x100": 2300,
                        "HeatingSetpoint_x100": 2500,
                        "CoolingSetpoint_x100": 2600,
                        "MaxHeatSetpoint_x100": 4000,
                        "MinHeatSetpoint_x100": 500,
                        "MaxCoolSetpoint_x100": 4000,
                        "MinCoolSetpoint_x100": 500,
                        "SystemMode": 4,
                        "RunningState": 33,
                    },
                    "sComm": {"HoldType": 2},
                    "sFanS": {"FanMode": 3},
                    "sZDOInfo": {"OnlineStatus_i": 1},
                    "sZDO": {
                        "DeviceName": '{"deviceName": "FC Unit"}',
                        "FirmwareVersion": "2.0",
                    },
                    "sBasicS": {"ManufactureName": "SALUS"},
                    "DeviceL": {"ModelIdentifier_i": "FC600"},
                }
            ],
        }
        with patch.object(
            gw,
            "_make_encrypted_request",
            new_callable=AsyncMock,
            return_value=resp,
        ):
            await gw._refresh_climate_devices(devices)

        dev = gw.get_climate_device("fc_001")
        assert dev is not None
        assert dev.hvac_mode == HVAC_MODE_HEAT
        assert dev.hvac_action == CURRENT_HVAC_HEAT
        assert dev.target_temperature == 25.0
        assert dev.fan_mode == FAN_MODE_HIGH
        assert dev.preset_mode == PRESET_PERMANENT_HOLD
        assert dev.supported_features & SUPPORT_FAN_MODE

    async def test_fc600_cooling(self):
        gw = _make_gateway()
        devices = [{"data": {"UniID": "fc_002"}, "sTherS": {}}]
        resp = {
            "status": "success",
            "id": [
                {
                    "data": {"UniID": "fc_002", "Endpoint": 1},
                    "sTherS": {
                        "LocalTemperature_x100": 2800,
                        "HeatingSetpoint_x100": 2500,
                        "CoolingSetpoint_x100": 2400,
                        "MaxHeatSetpoint_x100": 4000,
                        "MinHeatSetpoint_x100": 500,
                        "MaxCoolSetpoint_x100": 4000,
                        "MinCoolSetpoint_x100": 500,
                        "SystemMode": 3,
                        "RunningState": 66,
                    },
                    "sComm": {"HoldType": 0},
                    "sFanS": {"FanMode": 5},
                    "sZDOInfo": {"OnlineStatus_i": 1},
                    "sZDO": {
                        "DeviceName": '{"deviceName": "FC Cool"}',
                        "FirmwareVersion": "2.1",
                    },
                    "sBasicS": {"ManufactureName": "SALUS"},
                    "DeviceL": {"ModelIdentifier_i": "FC600"},
                }
            ],
        }
        with patch.object(
            gw,
            "_make_encrypted_request",
            new_callable=AsyncMock,
            return_value=resp,
        ):
            await gw._refresh_climate_devices(devices)

        dev = gw.get_climate_device("fc_002")
        assert dev.hvac_mode == HVAC_MODE_COOL
        assert dev.hvac_action == CURRENT_HVAC_COOL
        assert dev.target_temperature == 24.0
        assert dev.fan_mode == FAN_MODE_AUTO
        assert dev.preset_mode == PRESET_FOLLOW_SCHEDULE

    async def test_battery_extracted_from_status_d(self):
        """Battery level is character 99 in Status_d (0-5 → 0-100%)."""
        gw = _make_gateway()
        devices = [{"data": {"UniID": "thermo_bat"}, "sIT600TH": {}}]
        # Build a Status_d string with character at index 99 = '4' → 80%
        status_d = "0" * 99 + "4" + "0" * 10
        resp = {
            "status": "success",
            "id": [
                {
                    "data": {"UniID": "thermo_bat", "Endpoint": 1},
                    "sIT600TH": {
                        "LocalTemperature_x100": 2150,
                        "HeatingSetpoint_x100": 2200,
                        "MaxHeatSetpoint_x100": 3500,
                        "MinHeatSetpoint_x100": 500,
                        "HoldType": 0,
                        "RunningState": 1,
                        "Status_d": status_d,
                    },
                    "sZDOInfo": {"OnlineStatus_i": 1},
                    "sZDO": {
                        "DeviceName": '{"deviceName": "Battery TH"}',
                        "FirmwareVersion": "1.0",
                    },
                    "sBasicS": {"ManufactureName": "SALUS"},
                    "DeviceL": {"ModelIdentifier_i": "SQ610RF"},
                }
            ],
        }
        with patch.object(
            gw,
            "_make_encrypted_request",
            new_callable=AsyncMock,
            return_value=resp,
        ):
            await gw._refresh_climate_devices(devices)

        sensors = gw.get_sensor_devices()
        assert "thermo_bat_battery" in sensors
        bat = sensors["thermo_bat_battery"]
        assert bat.state == 80
        assert bat.device_class == "battery"
        assert bat.unit_of_measurement == "%"
        assert bat.name == "Battery TH Battery"
        assert bat.parent_unique_id == "thermo_bat"

    async def test_battery_not_created_when_status_d_too_short(self):
        gw = _make_gateway()
        devices = [{"data": {"UniID": "thermo_short"}, "sIT600TH": {}}]
        resp = {
            "status": "success",
            "id": [
                {
                    "data": {"UniID": "thermo_short", "Endpoint": 1},
                    "sIT600TH": {
                        "LocalTemperature_x100": 2150,
                        "HeatingSetpoint_x100": 2200,
                        "MaxHeatSetpoint_x100": 3500,
                        "MinHeatSetpoint_x100": 500,
                        "HoldType": 0,
                        "RunningState": 1,
                        "Status_d": "0" * 50,
                    },
                    "sZDOInfo": {"OnlineStatus_i": 1},
                    "sZDO": {
                        "DeviceName": '{"deviceName": "Short Status"}',
                        "FirmwareVersion": "1.0",
                    },
                    "sBasicS": {"ManufactureName": "SALUS"},
                    "DeviceL": {"ModelIdentifier_i": "iT600"},
                }
            ],
        }
        with patch.object(
            gw,
            "_make_encrypted_request",
            new_callable=AsyncMock,
            return_value=resp,
        ):
            await gw._refresh_climate_devices(devices)

        sensors = gw.get_sensor_devices()
        assert "thermo_short_battery" not in sensors

    async def test_battery_not_created_when_no_status_d(self):
        """No Status_d at all → no battery sensor."""
        gw = _make_gateway()
        devices = [{"data": {"UniID": "thermo_001"}, "sIT600TH": {}}]
        resp = self._it600th_response(hold=0, running=1)
        with patch.object(
            gw,
            "_make_encrypted_request",
            new_callable=AsyncMock,
            return_value=resp,
        ):
            await gw._refresh_climate_devices(devices)

        sensors = gw.get_sensor_devices()
        assert not any(k.endswith("_battery") for k in sensors)

    @pytest.mark.parametrize(
        ("raw_char", "expected_pct"),
        [("0", 0), ("1", 20), ("2", 40), ("3", 60), ("4", 80), ("5", 100)],
    )
    async def test_battery_level_mapping(self, raw_char, expected_pct):
        gw = _make_gateway()
        devices = [{"data": {"UniID": "thermo_lvl"}, "sIT600TH": {}}]
        status_d = "0" * 99 + raw_char + "0" * 10
        resp = {
            "status": "success",
            "id": [
                {
                    "data": {"UniID": "thermo_lvl", "Endpoint": 1},
                    "sIT600TH": {
                        "LocalTemperature_x100": 2000,
                        "HeatingSetpoint_x100": 2200,
                        "MaxHeatSetpoint_x100": 3500,
                        "MinHeatSetpoint_x100": 500,
                        "HoldType": 0,
                        "RunningState": 0,
                        "Status_d": status_d,
                    },
                    "sZDOInfo": {"OnlineStatus_i": 1},
                    "sZDO": {
                        "DeviceName": '{"deviceName": "Level Test"}',
                        "FirmwareVersion": "1.0",
                    },
                    "sBasicS": {"ManufactureName": "SALUS"},
                    "DeviceL": {"ModelIdentifier_i": "SQ610RF"},
                }
            ],
        }
        with patch.object(
            gw,
            "_make_encrypted_request",
            new_callable=AsyncMock,
            return_value=resp,
        ):
            await gw._refresh_climate_devices(devices)

        bat = gw.get_sensor_devices()["thermo_lvl_battery"]
        assert bat.state == expected_pct

    async def test_battery_not_created_when_raw_value_zero(self):
        """Non-battery model (iT600) always reports 0 in Status_d —
        no battery sensor should be created."""
        gw = _make_gateway()
        devices = [{"data": {"UniID": "thermo_nob"}, "sIT600TH": {}}]
        status_d = "0" * 110  # char 99 is '0'
        resp = {
            "status": "success",
            "id": [
                {
                    "data": {"UniID": "thermo_nob", "Endpoint": 1},
                    "sIT600TH": {
                        "LocalTemperature_x100": 2000,
                        "HeatingSetpoint_x100": 2200,
                        "MaxHeatSetpoint_x100": 3500,
                        "MinHeatSetpoint_x100": 500,
                        "HoldType": 0,
                        "RunningState": 0,
                        "Status_d": status_d,
                    },
                    "sZDOInfo": {"OnlineStatus_i": 1},
                    "sZDO": {
                        "DeviceName": '{"deviceName": "No Battery"}',
                        "FirmwareVersion": "1.0",
                    },
                    "sBasicS": {"ManufactureName": "SALUS"},
                    "DeviceL": {"ModelIdentifier_i": "iT600"},
                }
            ],
        }
        with patch.object(
            gw,
            "_make_encrypted_request",
            new_callable=AsyncMock,
            return_value=resp,
        ):
            await gw._refresh_climate_devices(devices)

        sensors = gw.get_sensor_devices()
        assert "thermo_nob_battery" not in sensors

    async def test_battery_created_for_sq610rf_at_zero(self):
        """SQ610RF at 0 means critical battery — sensor IS created."""
        gw = _make_gateway()
        devices = [{"data": {"UniID": "thermo_sq"}, "sIT600TH": {}}]
        status_d = "0" * 110  # char 99 is '0'
        resp = {
            "status": "success",
            "id": [
                {
                    "data": {"UniID": "thermo_sq", "Endpoint": 1},
                    "sIT600TH": {
                        "LocalTemperature_x100": 2000,
                        "HeatingSetpoint_x100": 2200,
                        "MaxHeatSetpoint_x100": 3500,
                        "MinHeatSetpoint_x100": 500,
                        "HoldType": 0,
                        "RunningState": 0,
                        "Status_d": status_d,
                    },
                    "sZDOInfo": {"OnlineStatus_i": 1},
                    "sZDO": {
                        "DeviceName": '{"deviceName": "SQ Battery"}',
                        "FirmwareVersion": "1.0",
                    },
                    "sBasicS": {"ManufactureName": "SALUS"},
                    "DeviceL": {"ModelIdentifier_i": "SQ610RF"},
                }
            ],
        }
        with patch.object(
            gw,
            "_make_encrypted_request",
            new_callable=AsyncMock,
            return_value=resp,
        ):
            await gw._refresh_climate_devices(devices)

        sensors = gw.get_sensor_devices()
        assert "thermo_sq_battery" in sensors
        assert sensors["thermo_sq_battery"].state == 0

    async def test_empty_list_clears_devices(self):
        gw = _make_gateway()
        await gw._refresh_climate_devices([])
        assert gw.get_climate_devices() == {}

    async def test_empty_list_clears_error_sensors(self):
        gw = _make_gateway()
        await gw._refresh_climate_devices([])
        assert gw.get_binary_sensor_devices() == {}


# ---------------------------------------------------------------------------
#  Refresh — thermostat error sensors
# ---------------------------------------------------------------------------


class TestRefreshClimateErrorSensors:
    """Test sIT600TH Error* fields are parsed into binary sensors."""

    @staticmethod
    def _error_response(**errors) -> dict:
        th = {
            "LocalTemperature_x100": 2100,
            "HeatingSetpoint_x100": 2200,
            "MaxHeatSetpoint_x100": 3500,
            "MinHeatSetpoint_x100": 500,
            "HoldType": 0,
            "RunningState": 0,
        }
        th.update(errors)
        return {
            "status": "success",
            "id": [
                {
                    "data": {"UniID": "err_th", "Endpoint": 1},
                    "sIT600TH": th,
                    "sZDOInfo": {"OnlineStatus_i": 1},
                    "sZDO": {
                        "DeviceName": '{"deviceName": "Error TH"}',
                        "FirmwareVersion": "1.0",
                    },
                    "sBasicS": {"ManufactureName": "SALUS"},
                    "DeviceL": {"ModelIdentifier_i": "iT600"},
                }
            ],
        }

    async def test_error32_creates_battery_binary_sensor(self):
        gw = _make_gateway()
        devices = [{"data": {"UniID": "err_th"}, "sIT600TH": {}}]
        resp = self._error_response(Error32=1)
        with patch.object(
            gw,
            "_make_encrypted_request",
            new_callable=AsyncMock,
            return_value=resp,
        ):
            await gw._refresh_climate_devices(devices)

        bs = gw.get_binary_sensor_devices()
        assert "err_th_error32" in bs
        dev = bs["err_th_error32"]
        assert dev.is_on is True
        assert dev.device_class == "battery"
        assert dev.parent_unique_id == "err_th"
        assert "Low battery" in dev.name

    async def test_error22_creates_battery_binary_sensor(self):
        gw = _make_gateway()
        devices = [{"data": {"UniID": "err_th"}, "sIT600TH": {}}]
        resp = self._error_response(Error22=1)
        with patch.object(
            gw,
            "_make_encrypted_request",
            new_callable=AsyncMock,
            return_value=resp,
        ):
            await gw._refresh_climate_devices(devices)

        bs = gw.get_binary_sensor_devices()
        assert "err_th_error22" in bs
        dev = bs["err_th_error22"]
        assert dev.is_on is True
        assert dev.device_class == "battery"

    async def test_error01_creates_problem_binary_sensor(self):
        gw = _make_gateway()
        devices = [{"data": {"UniID": "err_th"}, "sIT600TH": {}}]
        resp = self._error_response(Error01=1)
        with patch.object(
            gw,
            "_make_encrypted_request",
            new_callable=AsyncMock,
            return_value=resp,
        ):
            await gw._refresh_climate_devices(devices)

        bs = gw.get_binary_sensor_devices()
        assert "err_th_error01" in bs
        dev = bs["err_th_error01"]
        assert dev.is_on is True
        assert dev.device_class == "problem"

    async def test_error_value_zero_means_not_active(self):
        gw = _make_gateway()
        devices = [{"data": {"UniID": "err_th"}, "sIT600TH": {}}]
        resp = self._error_response(Error05=0)
        with patch.object(
            gw,
            "_make_encrypted_request",
            new_callable=AsyncMock,
            return_value=resp,
        ):
            await gw._refresh_climate_devices(devices)

        bs = gw.get_binary_sensor_devices()
        assert "err_th_error05" in bs
        assert bs["err_th_error05"].is_on is False

    async def test_unknown_error_keys_are_ignored(self):
        """Keys not in THERMOSTAT_ERROR_CODES are silently skipped."""
        gw = _make_gateway()
        devices = [{"data": {"UniID": "err_th"}, "sIT600TH": {}}]
        resp = self._error_response(Error99=1)
        with patch.object(
            gw,
            "_make_encrypted_request",
            new_callable=AsyncMock,
            return_value=resp,
        ):
            await gw._refresh_climate_devices(devices)

        bs = gw.get_binary_sensor_devices()
        assert "err_th_error99" not in bs

    async def test_multiple_errors_parsed(self):
        gw = _make_gateway()
        devices = [{"data": {"UniID": "err_th"}, "sIT600TH": {}}]
        resp = self._error_response(Error01=1, Error07=0, Error32=1)
        with patch.object(
            gw,
            "_make_encrypted_request",
            new_callable=AsyncMock,
            return_value=resp,
        ):
            await gw._refresh_climate_devices(devices)

        bs = gw.get_binary_sensor_devices()
        assert bs["err_th_error01"].is_on is True
        assert bs["err_th_error07"].is_on is False
        assert bs["err_th_error32"].is_on is True


class TestRefreshSensorDevices:
    """Test _refresh_sensor_devices parsing."""

    async def test_parses_temperature_sensor(self):
        gw = _make_gateway()
        devices = [{"data": {"UniID": "sens_001"}, "sTempS": {}}]
        resp = {
            "status": "success",
            "id": [
                {
                    "data": {"UniID": "sens_001", "Endpoint": 1},
                    "sTempS": {"MeasuredValue_x100": 2340},
                    "sZDOInfo": {"OnlineStatus_i": 1},
                    "sZDO": {
                        "DeviceName": '{"deviceName": "Office"}',
                        "FirmwareVersion": "1.0",
                    },
                    "sBasicS": {"ManufactureName": "SALUS"},
                    "DeviceL": {"ModelIdentifier_i": "TS600"},
                }
            ],
        }
        with patch.object(
            gw,
            "_make_encrypted_request",
            new_callable=AsyncMock,
            return_value=resp,
        ):
            await gw._refresh_sensor_devices(devices)

        devs = gw.get_sensor_devices()
        assert "sens_001_temp" in devs
        dev = devs["sens_001_temp"]
        assert dev.state == 23.4
        assert dev.device_class == "temperature"
        assert dev.name == "Office"

    async def test_empty_list_clears_devices(self):
        gw = _make_gateway()
        await gw._refresh_sensor_devices([])
        assert gw.get_sensor_devices() == {}

    async def test_battery_voltage_creates_battery_sensor(self):
        """BatteryVoltage_x10 from sPowerS creates a battery%  sensor."""
        gw = _make_gateway()
        devices = [{"data": {"UniID": "sens_v"}, "sTempS": {}}]
        resp = {
            "status": "success",
            "id": [
                {
                    "data": {"UniID": "sens_v", "Endpoint": 1},
                    "sTempS": {"MeasuredValue_x100": 2100},
                    "sPowerS": {"BatteryVoltage_x10": 29},
                    "sZDOInfo": {"OnlineStatus_i": 1},
                    "sZDO": {
                        "DeviceName": '{"deviceName": "Volt Sensor"}',
                        "FirmwareVersion": "1.0",
                    },
                    "sBasicS": {"ManufactureName": "SALUS"},
                    "DeviceL": {"ModelIdentifier_i": "TS600"},
                }
            ],
        }
        with patch.object(
            gw,
            "_make_encrypted_request",
            new_callable=AsyncMock,
            return_value=resp,
        ):
            await gw._refresh_sensor_devices(devices)

        devs = gw.get_sensor_devices()
        assert "sens_v_battery" in devs
        bat = devs["sens_v_battery"]
        assert bat.device_class == "battery"
        assert bat.state == 100  # 2.9V → 100% on door curve
        assert bat.parent_unique_id == "sens_v"


# ---------------------------------------------------------------------------
#  Refresh — binary sensors
# ---------------------------------------------------------------------------


class TestRefreshBinarySensorDevices:
    """Test _refresh_binary_sensor_devices parsing."""

    @pytest.mark.parametrize(
        ("model", "expected_class"),
        [
            ("SW600", "window"),
            ("OS600", "window"),
            ("WLS600", "moisture"),
            ("SmokeSensor-EM", "smoke"),
            ("it600MINITRV", "heat"),
            ("it600Receiver", "running"),
            ("UnknownModel", None),
        ],
    )
    async def test_device_class_mapping(self, model, expected_class):
        gw = _make_gateway()

        # Build appropriate response based on model
        if model in ("it600MINITRV", "it600Receiver"):
            sensor_key = "sIT600I"
            sensor_data = {"RelayStatus": 1}
            # These models need sBasicS.ModelIdentifier for initial filtering
            devices = [
                {
                    "data": {"UniID": f"bs_{model}"},
                    "sBasicS": {"ModelIdentifier": model},
                }
            ]
        else:
            sensor_key = "sIASZS"
            sensor_data = {"ErrorIASZSAlarmed1": 0}
            devices = [
                {
                    "data": {"UniID": f"bs_{model}"},
                    "sIASZS": {},
                }
            ]

        resp = {
            "status": "success",
            "id": [
                {
                    "data": {"UniID": f"bs_{model}", "Endpoint": 1},
                    sensor_key: sensor_data,
                    "sZDOInfo": {"OnlineStatus_i": 1},
                    "sZDO": {
                        "DeviceName": f'{{"deviceName": "{model} Sensor"}}',
                        "FirmwareVersion": "1.0",
                    },
                    "sBasicS": {"ManufactureName": "SALUS"},
                    "DeviceL": {"ModelIdentifier_i": model},
                }
            ],
        }

        with patch.object(
            gw,
            "_make_encrypted_request",
            new_callable=AsyncMock,
            return_value=resp,
        ):
            await gw._refresh_binary_sensor_devices(devices)

        dev = gw.get_binary_sensor_device(f"bs_{model}")
        assert dev is not None
        assert dev.device_class == expected_class

    async def test_button_device_skipped(self):
        """SB600 button devices should be filtered out."""
        gw = _make_gateway()
        devices = [{"data": {"UniID": "btn_001"}, "sIASZS": {}}]
        resp = {
            "status": "success",
            "id": [
                {
                    "data": {"UniID": "btn_001", "Endpoint": 1},
                    "sIASZS": {"ErrorIASZSAlarmed1": 0},
                    "sZDOInfo": {"OnlineStatus_i": 1},
                    "sZDO": {"DeviceName": '{"deviceName": "Button"}'},
                    "sBasicS": {"ManufactureName": "SALUS"},
                    "DeviceL": {"ModelIdentifier_i": "SB600"},
                }
            ],
        }
        with patch.object(
            gw,
            "_make_encrypted_request",
            new_callable=AsyncMock,
            return_value=resp,
        ):
            await gw._refresh_binary_sensor_devices(devices)

        assert gw.get_binary_sensor_devices() == {}

    async def test_low_battery_iaszs_creates_binary_sensor(self):
        """ErrorIASZSLowBattery creates a battery binary sensor."""
        gw = _make_gateway()
        devices = [{"data": {"UniID": "bs_lb"}, "sIASZS": {}}]
        resp = {
            "status": "success",
            "id": [
                {
                    "data": {"UniID": "bs_lb", "Endpoint": 1},
                    "sIASZS": {
                        "ErrorIASZSAlarmed1": 0,
                        "ErrorIASZSLowBattery": 1,
                    },
                    "sZDOInfo": {"OnlineStatus_i": 1},
                    "sZDO": {
                        "DeviceName": '{"deviceName": "Door"}',
                        "FirmwareVersion": "1.0",
                    },
                    "sBasicS": {"ManufactureName": "SALUS"},
                    "DeviceL": {"ModelIdentifier_i": "SW600"},
                }
            ],
        }
        with patch.object(
            gw,
            "_make_encrypted_request",
            new_callable=AsyncMock,
            return_value=resp,
        ):
            await gw._refresh_binary_sensor_devices(devices)

        bs = gw.get_binary_sensor_devices()
        assert "bs_lb_low_battery" in bs
        dev = bs["bs_lb_low_battery"]
        assert dev.is_on is True
        assert dev.device_class == "battery"
        assert dev.parent_unique_id == "bs_lb"

    async def test_low_battery_powers_creates_binary_sensor(self):
        """ErrorPowerSLowBattery creates a battery binary sensor."""
        gw = _make_gateway()
        devices = [{"data": {"UniID": "bs_plb"}, "sIASZS": {}}]
        resp = {
            "status": "success",
            "id": [
                {
                    "data": {"UniID": "bs_plb", "Endpoint": 1},
                    "sIASZS": {"ErrorIASZSAlarmed1": 0},
                    "sPowerS": {"ErrorPowerSLowBattery": 0},
                    "sZDOInfo": {"OnlineStatus_i": 1},
                    "sZDO": {
                        "DeviceName": '{"deviceName": "Window"}',
                        "FirmwareVersion": "1.0",
                    },
                    "sBasicS": {"ManufactureName": "SALUS"},
                    "DeviceL": {"ModelIdentifier_i": "SW600"},
                }
            ],
        }
        with patch.object(
            gw,
            "_make_encrypted_request",
            new_callable=AsyncMock,
            return_value=resp,
        ):
            await gw._refresh_binary_sensor_devices(devices)

        bs = gw.get_binary_sensor_devices()
        assert "bs_plb_low_battery" in bs
        assert bs["bs_plb_low_battery"].is_on is False


# ---------------------------------------------------------------------------
#  Refresh — switches
# ---------------------------------------------------------------------------


class TestRefreshSwitchDevices:
    """Test _refresh_switch_devices parsing."""

    async def test_parses_switch(self):
        gw = _make_gateway()
        devices = [{"data": {"UniID": "sw_001"}, "sOnOffS": {}}]
        resp = {
            "status": "success",
            "id": [
                {
                    "data": {"UniID": "sw_001", "Endpoint": 1},
                    "sOnOffS": {"OnOff": 1},
                    "sZDOInfo": {"OnlineStatus_i": 1},
                    "sZDO": {
                        "DeviceName": '{"deviceName": "My Plug"}',
                        "FirmwareVersion": "1.0",
                    },
                    "sBasicS": {"ManufactureName": "SALUS"},
                    "DeviceL": {"ModelIdentifier_i": "SP600"},
                }
            ],
        }
        with patch.object(
            gw,
            "_make_encrypted_request",
            new_callable=AsyncMock,
            return_value=resp,
        ):
            await gw._refresh_switch_devices(devices)

        devs = gw.get_switch_devices()
        assert len(devs) == 1
        dev = list(devs.values())[0]
        assert dev.is_on is True
        assert dev.device_class == "outlet"
        assert dev.name == "My Plug"

    async def test_non_outlet_device_class(self):
        gw = _make_gateway()
        devices = [{"data": {"UniID": "sw_002"}, "sOnOffS": {}}]
        resp = {
            "status": "success",
            "id": [
                {
                    "data": {"UniID": "sw_002", "Endpoint": 1},
                    "sOnOffS": {"OnOff": 0},
                    "sZDOInfo": {"OnlineStatus_i": 1},
                    "sZDO": {"DeviceName": '{"deviceName": "Relay"}'},
                    "sBasicS": {"ManufactureName": "SALUS"},
                    "DeviceL": {"ModelIdentifier_i": "SR600"},
                }
            ],
        }
        with patch.object(
            gw,
            "_make_encrypted_request",
            new_callable=AsyncMock,
            return_value=resp,
        ):
            await gw._refresh_switch_devices(devices)

        dev = list(gw.get_switch_devices().values())[0]
        assert dev.device_class == "switch"
        assert dev.is_on is False

    async def test_roller_shutter_endpoint_skipped(self):
        """Endpoints with sLevelS should be skipped as they are covers."""
        gw = _make_gateway()
        devices = [{"data": {"UniID": "combo_001"}, "sOnOffS": {}}]
        resp = {
            "status": "success",
            "id": [
                {
                    "data": {"UniID": "combo_001", "Endpoint": 1},
                    "sOnOffS": {"OnOff": 1},
                    "sLevelS": {"CurrentLevel": 50},
                    "sZDOInfo": {"OnlineStatus_i": 1},
                    "sZDO": {"DeviceName": '{"deviceName": "Combo"}'},
                    "sBasicS": {"ManufactureName": "SALUS"},
                    "DeviceL": {"ModelIdentifier_i": "RS600"},
                }
            ],
        }
        with patch.object(
            gw,
            "_make_encrypted_request",
            new_callable=AsyncMock,
            return_value=resp,
        ):
            await gw._refresh_switch_devices(devices)

        assert gw.get_switch_devices() == {}


# ---------------------------------------------------------------------------
#  Refresh — covers
# ---------------------------------------------------------------------------


class TestRefreshCoverDevices:
    """Test _refresh_cover_devices parsing."""

    async def test_parses_cover(self):
        gw = _make_gateway()
        devices = [{"data": {"UniID": "cov_001"}, "sLevelS": {}}]
        resp = {
            "status": "success",
            "id": [
                {
                    "data": {"UniID": "cov_001", "Endpoint": 1},
                    "sLevelS": {
                        "CurrentLevel": 75,
                        "MoveToLevel_f": "50FFFF",
                    },
                    "sButtonS": {"Mode": 1},
                    "sZDOInfo": {"OnlineStatus_i": 1},
                    "sZDO": {
                        "DeviceName": '{"deviceName": "Blinds"}',
                        "FirmwareVersion": "1.0",
                    },
                    "sBasicS": {"ManufactureName": "SALUS"},
                    "DeviceL": {"ModelIdentifier_i": "RS600"},
                }
            ],
        }
        with patch.object(
            gw,
            "_make_encrypted_request",
            new_callable=AsyncMock,
            return_value=resp,
        ):
            await gw._refresh_cover_devices(devices)

        devs = gw.get_cover_devices()
        assert len(devs) == 1
        dev = devs["cov_001"]
        assert dev.current_cover_position == 75
        assert dev.is_closed is False
        # "50" hex = 80 decimal; current 75 < 80 → opening toward target
        assert dev.is_opening is True
        assert dev.is_closing is False
        assert dev.supported_features == (
            SUPPORT_OPEN | SUPPORT_CLOSE | SUPPORT_SET_POSITION
        )

    async def test_closed_cover(self):
        gw = _make_gateway()
        devices = [{"data": {"UniID": "cov_002"}, "sLevelS": {}}]
        resp = {
            "status": "success",
            "id": [
                {
                    "data": {"UniID": "cov_002", "Endpoint": 1},
                    "sLevelS": {"CurrentLevel": 0},
                    "sButtonS": {"Mode": 1},
                    "sZDOInfo": {"OnlineStatus_i": 1},
                    "sZDO": {"DeviceName": '{"deviceName": "Closed"}'},
                    "sBasicS": {"ManufactureName": "SALUS"},
                    "DeviceL": {"ModelIdentifier_i": "RS600"},
                }
            ],
        }
        with patch.object(
            gw,
            "_make_encrypted_request",
            new_callable=AsyncMock,
            return_value=resp,
        ):
            await gw._refresh_cover_devices(devices)

        dev = gw.get_cover_device("cov_002")
        assert dev.is_closed is True

    async def test_disabled_endpoint_skipped(self):
        gw = _make_gateway()
        devices = [{"data": {"UniID": "cov_003"}, "sLevelS": {}}]
        resp = {
            "status": "success",
            "id": [
                {
                    "data": {"UniID": "cov_003", "Endpoint": 1},
                    "sLevelS": {"CurrentLevel": 50},
                    "sButtonS": {"Mode": 0},  # disabled
                    "sZDOInfo": {"OnlineStatus_i": 1},
                    "sZDO": {"DeviceName": '{"deviceName": "Disabled"}'},
                    "sBasicS": {"ManufactureName": "SALUS"},
                    "DeviceL": {"ModelIdentifier_i": "RS600"},
                }
            ],
        }
        with patch.object(
            gw,
            "_make_encrypted_request",
            new_callable=AsyncMock,
            return_value=resp,
        ):
            await gw._refresh_cover_devices(devices)

        assert gw.get_cover_devices() == {}


# ---------------------------------------------------------------------------
#  Commands
# ---------------------------------------------------------------------------


class TestCommands:
    """Test gateway command methods."""

    async def test_set_cover_position(self, cover_device):
        gw = _make_gateway()
        gw._cover_devices = {cover_device.unique_id: cover_device}

        with patch.object(
            gw, "_make_encrypted_request", new_callable=AsyncMock
        ) as mock_req:
            await gw.set_cover_position(cover_device.unique_id, 50)

        mock_req.assert_awaited_once()
        call_body = mock_req.call_args[0][1]
        assert call_body["id"][0]["sLevelS"]["SetMoveToLevel"] == "32FFFF"

    async def test_set_cover_position_out_of_range(self):
        gw = _make_gateway()
        with pytest.raises(ValueError, match="0-100"):
            await gw.set_cover_position("any", 150)

    async def test_open_cover(self, cover_device):
        gw = _make_gateway()
        gw._cover_devices = {cover_device.unique_id: cover_device}

        with patch.object(
            gw, "_make_encrypted_request", new_callable=AsyncMock
        ) as mock_req:
            await gw.open_cover(cover_device.unique_id)

        call_body = mock_req.call_args[0][1]
        assert call_body["id"][0]["sLevelS"]["SetMoveToLevel"] == "64FFFF"

    async def test_close_cover(self, cover_device):
        gw = _make_gateway()
        gw._cover_devices = {cover_device.unique_id: cover_device}

        with patch.object(
            gw, "_make_encrypted_request", new_callable=AsyncMock
        ) as mock_req:
            await gw.close_cover(cover_device.unique_id)

        call_body = mock_req.call_args[0][1]
        assert call_body["id"][0]["sLevelS"]["SetMoveToLevel"] == "00FFFF"

    async def test_turn_on_switch(self, switch_device):
        gw = _make_gateway()
        gw._switch_devices = {switch_device.unique_id: switch_device}

        with patch.object(
            gw, "_make_encrypted_request", new_callable=AsyncMock
        ) as mock_req:
            await gw.turn_on_switch_device(switch_device.unique_id)

        call_body = mock_req.call_args[0][1]
        assert call_body["id"][0]["sOnOffS"]["SetOnOff"] == 1

    async def test_turn_off_switch(self, switch_device):
        gw = _make_gateway()
        gw._switch_devices = {switch_device.unique_id: switch_device}

        with patch.object(
            gw, "_make_encrypted_request", new_callable=AsyncMock
        ) as mock_req:
            await gw.turn_off_switch_device(switch_device.unique_id)

        call_body = mock_req.call_args[0][1]
        assert call_body["id"][0]["sOnOffS"]["SetOnOff"] == 0

    async def test_set_climate_temperature_it600(self, climate_device):
        gw = _make_gateway()
        gw._climate_devices = {climate_device.unique_id: climate_device}

        with patch.object(
            gw, "_make_encrypted_request", new_callable=AsyncMock
        ) as mock_req:
            await gw.set_climate_device_temperature(
                climate_device.unique_id, 23.5
            )

        call_body = mock_req.call_args[0][1]
        assert (
            call_body["id"][0]["sIT600TH"]["SetHeatingSetpoint_x100"] == 2350
        )

    async def test_set_climate_preset_off(self, climate_device):
        gw = _make_gateway()
        gw._climate_devices = {climate_device.unique_id: climate_device}

        with patch.object(
            gw, "_make_encrypted_request", new_callable=AsyncMock
        ) as mock_req:
            await gw.set_climate_device_preset(
                climate_device.unique_id, PRESET_OFF
            )

        call_body = mock_req.call_args[0][1]
        assert call_body["id"][0]["sIT600TH"]["SetHoldType"] == 7

    async def test_set_climate_preset_permanent_hold(self, climate_device):
        gw = _make_gateway()
        gw._climate_devices = {climate_device.unique_id: climate_device}

        with patch.object(
            gw, "_make_encrypted_request", new_callable=AsyncMock
        ) as mock_req:
            await gw.set_climate_device_preset(
                climate_device.unique_id, PRESET_PERMANENT_HOLD
            )

        call_body = mock_req.call_args[0][1]
        assert call_body["id"][0]["sIT600TH"]["SetHoldType"] == 2

    async def test_set_climate_mode_off(self, climate_device):
        gw = _make_gateway()
        gw._climate_devices = {climate_device.unique_id: climate_device}

        with patch.object(
            gw, "_make_encrypted_request", new_callable=AsyncMock
        ) as mock_req:
            await gw.set_climate_device_mode(
                climate_device.unique_id, HVAC_MODE_OFF
            )

        call_body = mock_req.call_args[0][1]
        assert call_body["id"][0]["sIT600TH"]["SetHoldType"] == 7

    async def test_set_climate_fan_mode(self):
        """Test fan mode on FC600-style device."""
        from custom_components.salus.models import ClimateDevice

        fc_device = ClimateDevice(
            available=True,
            name="FC Unit",
            unique_id="fc_001",
            temperature_unit="°C",
            precision=0.1,
            current_temperature=23.0,
            target_temperature=24.0,
            max_temp=40.0,
            min_temp=5.0,
            current_humidity=None,
            hvac_mode=HVAC_MODE_HEAT,
            hvac_action=CURRENT_HVAC_HEAT,
            hvac_modes=[HVAC_MODE_HEAT, HVAC_MODE_COOL, HVAC_MODE_AUTO],
            preset_mode=PRESET_FOLLOW_SCHEDULE,
            preset_modes=[PRESET_FOLLOW_SCHEDULE, PRESET_PERMANENT_HOLD],
            fan_mode=FAN_MODE_AUTO,
            fan_modes=[
                FAN_MODE_AUTO,
                FAN_MODE_HIGH,
                FAN_MODE_MEDIUM,
                FAN_MODE_LOW,
                FAN_MODE_OFF,
            ],
            locked=False,
            supported_features=(
                SUPPORT_TARGET_TEMPERATURE
                | SUPPORT_PRESET_MODE
                | SUPPORT_FAN_MODE
            ),
            device_class="temperature",
            data={"UniID": "fc_001", "Endpoint": 1},
            manufacturer="SALUS",
            model="FC600",
            sw_version="2.0",
        )

        gw = _make_gateway()
        gw._climate_devices = {"fc_001": fc_device}

        with patch.object(
            gw, "_make_encrypted_request", new_callable=AsyncMock
        ) as mock_req:
            await gw.set_climate_device_fan_mode("fc_001", FAN_MODE_HIGH)

        call_body = mock_req.call_args[0][1]
        assert call_body["id"][0]["sFanS"]["FanMode"] == 3

    async def test_missing_device_logs_error(self):
        gw = _make_gateway()
        # These should not raise, just log
        await gw.turn_on_switch_device("nonexistent")
        await gw.turn_off_switch_device("nonexistent")
        await gw.set_climate_device_temperature("nonexistent", 20)
        await gw.set_climate_device_preset("nonexistent", PRESET_OFF)
        await gw.set_climate_device_mode("nonexistent", HVAC_MODE_OFF)


# ---------------------------------------------------------------------------
#  Callbacks
# ---------------------------------------------------------------------------


class TestCallbacks:
    """Test add/send callback methods."""

    async def test_climate_callback(self):
        gw = _make_gateway()
        cb = AsyncMock()
        await gw.add_climate_update_callback(cb)
        await gw._send_climate_update_callback("dev_001")
        cb.assert_awaited_once_with(device_id="dev_001")

    async def test_binary_sensor_callback(self):
        gw = _make_gateway()
        cb = AsyncMock()
        await gw.add_binary_sensor_update_callback(cb)
        await gw._send_binary_sensor_update_callback("dev_002")
        cb.assert_awaited_once_with(device_id="dev_002")

    async def test_switch_callback(self):
        gw = _make_gateway()
        cb = AsyncMock()
        await gw.add_switch_update_callback(cb)
        await gw._send_switch_update_callback("dev_003")
        cb.assert_awaited_once_with(device_id="dev_003")

    async def test_cover_callback(self):
        gw = _make_gateway()
        cb = AsyncMock()
        await gw.add_cover_update_callback(cb)
        await gw._send_cover_update_callback("dev_004")
        cb.assert_awaited_once_with(device_id="dev_004")

    async def test_sensor_callback(self):
        gw = _make_gateway()
        cb = AsyncMock()
        await gw.add_sensor_update_callback(cb)
        await gw._send_sensor_update_callback("dev_005")
        cb.assert_awaited_once_with(device_id="dev_005")


# ---------------------------------------------------------------------------
#  Session lifecycle
# ---------------------------------------------------------------------------


class TestSessionLifecycle:
    """Test close / context-manager behaviour."""

    async def test_close_own_session(self):
        gw = _make_gateway()
        gw._close_session = True
        mock_session = AsyncMock()
        gw._session = mock_session

        await gw.close()
        mock_session.close.assert_awaited_once()

    async def test_close_external_session_not_closed(self):
        gw = _make_gateway()
        gw._close_session = False
        mock_session = AsyncMock()
        gw._session = mock_session

        await gw.close()
        mock_session.close.assert_not_awaited()

    async def test_context_manager(self):
        gw = _make_gateway()
        gw._close_session = True
        mock_session = AsyncMock()
        gw._session = mock_session

        async with gw:
            pass

        mock_session.close.assert_awaited_once()
