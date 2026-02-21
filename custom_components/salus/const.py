"""Constants for the Salus iT600 integration and gateway library."""

from __future__ import annotations

# ── Home Assistant integration ──────────────────────────────────────
DOMAIN = "salus"

# ── Temperature ─────────────────────────────────────────────────────
DEGREE = "°"
TEMP_CELSIUS = f"{DEGREE}C"

# ── Library-internal feature bit-flags ──────────────────────────────
SUPPORT_TARGET_TEMPERATURE = 1
SUPPORT_FAN_MODE = 8
SUPPORT_PRESET_MODE = 16

SUPPORT_OPEN = 1
SUPPORT_CLOSE = 2
SUPPORT_SET_POSITION = 4

# ── HVAC modes (values intentionally match HVACMode enum) ──────────
HVAC_MODE_OFF = "off"
HVAC_MODE_HEAT = "heat"
HVAC_MODE_COOL = "cool"
HVAC_MODE_AUTO = "auto"

# ── HVAC action states (values match HVACAction enum) ──────────────
CURRENT_HVAC_OFF = "off"
CURRENT_HVAC_HEAT = "heating"
CURRENT_HVAC_HEAT_IDLE = "idle"
CURRENT_HVAC_COOL = "cooling"
CURRENT_HVAC_COOL_IDLE = "idle"
CURRENT_HVAC_IDLE = "idle"

# ── Preset modes ───────────────────────────────────────────────────
PRESET_FOLLOW_SCHEDULE = "Follow Schedule"
PRESET_PERMANENT_HOLD = "Permanent Hold"
PRESET_TEMPORARY_HOLD = "Temporary Hold"
PRESET_ECO = "Eco"
PRESET_OFF = "Off"

# ── Fan modes (lowercase — match HA fan-mode constants) ────────────
FAN_MODE_AUTO = "auto"
FAN_MODE_HIGH = "high"
FAN_MODE_MEDIUM = "medium"
FAN_MODE_LOW = "low"
FAN_MODE_OFF = "off"

# ── Thermostat error codes (sIT600TH Error* fields) ───────────────
THERMOSTAT_ERROR_CODES: dict[str, str] = {
    "Error01": "Paired TRV hardware issue",
    "Error02": "Floor sensor overheating",
    "Error03": "Floor sensor open",
    "Error04": "Floor sensor short",
    "Error05": "Lost link with ZigBee Coordinator",
    "Error06": "Lost link with Wiring Center KL08RF",
    "Error07": "Lost link with TRV",
    "Error08": "Lost link with RX10RF (RX1)",
    "Error09": "Lost link with RX10RF (RX2)",
    "Error21": "Paired TRV lost link with Coordinator",
    "Error22": "Paired TRV low battery",
    "Error23": "Message from unpaired TRV",
    "Error24": "Rejected by Wiring Centre",
    "Error25": "Lost link with Parent",
    "Error30": "Paired TRV gear issue",
    "Error31": "Paired TRV adaptation issue",
    "Error32": "Low battery",
}

# Error codes that represent low-battery conditions
BATTERY_ERROR_CODES: frozenset[str] = frozenset({"Error22", "Error32"})

# ── Battery percentage from Status_d ───────────────────────────────
# Only these OEM models are battery-powered thermostats that report a
# 0-5 battery level at Status_d character 99.  All other IT600 devices
# are mains-powered and always report 0 (which is meaningless).
BATTERY_OEM_MODELS: frozenset[str] = frozenset({"SQ610RF", "SQ610RF(WB)", "SQ610RFNH"})

# ── Voltage-based battery thresholds (BatteryVoltage_x10 / 10 → V) ─
# Extracted from the official Salus web-app JS.
# Each entry: (model_set, [(voltage_threshold, percent, status), ...])
# Thresholds are checked high → low; the first match wins.
BATTERY_VOLTAGE_THRESHOLDS: dict[str, list[tuple[float, int, str]]] = {
    "window": [
        (2.6, 100, "full"),
        (2.3, 50, "half"),
        (2.1, 25, "low"),
        (0.0, 0, "critical"),
    ],
    "door": [
        (2.9, 100, "full"),
        (2.8, 50, "half"),
        (2.2, 25, "low"),
        (0.0, 0, "critical"),
    ],
    "energy_meter": [
        (5.2, 100, "full"),
        (4.6, 50, "half"),
        (4.2, 25, "low"),
        (0.0, 0, "critical"),
    ],
}

# Models that use the "door" voltage curve (CO, smoke, remote temp)
DOOR_VOLTAGE_MODELS: frozenset[str] = frozenset({
    "SmokeSensor-EM", "WLS600", "TS600", "SD600",
})
# Models that use the "window" voltage curve
WINDOW_VOLTAGE_MODELS: frozenset[str] = frozenset({
    "SW600", "OS600",
})
# Models that use the "energy_meter" voltage curve
ENERGY_METER_VOLTAGE_MODELS: frozenset[str] = frozenset({
    "RE600", "RE10B",
})

# ── Cover device class mapping ────────────────────────────────────
COVER_DEVICE_CLASS_MAP: dict[str, str] = {
    "SR600": "shutter",
    "RS600": "shutter",
}
