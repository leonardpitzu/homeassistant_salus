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
