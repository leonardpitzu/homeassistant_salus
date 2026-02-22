# Salus iT600 for Home Assistant

A custom [Home Assistant](https://www.home-assistant.io/) integration that lets you control and monitor your [Salus iT600](https://salus-controls.com/) smart home devices **locally** through the UGE600 universal gateway — thermostats, smart plugs, roller shutters, sensors, and more, all without cloud dependency.

## Features

### Climate

One climate entity per thermostat connected to the gateway. Two thermostat families are supported:

- **iT600 thermostats** (e.g. SQ610RF) — heat/off/auto modes, Follow Schedule / Permanent Hold / Off presets, current & target temperature, humidity, 0.5 °C increments.
- **FC600 fan-coil controllers** — heat/cool/auto modes, five presets (Follow Schedule, Permanent Hold, Temporary Hold, Eco, Off), fan modes (auto/high/medium/low/off), separate heating/cooling setpoints.

### Sensors

| Sensor | Description |
|---|---|
| **Temperature** | Current temperature reading (°C) |
| **Humidity** | Relative humidity (%) |
| **Battery** | Battery level for wireless thermostats and standalone sensors (%) |
| **Power** | Instantaneous power draw from smart plugs (W) |
| **Energy** | Cumulative energy consumption from smart plugs (kWh) |

### Binary sensors

| Binary sensor | Description |
|---|---|
| **Window / Door** | Open/closed state (SW600, OS600) |
| **Water leak** | Moisture detection (WLS600) |
| **Smoke** | Smoke alarm (SmokeSensor-EM, SD600) |
| **Low battery** | Battery warning for wireless sensors |
| **Thermostat problem** | Aggregated thermostat error flags with human-readable descriptions as attributes |
| **Battery problem** | Battery-specific thermostat error indicator |

### Covers

One cover entity per roller shutter or blind (SR600, RS600). Supports **open**, **close**, and **set position** (0–100 %).

### Switches

One switch entity per smart plug or relay (SP600, SPE600). Supports **on/off** control. Double-switch devices are exposed as separate entities.

### Locks

One lock entity per thermostat that supports child lock. Allows **locking/unlocking** the thermostat keypad.

## Installation

### HACS (recommended)

1. Open HACS in your Home Assistant instance.
2. Go to **Integrations** → **⋮** → **Custom repositories**.
3. Add `https://github.com/leonardpitzu/homeassistant_salus` as an **Integration**.
4. Search for **Salus iT600** and install it.
5. Restart Home Assistant.

### Manual

1. Copy the `custom_components/salus` folder into your Home Assistant `config/custom_components/` directory.
2. Restart Home Assistant.

## Configuration

1. Go to **Settings** → **Devices & Services** → **Add Integration**.
2. Search for **Salus iT600**.
3. Enter your gateway's **IP address** and **EUID** (the first 16 characters printed under the gateway's micro-USB port).
4. The integration will discover all devices on the gateway and create entities automatically.

Data is polled every 30 seconds. All communication is local over your LAN — encrypted with AES-128-CBC.

## Troubleshooting

- If you can't connect using the EUID on your gateway (e.g. `001E5E0D32906128`), try `0000000000000000` as EUID.
- Make sure **Local WiFi Mode** is enabled on your gateway:
  1. Open the Salus Smart Home app on your phone and sign in.
  2. Double-tap your gateway to open the info screen.
  3. Press the gear icon to enter configuration.
  4. Scroll down and check that **Disable Local WiFi Mode** is set to **No**.
  5. Scroll to the bottom, save settings, and restart the gateway by unplugging/plugging USB power.

## Supported devices

SQ610RF, SQ610RF(WB), SQ610RFNH, FC600, SP600, SPE600, SR600, RS600, SW600, OS600, WLS600, SmokeSensor-EM, SD600, TS600, RE600, RE10B, it600MINITRV, it600Receiver.

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
