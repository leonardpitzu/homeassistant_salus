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

Data is polled every 30 seconds. All communication is local over your LAN.

## Encryption / firmware changes

Salus gateways encrypt all local API traffic. A recent firmware update has changed the encryption protocol entirely. The integration currently supports the legacy protocol; support for the new protocol is under investigation.

|  | Legacy (AES-CBC) | New firmware (under investigation) |
|---|---|---|
| **Affected gateways** | UGE600, older UG800 firmware | UG800 with firmware ≥ 2025-07-15 |
| **Cipher** | AES-256-CBC (or AES-128-CBC) | AES-CCM (authenticated encryption) |
| **Key derivation** | `MD5("Salus-{euid}")` — static, derived from the gateway EUID | ECDH key exchange (`secp256r1`) → session key derivation |
| **IV / nonce** | Static, all zeros | Per-message nonce (part of AES-CCM) |
| **Padding** | PKCS7 | None (AES-CCM handles arbitrary lengths) |
| **Session setup** | None — key is static | Multi-step handshake (`setup0Request` / `setup0Response`) exchanging device public keys and randoms |
| **Framing** | Plain HTTP body | Encrypted core + variable-length trailer: `[prefix][sequence_byte][0xFD][check_hi][check_lo]` |
| **Sequence tracking** | None | Incrementing sequence byte per request |

### What we know so far

- Sending a legacy AES-CBC encrypted payload to an updated gateway returns a **33-byte reject frame** (32 bytes of opaque data + 1-byte trailer `0xAE`). This is not an encrypted response — it is a status/rejection indicator.
- The decryptable portion of any gateway response is the block-aligned prefix: `response[0 : len - (len % 16)]`. The remaining bytes form the trailer.
- **Exact replay** of captured request frames from the official Salus Smart Home app succeeds — the gateway returns full encrypted responses. However, re-encrypting the same plaintext with the old AES-CBC key and appending the captured trailer is rejected, confirming the encryption key itself has changed.
- Evidence from the Android APK references `secp256r1`, `cipherSecretKey`, `Device public key`, `Device random`, and `aes_ccm`, strongly indicating an **ECDH + AES-CCM** scheme.

### Current status

| What | Status |
|---|---|
| Legacy AES-CBC gateways | **Fully supported** |
| Detecting new-firmware reject frame | **Working** — the integration recognises the 33-byte reject and logs it clearly |
| New ECDH + AES-CCM handshake | **Not yet implemented** — reverse engineering in progress |
| Replaying captured new-protocol frames | **Confirmed working** in research tooling |
| Generating new valid encrypted requests | **Not yet possible** — key exchange flow still being reconstructed |

If your gateway has received the new firmware and the integration can no longer connect, there is unfortunately no workaround yet. Progress is tracked in [issue #81](https://github.com/epoplavskis/homeassistant_salus/issues/81). Contributions and packet captures are welcome.

## Debugging

If you're having issues with the integration, there are two ways to enable debug logging.

### Option 1 — YAML configuration

Add the following to your `configuration.yaml` and restart Home Assistant:

```yaml
logger:
  default: info
  logs:
    custom_components.salus: debug
```

### Option 2 — Home Assistant UI

1. Go to **Settings** → **Devices & Services**.
2. Find the **Salus iT600** integration and click the **⋮** menu.
3. Select **Enable debug logging**.
4. Reproduce the issue.
5. Click **Disable debug logging** — the browser will download a log file you can inspect or attach to a bug report.

This method is useful for one-off troubleshooting since it automatically reverts to the normal log level once you stop it.

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
