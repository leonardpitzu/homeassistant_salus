#!/usr/bin/env python3
"""Salus iT600 gateway Security1 handshake diagnostic tool.

Run this against your gateway to produce a comprehensive diagnostic
report.  The output can be shared in a GitHub issue without installing
Home Assistant.

Usage:
    python3 tools/gateway_diag.py --host 192.168.1.100 --euid 001E5E0D32906128

Requirements:
    pip install aiohttp cryptography
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import time
from pathlib import Path

# Add project root so we can import from custom_components
_project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_project_root))

import aiohttp  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.x25519 import (  # noqa: E402
    X25519PrivateKey,
)
from cryptography.hazmat.primitives.serialization import (  # noqa: E402
    Encoding,
    PublicFormat,
)

from custom_components.salus.protocol import parse_frame_33  # noqa: E402
from custom_components.salus.protocol_aes_cbc import AesCbcProtocol  # noqa: E402
from custom_components.salus.protocol_ecdh_aes_ccm import (  # noqa: E402
    PUBLIC_KEY_LEN,
    SZ_RANDOM,
    _build_pop_candidates,
    _decode_protobuf,
    aes_ctr_encrypt,
    build_session_cmd0,
    build_session_cmd1,
    derive_session_key,
    parse_session_resp0,
    parse_session_resp1,
)

# ---------------------------------------------------------------------------
#  Logging
# ---------------------------------------------------------------------------

LOG = logging.getLogger("salus_diag")


def _hex(data: bytes, limit: int = 128) -> str:
    h = data.hex()
    if len(h) > limit * 2:
        return f"{h[:limit * 2]}... ({len(data)}B total)"
    return h


# ---------------------------------------------------------------------------
#  Diagnostic probes
# ---------------------------------------------------------------------------

async def _probe_root(session: aiohttp.ClientSession, base: str, timeout: int) -> None:
    """Probe the root URL for reachability and server identity."""
    LOG.info("=== Phase 0: Reachability ===")
    for path in ("/", "/deviceid/read", "/prov-session"):
        url = f"{base}{path}"
        try:
            async with asyncio.timeout(timeout):
                for method in ("GET", "POST"):
                    if method == "GET":
                        resp = await session.get(url)
                    else:
                        resp = await session.post(url, data=b"")
                    body = await resp.read()
                    LOG.info(
                        "  %s %s → HTTP %d, %dB, hex=%s",
                        method, path, resp.status, len(body), _hex(body),
                    )
                    interesting = {
                        k: v for k, v in resp.headers.items()
                        if k.lower() in ("server", "content-type", "x-powered-by")
                    }
                    if interesting:
                        LOG.info("    headers: %s", interesting)
                    frame = parse_frame_33(body)
                    if frame:
                        LOG.info(
                            "    Frame33: type=%s counter=%d tag=%s",
                            frame.trailer_name, frame.counter, frame.tag.hex(),
                        )
        except Exception as exc:
            LOG.info("  %s → ERROR: %s", path, exc)


async def _probe_aes_cbc(
    session: aiohttp.ClientSession, base: str, euid: str, timeout: int
) -> bool:
    """Try the old AES-CBC protocols."""
    LOG.info("=== Phase 1: AES-CBC (legacy) ===")
    for aes128 in (False, True):
        label = "AES-128-CBC" if aes128 else "AES-256-CBC"
        proto = AesCbcProtocol(euid, aes128=aes128)
        try:
            result = await proto.connect(session, base.split("//")[1].split(":")[0],
                                         int(base.rsplit(":", 1)[1]), timeout)
            LOG.info("  %s: SUCCESS — readall returned %d devices", label, len(result.get("id", [])))
            return True
        except Exception as exc:
            LOG.info("  %s: FAILED — %s", label, exc)
    return False


async def _probe_security1(
    session: aiohttp.ClientSession,
    base: str,
    euid: str,
    timeout: int,
) -> bool:
    """Perform the Security1 handshake with full diagnostics."""
    LOG.info("=== Phase 2: Security1 (X25519 + AES-256-CTR) ===")

    endpoints = [f"{base}/prov-session", f"{base}/deviceid/read"]
    pop_candidates = _build_pop_candidates(euid)

    LOG.info("  PoP candidates (%d):", len(pop_candidates))
    for i, p in enumerate(pop_candidates):
        LOG.info("    [%d] %s", i, repr(p))

    for endpoint in endpoints:
        LOG.info("")
        LOG.info("--- Endpoint: %s ---", endpoint)

        # Generate fresh keypair
        client_key = X25519PrivateKey.generate()
        client_pub = client_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        LOG.info("  Client pubkey (%dB): %s", len(client_pub), client_pub.hex())

        # Step 1: SessionCmd0
        cmd0 = build_session_cmd0(client_pub)
        LOG.info("  SessionCmd0 (%dB): %s", len(cmd0), cmd0.hex())

        try:
            async with asyncio.timeout(timeout):
                resp = await session.post(
                    endpoint, data=cmd0,
                    headers={"content-type": "application/x-protocomm"},
                )
                resp0_raw = await resp.read()
        except Exception as exc:
            LOG.info("  POST SessionCmd0 → ERROR: %s", exc)
            continue

        LOG.info("  POST SessionCmd0 → HTTP %d, %dB", resp.status, len(resp0_raw))
        LOG.info("  Response hex: %s", _hex(resp0_raw))

        frame = parse_frame_33(resp0_raw)
        if frame:
            LOG.info(
                "  ⚠ Got Frame33: type=%s counter=%d tag=%s",
                frame.trailer_name, frame.counter, frame.tag.hex(),
            )

        if resp.status != 200:
            LOG.info("  ⚠ Non-200 — skipping")
            continue

        # Parse SessionResp0
        try:
            status0, device_pub, device_random = parse_session_resp0(resp0_raw)
        except ValueError as exc:
            LOG.info("  SessionResp0 parse FAILED: %s", exc)
            LOG.info("  Trying raw protobuf decode...")
            try:
                fields = _decode_protobuf(resp0_raw)
                for fnum, entries in fields.items():
                    for _wt, val in entries:
                        if isinstance(val, bytes):
                            LOG.info("    field %d (bytes, %dB): %s", fnum, len(val), _hex(val))
                        else:
                            LOG.info("    field %d (varint): %d", fnum, val)
            except Exception:
                LOG.info("  Raw protobuf decode also failed")

            # Try interpreting as raw 32+16 bytes
            if len(resp0_raw) >= PUBLIC_KEY_LEN + SZ_RANDOM:
                LOG.info(
                    "  Possible raw: pubkey=%s random=%s",
                    resp0_raw[:PUBLIC_KEY_LEN].hex(),
                    resp0_raw[PUBLIC_KEY_LEN:PUBLIC_KEY_LEN + SZ_RANDOM].hex(),
                )
            continue

        LOG.info("  SessionResp0: status=%d", status0)
        LOG.info("    device_pubkey (%dB): %s", len(device_pub), device_pub.hex())
        LOG.info("    device_random (%dB): %s", len(device_random), device_random.hex())

        if status0 != 0:
            LOG.info("  ⚠ Non-zero status!")
            continue

        # Step 2: Try each PoP
        for i, pop in enumerate(pop_candidates):
            pop_label = repr(pop) if pop is not None else "None (no PoP)"
            LOG.info("")
            LOG.info("  --- PoP [%d/%d]: %s ---", i + 1, len(pop_candidates), pop_label)

            try:
                session_key = derive_session_key(client_key, device_pub, pop)
            except Exception as exc:
                LOG.info("    Key derivation failed: %s", exc)
                continue

            LOG.info("    session_key: %s", session_key.hex())

            # Encrypt device_pubkey → client_verify
            client_verify = aes_ctr_encrypt(session_key, device_random, device_pub)
            LOG.info("    client_verify (%dB): %s", len(client_verify), client_verify.hex())

            cmd1 = build_session_cmd1(client_verify)
            LOG.info("    SessionCmd1 (%dB): %s", len(cmd1), cmd1.hex())

            try:
                async with asyncio.timeout(timeout):
                    resp1 = await session.post(
                        endpoint, data=cmd1,
                        headers={"content-type": "application/x-protocomm"},
                    )
                    resp1_raw = await resp1.read()
            except Exception as exc:
                LOG.info("    POST SessionCmd1 → ERROR: %s", exc)
                continue

            LOG.info("    POST SessionCmd1 → HTTP %d, %dB", resp1.status, len(resp1_raw))
            LOG.info("    Response hex: %s", _hex(resp1_raw))

            if resp1.status != 200:
                continue

            try:
                status1, device_verify = parse_session_resp1(resp1_raw)
            except ValueError as exc:
                LOG.info("    SessionResp1 parse FAILED: %s", exc)
                continue

            LOG.info("    SessionResp1: status=%d", status1)
            LOG.info("    device_verify (%dB): %s", len(device_verify), device_verify.hex())

            if status1 != 0:
                LOG.info("    ⚠ Non-zero status — PoP likely wrong")
                continue

            # Verify: decrypt device_verify at CTR offset 32
            # The client encrypted 32 bytes (device_pub → client_verify),
            # consuming CTR blocks 0-1.  The device then encrypts our
            # pubkey at CTR offset 32 → device_verify.
            # Decrypt the 64-byte concat to recover both plaintexts:
            combined_dec = aes_ctr_encrypt(
                session_key, device_random,
                client_verify + device_verify,
            )
            decrypted_our_pub = combined_dec[PUBLIC_KEY_LEN:]

            LOG.info("    Decrypted device_verify: %s", decrypted_our_pub.hex())
            LOG.info("    Our pubkey:              %s", client_pub.hex())

            if decrypted_our_pub == client_pub:
                LOG.info("    ✓✓✓ HANDSHAKE VERIFIED with pop=%s ✓✓✓", pop_label)

                # Try readall
                LOG.info("")
                LOG.info("  === Trying readall ===")
                body = json.dumps({"requestAttr": "readall"})
                encrypted = aes_ctr_encrypt(session_key, device_random, body.encode())
                for data_url in [f"{base}/deviceid/read", endpoint]:
                    LOG.info("    POST readall to %s (%dB)", data_url, len(encrypted))
                    try:
                        async with asyncio.timeout(timeout):
                            r = await session.post(
                                data_url, data=encrypted,
                                headers={"content-type": "application/x-protocomm"},
                            )
                            raw = await r.read()
                        LOG.info("    → HTTP %d, %dB", r.status, len(raw))
                        if raw:
                            LOG.info("    hex: %s", _hex(raw, 256))
                            try:
                                decrypted = aes_ctr_encrypt(session_key, device_random, raw)
                                text = decrypted.decode(errors="replace")
                                LOG.info("    Decrypted: %.500s", text)
                            except Exception as exc:
                                LOG.info("    Decrypt failed: %s", exc)
                    except Exception as exc:
                        LOG.info("    POST readall failed: %s", exc)

                return True
            else:
                LOG.info("    ✗ Verification mismatch")

    LOG.info("")
    LOG.info("All PoP candidates exhausted on all endpoints.")
    return False


# ---------------------------------------------------------------------------
#  Determinism probe
# ---------------------------------------------------------------------------

async def _probe_determinism(
    session: aiohttp.ClientSession, base: str, timeout: int
) -> None:
    """Send identical payloads twice to check response determinism."""
    LOG.info("=== Phase 3: Determinism test ===")
    url = f"{base}/deviceid/read"
    payload = b"\x00" * 32

    responses = []
    for i in range(2):
        try:
            async with asyncio.timeout(timeout):
                resp = await session.post(url, data=payload)
                raw = await resp.read()
            responses.append(raw)
            LOG.info("  Attempt %d: HTTP %d, %dB, hex=%s", i + 1, resp.status, len(raw), _hex(raw))
        except Exception as exc:
            LOG.info("  Attempt %d: ERROR: %s", i + 1, exc)

    if len(responses) == 2:
        LOG.info("  Identical output: %s", responses[0] == responses[1])
        f1, f2 = parse_frame_33(responses[0]), parse_frame_33(responses[1])
        if f1 and f2:
            LOG.info(
                "  Counter: %d → %d (delta=%d), tag_stable=%s",
                f1.counter, f2.counter, f2.counter - f1.counter,
                f1.tag == f2.tag,
            )


# ---------------------------------------------------------------------------
#  Main
# ---------------------------------------------------------------------------

async def run_diagnostics(host: str, port: int, euid: str, timeout: int) -> None:
    """Run all diagnostic phases and print summary."""
    base = f"http://{host}:{port}"
    euid_masked = euid[:4] + "…" + euid[-4:]

    LOG.info("=" * 72)
    LOG.info("  SALUS GATEWAY DIAGNOSTIC TOOL")
    LOG.info("=" * 72)
    LOG.info("  Host: %s:%d", host, port)
    LOG.info("  EUID: %s", euid_masked)
    LOG.info("  Timestamp: %s", time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()))
    LOG.info("=" * 72)
    LOG.info("")

    async with aiohttp.ClientSession() as session:
        # Phase 0: reachability
        await _probe_root(session, base, timeout)
        LOG.info("")

        # Phase 1: legacy AES-CBC
        aes_ok = await _probe_aes_cbc(session, base, euid, timeout)
        LOG.info("")

        if aes_ok:
            LOG.info("✓ Gateway works with legacy AES-CBC — no new protocol needed.")
            LOG.info("  If you see this but the integration still fails, the issue")
            LOG.info("  is elsewhere. Open an issue with this full output.")
            return

        # Phase 2: Security1
        sec1_ok = await _probe_security1(session, base, euid, timeout)
        LOG.info("")

        # Phase 3: determinism
        await _probe_determinism(session, base, timeout)
        LOG.info("")

    LOG.info("=" * 72)
    if sec1_ok:
        LOG.info("  RESULT: Security1 handshake SUCCEEDED")
    else:
        LOG.info("  RESULT: No protocol worked. Please share this FULL output at:")
        LOG.info("  https://github.com/leonardpitzu/homeassistant_salus/issues/3")
    LOG.info("=" * 72)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Salus iT600 gateway Security1 diagnostic tool"
    )
    parser.add_argument("--host", required=True, help="Gateway IP address")
    parser.add_argument("--port", type=int, default=80, help="Gateway port (default: 80)")
    parser.add_argument("--euid", required=True, help="Gateway EUID")
    parser.add_argument("--timeout", type=int, default=5, help="HTTP timeout in seconds")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        stream=sys.stdout,
    )

    asyncio.run(run_diagnostics(args.host, args.port, args.euid, args.timeout))


if __name__ == "__main__":
    main()
