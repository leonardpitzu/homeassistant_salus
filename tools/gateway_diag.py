#!/usr/bin/env python3
"""Salus iT600 gateway diagnostic tool.

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
import logging
import sys
import time
from pathlib import Path

# Add project root so we can import from custom_components
_project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_project_root))

import aiohttp  # noqa: E402

from custom_components.salus.protocol import parse_frame_33  # noqa: E402
from custom_components.salus.protocol_aes_cbc import AesCbcProtocol  # noqa: E402
from custom_components.salus.protocol_new_aes_cbc import NewAesCbcProtocol  # noqa: E402

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


async def _probe_new_aes_cbc(
    session: aiohttp.ClientSession,
    base: str,
    timeout: int,
) -> bool:
    """Try the new-firmware AES-CBC protocols (universal key)."""
    LOG.info("=== Phase 2: NewAES-CBC (new firmware, universal key) ===")
    host = base.split("//")[1].split(":")[0]
    port = int(base.rsplit(":", 1)[1])
    for aes256 in (False, True):
        proto = NewAesCbcProtocol(aes256=aes256)
        try:
            result = await proto.connect(session, host, port, timeout)
            LOG.info("  %s: SUCCESS — readall returned %d devices", proto.name, len(result.get("id", [])))
            return True
        except Exception as exc:
            LOG.info("  %s: FAILED — %s", proto.name, exc)
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
            LOG.info("✓ Gateway works with legacy AES-CBC.")
            LOG.info("=" * 72)
            LOG.info("  RESULT: Protocol auto-detection SUCCEEDED")
            LOG.info("=" * 72)
            return

        # Phase 2: new AES-CBC (universal key)
        new_ok = await _probe_new_aes_cbc(session, base, timeout)
        LOG.info("")

        if new_ok:
            LOG.info("✓ Gateway works with new-firmware AES-CBC (universal key).")
            LOG.info("=" * 72)
            LOG.info("  RESULT: Protocol auto-detection SUCCEEDED")
            LOG.info("=" * 72)
            return

        # Phase 3: determinism
        await _probe_determinism(session, base, timeout)
        LOG.info("")

    LOG.info("=" * 72)
    if aes_ok or new_ok:
        LOG.info("  RESULT: Protocol auto-detection SUCCEEDED")
    else:
        LOG.info("  RESULT: No protocol worked. Please share this FULL output at:")
        LOG.info("  https://github.com/leonardpitzu/homeassistant_salus/issues/3")
    LOG.info("=" * 72)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Salus iT600 gateway diagnostic tool"
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
