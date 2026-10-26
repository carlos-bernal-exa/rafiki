# /// script
# requires-python = ">=3.11"
# dependencies = ["mcp>=1.0,<2", "httpx>=0.27,<1", "certifi>=2024,<2027"]
# ///
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Read-only Exabeam MCP bridge for aiscoring.

Derived from socxen's bridge. A local stdio MCP server that forwards to the remote Exabeam
New-Scale MCP, minting and refreshing the OAuth token. Unlike socxen's, it exposes ONLY the
read tools in READ_TOOLS: write tools are hidden from list_tools and refused by call_tool, so
the scorer cannot change an alert or case however it is prompted. Read results pass through
canonicalize() to strip invisible-Unicode smuggling from telemetry.

Reads creds from ~/.exabeam-mcp.env (same file socxen uses):
    EXABEAM_MCP_URL=https://api.<region>.exabeam.cloud/mcp
    EXABEAM_API_KEY=...
    EXABEAM_API_SECRET=...

Run with --check to validate the connection without starting the server.
"""
import asyncio
import os
import re
import ssl
import sys
import time
from urllib.parse import urlparse

import certifi
import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.server import Server
from mcp.server.stdio import stdio_server

from canonicalize import canonicalize

_VERIFY = ssl.create_default_context(cafile=certifi.where())
_token = {"value": None, "exp": 0.0}

# Allowlist, not denylist: a tool the remote MCP adds later stays hidden until someone decides
# it is read-only and adds it here.
READ_TOOLS = frozenset({
    "exabeam_get_case_details",
    "exabeam_get_case_notes",
    "exabeam_get_case_threat_timeline",
    "exabeam_search_cases",
    "exabeam_get_alert_details",
    "exabeam_get_alert_threat_timeline",
    "exabeam_search_alerts",
    "exabeam_threat_summary",
    "exabeam_search_events",
    "exabeam_get_mitre_coverage",
    "exabeam_get_use_case_score",
    "exabeam_analytics_rule_list",
    "exabeam_correlation_rule_list",
    "exabeam_get_correlation_rule_details",
    "exabeam_context_table_list",
    "exabeam_get_context_table_records",
})


def load_env(path="~/.exabeam-mcp.env"):
    cfg = {}
    p = os.path.expanduser(path)
    if not os.path.exists(p):
        return cfg
    for line in open(p):
        s = line.rstrip("\n")
        if not s.strip() or s.lstrip().startswith("#") or "=" not in s:
            continue
        k, v = s.split("=", 1)
        cfg[k.strip()] = re.sub(r"\s+#.*$", "", v).strip()
    return cfg


CFG = load_env()
URL = CFG.get("EXABEAM_MCP_URL", "")
KEY = CFG.get("EXABEAM_API_KEY", "")
SECRET = CFG.get("EXABEAM_API_SECRET", "")


async def get_token():
    """Mint/refresh the OAuth client-credentials token; cached until ~1 min before expiry."""
    if _token["value"] and time.time() < _token["exp"] - 60:
        return _token["value"]
    p = urlparse(URL)
    async with httpx.AsyncClient(verify=_VERIFY) as c:
        r = await c.post(
            f"{p.scheme}://{p.netloc}/auth/v1/token",
            json={"grant_type": "client_credentials", "client_id": KEY, "client_secret": SECRET},
            headers={"Content-Type": "application/json"},
            timeout=20,
        )
        r.raise_for_status()
        d = r.json()
    _token["value"] = d["access_token"]
    _token["exp"] = time.time() + int(d.get("expires_in", 3600))
    return _token["value"]


async def remote(op):
    """Open a fresh authenticated connection to the remote Exabeam MCP and run op(session)."""
    tok = await get_token()
    async with streamablehttp_client(URL, headers={"Authorization": f"Bearer {tok}"}) as (r, w, _):
        async with ClientSession(r, w) as session:
            await session.initialize()
            return await op(session)


server = Server("exabeam")


def _canon_block(block):
    """Strip the invisible smuggling layer from a text or embedded-resource block. Fail-open:
    a canonicalizer bug must not break a read."""
    try:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            return block.model_copy(update={"text": canonicalize(text)[0]})
        res = getattr(block, "resource", None)
        rtext = getattr(res, "text", None)
        if isinstance(rtext, str):
            return block.model_copy(update={"resource": res.model_copy(update={"text": canonicalize(rtext)[0]})})
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"bridge: canonicalize passthrough after error: {e!r}\n")
    return block


@server.list_tools()
async def list_tools():
    tools = (await remote(lambda s: s.list_tools())).tools
    return [t for t in tools if t.name in READ_TOOLS]


@server.call_tool()
async def call_tool(name, arguments):
    if name not in READ_TOOLS:
        raise ValueError(f"{name} is not available: aiscoring is read-only")
    content = (await remote(lambda s: s.call_tool(name, arguments or {}))).content
    return [_canon_block(b) for b in content]


async def _check():
    tools = (await remote(lambda s: s.list_tools())).tools
    exposed = sorted(t.name for t in tools if t.name in READ_TOOLS)
    print(f"OK, connected to {URL}; exposing {len(exposed)} of {len(tools)} Exabeam tools (read-only).")


async def _serve():
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


def main():
    if not (URL and KEY and SECRET):
        sys.stderr.write(
            "exabeam-mcp-bridge: missing credentials. Create ~/.exabeam-mcp.env with "
            "EXABEAM_MCP_URL, EXABEAM_API_KEY, EXABEAM_API_SECRET.\n"
        )
        sys.exit(1)
    asyncio.run(_check() if "--check" in sys.argv else _serve())


if __name__ == "__main__":
    main()
