# /// script
# requires-python = ">=3.11"
# dependencies = ["mcp>=1.0,<2", "httpx>=0.27,<1", "certifi>=2024,<2027"]
# ///
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Read-only Exabeam MCP bridge for aiscoring.

Derived from socxen's bridge. A local stdio MCP server that forwards to the remote Exabeam
New-Scale MCP, minting and refreshing the OAuth token. Unlike socxen's:

- It exposes ONLY the read tools in READ_TOOLS. Write tools are hidden from list_tools and
  refused by call_tool, so the scorer cannot change an alert or case however it is prompted.
- It strips the analyst's disposition (LABEL_FIELDS) from case and alert results before the
  model sees them, as AIScoring's stripLabels does. A closed case carries its answer, and a
  score that reads it measures nothing. Case notes are not exposed at all, for the same reason.

Read results also pass through canonicalize() to strip invisible-Unicode smuggling.

Reads creds from ~/.exabeam-mcp.env (same file socxen uses):
    EXABEAM_MCP_URL=https://api.<region>.exabeam.cloud/mcp
    EXABEAM_API_KEY=...
    EXABEAM_API_SECRET=...

  --check                  validate the connection without starting the server
  --closure ID [ID ...]    print {caseId: {"stage", "closedReason"}} as JSON. For history.py
                           only: it runs outside the MCP session, so the model never sees it.
"""
import asyncio
import json
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

# Case and alert results carry the disposition under these keys (AIScoring server/mapping.ts
# reads the same names; compared lowercase). Raw log searches are left alone: a log is evidence,
# and a key named `status` inside one means something else.
LABELLED_TOOLS = frozenset({
    "exabeam_get_case_details", "exabeam_search_cases", "exabeam_get_case_threat_timeline",
    "exabeam_get_alert_details", "exabeam_search_alerts", "exabeam_get_alert_threat_timeline",
    "exabeam_threat_summary",
})
LABEL_FIELDS = frozenset({
    "stage", "casestage", "queue", "casequeue", "assignee", "assignedto",
    "closed_reason", "closurereason", "resolution", "case_close_supporting_reason", "closurecomment",
    "status", "case_status", "casestatus", "alertstatus", "alert_status",
})
CLOSURE_KEYS = ("closed_reason", "closureReason", "resolution")


def strip_labels(obj):
    if isinstance(obj, dict):
        return {k: strip_labels(v) for k, v in obj.items() if k.lower() not in LABEL_FIELDS}
    if isinstance(obj, list):
        return [strip_labels(v) for v in obj]
    return obj


def find_first(obj, keys):
    """First non-empty value under any of `keys`, searching nested dicts and lists."""
    if isinstance(obj, dict):
        for k in keys:
            if obj.get(k):
                return obj[k]
        obj = list(obj.values())
    if isinstance(obj, list):
        for v in obj:
            if (found := find_first(v, keys)) is not None:
                return found
    return None


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


def unlabel_text(text):
    """Remove LABEL_FIELDS from a JSON result. Fail-CLOSED: a result that cannot be parsed is
    withheld rather than passed through, because passing it through could show the model the
    case's own disposition."""
    try:
        return json.dumps(strip_labels(json.loads(text)))
    except ValueError:
        return "[withheld by the aiscoring bridge: result was not JSON, so the case disposition could not be removed]"


def _clean_block(block, unlabel):
    """Canonicalize a text or embedded-resource block (fail-open), then strip labels if asked."""
    def clean(text):
        try:
            text = canonicalize(text)[0]
        except Exception as e:  # noqa: BLE001
            sys.stderr.write(f"bridge: canonicalize passthrough after error: {e!r}\n")
        return unlabel_text(text) if unlabel else text

    text = getattr(block, "text", None)
    if isinstance(text, str):
        return block.model_copy(update={"text": clean(text)})
    res = getattr(block, "resource", None)
    rtext = getattr(res, "text", None)
    if isinstance(rtext, str):
        return block.model_copy(update={"resource": res.model_copy(update={"text": clean(rtext)})})
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
    return [_clean_block(b, name in LABELLED_TOOLS) for b in content]


async def _check():
    tools = (await remote(lambda s: s.list_tools())).tools
    exposed = sorted(t.name for t in tools if t.name in READ_TOOLS)
    print(f"OK, connected to {URL}; exposing {len(exposed)} of {len(tools)} Exabeam tools (read-only).")


async def _closure(case_ids):
    async def one(session, case_id):
        result = await session.call_tool("exabeam_get_case_details", {"arg0": {"caseId": case_id}})
        for block in result.content:
            try:
                data = json.loads(getattr(block, "text", "") or "")
            except ValueError:
                continue
            return {"stage": find_first(data, ("stage", "caseStage")),
                    "closedReason": find_first(data, CLOSURE_KEYS)}
        return {"stage": None, "closedReason": None}

    async def all_cases(session):
        return {case_id: await one(session, case_id) for case_id in case_ids}

    print(json.dumps(await remote(all_cases)))


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
    if "--closure" in sys.argv:
        asyncio.run(_closure(sys.argv[sys.argv.index("--closure") + 1:]))
    else:
        asyncio.run(_check() if "--check" in sys.argv else _serve())


if __name__ == "__main__":
    main()
