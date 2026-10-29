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
  --lookup USER [USER ...] print each account's title, department, employee type, MFA and
                           account status from the identity context tables, and whether a
                           service-account table lists it. Only those fields leave the bridge.
"""
import asyncio
import json
import os
import random
import re
import signal
import ssl
import sys
import time
from datetime import timedelta
from urllib.parse import urlparse

import certifi
import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.shared.exceptions import McpError

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
    # exabeam_get_context_table_records is left out on purpose: one page of an identity table is
    # a thousand employees' names and phone numbers. --lookup reads it and returns one row's role.
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
    # camelCase names the New-Scale API actually returns. alertdescription goes too: analysts
    # edit it, and it has carried "False Positive: ..." text. The rule's own description stays
    # available per detection in the timeline.
    "closedreason", "supportingreason", "caseclosedtimestamp", "lastmodifiedby", "alertdescription",
})
# Backstop for names the list above has not seen: a tenant or API version that calls the field
# something else must lose it, not leak it. A key that merely looks like a disposition is dropped
# too; losing an odd field costs less than showing the answer. assign, queue and status cover
# the rest of the handling fields the skill promises to hide (an assignment timestamp still shows
# the case was worked).
LABEL_PATTERN = re.compile(r"clos(e|ed|ure|ing)|resolution|disposition|false_?positive|assign|queue|status", re.I)
CLOSURE_KEYS = ("closed_reason", "closureReason", "closedReason", "resolution")


def strip_labels(obj):
    if isinstance(obj, dict):
        return {k: strip_labels(v) for k, v in obj.items() if k.lower() not in LABEL_FIELDS and not LABEL_PATTERN.search(k)}
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


def leaf_errors(exc):
    """The real errors inside the ExceptionGroups that anyio's task groups wrap them in."""
    if isinstance(exc, BaseExceptionGroup):
        return [leaf for sub in exc.exceptions for leaf in leaf_errors(sub)]
    return [exc]


def error_text(result):
    """The message of a failed Exabeam call, or None. An error is not case data, so showing it
    cannot leak a disposition, and withholding it left the model unable to say what went wrong."""
    if not result.isError:
        return None
    text = " ".join(getattr(b, "text", None) or "" for b in result.content).strip()
    return "Exabeam returned an error: " + text[:500]


# ---- the upstream session, ported from socxen's bridge (socxen #153-#157) ----
# One remote MCP session per bridge process, opened lazily and reopened when it is lost. The
# old design opened a new session for every call, and Exabeam rate-limits session opens: 16
# concurrent reads through it got a 403 and queued up to 71 s, where one shared session served
# all 16 in about 9 s. Every tool here is a read, so every call may be retried.

_RETRYABLE_STATUS = {429, 500, 502, 503, 504}
_RETRY_DELAYS = (0.3, 0.9)               # seconds, plus jitter
_CALL_TIMEOUT = timedelta(seconds=120)   # no call may hang the bridge forever
_DROP_TIMEOUT = 10.0             # how long drop() waits for the owner task to send its DELETE and exit
_OPEN_FAIL_WAIT = 5.0            # how long _open() waits for a failed owner task to finish unwinding
_BREAKER_TRIP = 5                # consecutive transport failures ...
_BREAKER_HOLD = 20.0             # ... open the breaker for this long


class _Leaf:
    """What actually failed, dug out of the ExceptionGroup that anyio wraps around everything
    raised inside a session, and whether a retry or a new session can help."""

    def __init__(self, exc):
        def rank(e):                     # the most informative leaf wins
            if isinstance(e, httpx.HTTPStatusError):
                return 0
            if isinstance(e, McpError):
                return 1
            if isinstance(e, httpx.TransportError):
                return 2
            return 3
        e = sorted(leaf_errors(exc), key=rank)[0]
        self.status = e.response.status_code if isinstance(e, httpx.HTTPStatusError) else None
        self.message = (str(e) or type(e).__name__)[:300]
        self.summary = f"{type(e).__name__}: {self.message}"
        transport = isinstance(e, httpx.TransportError)
        code = getattr(getattr(e, "error", None), "code", None) if isinstance(e, McpError) else None
        # A read or write timeout is not retryable: the query is slow, not transient, and a retry
        # doubles the load. A connect or pool timeout sent nothing, so a retry is cheap.
        sent_and_timed_out = isinstance(e, (httpx.ReadTimeout, httpx.WriteTimeout))
        self.retryable = (transport and not sent_and_timed_out) or self.status in _RETRYABLE_STATUS
        # The session survives an application-level JSON-RPC error. A status error, a dropped
        # connection or "Session terminated" (code 32600) kills it, and the next call must reopen.
        terminated = code == 32600 or "session" in self.message.lower()
        self.session_lost = not (isinstance(e, McpError) and not terminated)


class _Upstream:
    def __init__(self):
        self._session = None
        self._task = None
        self._close = None
        self._lock = None
        self._streak = 0
        self._open_until = 0.0
        self._last_summary = ""
        self._last_failed_owner = None

    async def _runner(self, tok, ready, close, err):
        # The session's context managers are entered and exited by THIS task only (anyio requires
        # it). The session lives until `close` is set; a normal exit sends the DELETE. The task
        # returns its error, so a caller racing it reads that generation's error and no other. A
        # cancellation is re-raised: a bare CancelledError escaping a handler kills the server.
        mine = None
        try:
            async with streamablehttp_client(URL, headers={"Authorization": f"Bearer {tok}"}) as (r, w, _):
                async with ClientSession(r, w) as s:
                    await s.initialize()
                    if self._task is asyncio.current_task():     # publish only while still the owner
                        self._session = mine = s
                    ready.set()
                    await close.wait()
        except asyncio.CancelledError:
            ready.set()
            raise
        except BaseException as e:  # noqa: BLE001  reported to the opener through `err`, to callers as the task's result
            err.append(e)
            ready.set()
            return e
        finally:
            if mine is not None and self._session is mine:   # never clear a session a newer owner opened
                self._session = None
        return None

    async def _open(self):
        tok = await get_token()
        ready, close, err = asyncio.Event(), asyncio.Event(), []
        task = asyncio.create_task(self._runner(tok, ready, close, err))
        self._task, self._close = task, close            # registered before waiting: a cancelled opener can still close it
        try:
            await ready.wait()
        except asyncio.CancelledError:
            close.set()
            raise
        if err:
            try:
                await asyncio.wait_for(task, _OPEN_FAIL_WAIT)
            except BaseException:  # noqa: BLE001, S110  the owner already failed; its error is err[0], raised next
                pass
            self._task = self._close = None
            raise err[0]

    async def drop(self):
        if self._close is not None:
            self._close.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, _DROP_TIMEOUT)
            except BaseException:  # noqa: BLE001, S110  teardown is best effort; the session is gone either way
                pass
        self._task = self._close = self._session = None

    async def session(self):
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            if self._session is None or self._task is None or self._task.done():
                await self.drop()
                await self._open()
            return self._session, self._task

    async def _drop_if(self, owner):
        """Drop the session only while `owner` still owns it. Every call in flight on a session
        fails when it dies; the first to notice reopens it, and the rest must not drop the new one."""
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            if self._task is owner:
                await self.drop()

    async def _run_on_session(self, op, s, owner):
        """Run op(s) but never outlive the session. The transport dies in the owner task, and a
        caller blocked on it would otherwise wait out the full read timeout."""
        op_task = asyncio.ensure_future(op(s))
        try:
            done, _ = await asyncio.wait({op_task, owner}, return_when=asyncio.FIRST_COMPLETED)
        except asyncio.CancelledError:                   # the host cancelled the call: do not orphan the op
            op_task.cancel()
            raise
        if op_task in done:
            return op_task.result()
        op_task.cancel()
        try:
            await op_task
        except BaseException:  # noqa: BLE001, S110  the cancellation or the op's own error; the owner's is raised
            pass
        exc = None
        if owner.done() and not owner.cancelled():
            try:
                exc = owner.result()
            except BaseException:  # noqa: BLE001, S110  a runner that raised anyway: an unexplained close
                exc = None
        if not isinstance(exc, Exception):
            exc = RuntimeError("upstream session closed during the call")
        raise exc

    def _breaker_check(self):
        now = time.time()
        if now < self._open_until:
            raise RuntimeError(f"Exabeam MCP: {_BREAKER_TRIP} transport failures in a row (last: {self._last_summary}); "
                               f"refusing calls for another {self._open_until - now:.0f}s")

    def _note(self, ok, owner=None):
        if ok:
            self._streak = 0
            self._last_failed_owner = None
            return
        if owner is not None and owner is self._last_failed_owner:
            return                       # N calls in flight on one lost session are one failure, not N
        self._last_failed_owner = owner
        self._streak += 1
        if self._streak >= _BREAKER_TRIP:
            self._open_until = time.time() + _BREAKER_HOLD
            self._streak = 0
            log(f"{_BREAKER_TRIP} transport failures in a row, holding off Exabeam for {_BREAKER_HOLD:.0f}s")

    async def call(self, op):
        self._breaker_check()
        attempt = 0
        while True:
            owner = None
            try:
                s, owner = await self.session()
                result = await self._run_on_session(op, s, owner)
            except Exception as e:
                leaf = _Leaf(e)
                self._last_summary = leaf.summary
                if leaf.status == 401:
                    _token["exp"] = 0.0          # a rejected token is not fresh, whatever our clock says
                if owner is not None and leaf.session_lost:
                    await self._drop_if(owner)
                self._note(False, owner)
                if (leaf.retryable or (owner is not None and leaf.session_lost)) and attempt < len(_RETRY_DELAYS):
                    await asyncio.sleep(_RETRY_DELAYS[attempt] + random.uniform(0, 0.3))  # noqa: S311
                    attempt += 1
                    continue
                raise RuntimeError(leaf.summary) from e
            self._note(True)
            return result


UPSTREAM = _Upstream()


async def remote(op):
    """Run op(session) on the process's one upstream session."""
    return await UPSTREAM.call(op)


async def _then_drop(coro):
    """For the one-shot modes: run, then close the session cleanly (one DELETE)."""
    try:
        return await coro
    finally:
        await UPSTREAM.drop()


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
    result = await remote(lambda s: s.call_tool(name, arguments or {}, read_timeout_seconds=_CALL_TIMEOUT))
    if (failure := error_text(result)) is not None:
        raise ValueError(canonicalize(failure)[0])
    content = result.content
    return [_clean_block(b, name in LABELLED_TOOLS) for b in content]


async def _check():
    tools = (await remote(lambda s: s.list_tools())).tools
    exposed = sorted(t.name for t in tools if t.name in READ_TOOLS)
    print(f"OK, connected to {URL}; exposing {len(exposed)} of {len(tools)} Exabeam tools (read-only).")


async def _closure(case_ids):
    async def one(session, case_id):
        try:
            result = await session.call_tool("exabeam_get_case_details", {"arg0": {"caseId": case_id}})
        except Exception as e:  # noqa: BLE001  one bad case must not lose the others' closures
            sys.stderr.write(f"bridge: closure lookup for {case_id} failed: {e!r}\n")
            return {"stage": None, "closedReason": None}
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


# ---- --lookup: entity context from the tenant's identity context tables ----

# Table names differ per tenant, so tables are picked by their columns. A table with a Title or
# Department column describes people; one named like a service-account list marks accounts.
PROFILE_COLUMN = re.compile(r"^(title|department)$", re.I)
SERVICE_TABLE = re.compile(r"service.?accounts?", re.I)
ID_KEY = re.compile(r"(user(_?names?)?|email|account|login)$", re.I)
# Only these leave the bridge. A row also holds names, phone numbers and the manager, which
# say nothing about whether the actor fits the action.
PROFILE_KEYS = {"title": "title", "department": "department", "employee_type": "employeeType",
                "mfa_registered": "mfaRegistered", "user_access_status": "accountStatus"}
PAGE = 200  # 1,000 rows per page made Exabeam answer 500 on a wide table


def identity_tables(tables):
    """[(id, name, "profile" | "service")] for the non-empty tables that describe accounts."""
    out = []
    for t in tables:
        if not t.get("totalItems"):
            continue
        if any(PROFILE_COLUMN.match(a.get("displayName") or "") for a in t.get("attributes") or []):
            out.append((t["id"], t.get("name"), "profile"))
        elif SERVICE_TABLE.search(t.get("name") or ""):
            out.append((t["id"], t.get("name"), "service"))
    return out


def same_user(user, row):
    """True when a row is this account. Exact match on any identifier. A bare username (no @)
    also matches an email's local part. An email matches a bare username only on a row that
    holds no email, such as a service-account list: a directory that does list emails and lists
    another domain's is another account (an acquired company's jdoe@old.com is not jdoe@corp.com)."""
    want = user.lower().split("\\")[-1]
    ids = {str(x).lower().split("\\")[-1] for k, v in row.items() if ID_KEY.search(k)
           for x in (v if isinstance(v, list) else [v]) if x}
    local = want.split("@")[0]
    if want in ids:
        return True
    if "@" not in want:
        return local in {i.split("@")[0] for i in ids}
    return not any("@" in i for i in ids) and local in ids


def profile(row, table):
    out = {"table": table}
    for k, v in row.items():
        if (name := PROFILE_KEYS.get(re.sub(r"^u_", "", k.lower()))) and v not in (None, "", []):
            out[name] = v
    return out


async def _lookup(users):
    async def call(session, name, args):
        result = await session.call_tool(name, args)
        if (failure := error_text(result)) is not None:
            raise ValueError(failure)
        return json.loads(result.content[0].text)

    async def scan(session):
        found = {u: {"records": []} for u in users}
        unavailable = []
        listed = await call(session, "exabeam_context_table_list", {})
        for table_id, table, kind in identity_tables(listed if isinstance(listed, list) else find_first(listed, ("tables", "items")) or []):
            pending, offset = set(users), 0
            try:
                while pending:
                    page = await call(session, "exabeam_get_context_table_records",
                                      {"arg0": {"tableId": table_id, "limit": PAGE, "offset": offset}})
                    for row in page.get("records") or []:
                        for u in [u for u in pending if same_user(u, row)]:
                            pending.discard(u)
                            if kind == "service":
                                found[u]["serviceAccount"] = True
                            else:
                                found[u]["records"].append(profile(row, table))
                    offset += PAGE
                    if offset >= (page.get("paging") or {}).get("count", 0):
                        break
            except Exception as e:  # noqa: BLE001  one unreadable table must not lose the others
                log(f"lookup: table {table} could not be read: {e!r}")
                unavailable.append(f"entity context: table {table} could not be read")
        return {"entities": found, "unavailable": unavailable}

    print(json.dumps(await remote(scan)))


async def _serve():
    try:
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())
    finally:
        await UPSTREAM.drop()                          # one DELETE, at the end of the process


def log(message):
    """stderr is the only channel Claude Code keeps for a stdio server, so say why we stop."""
    sys.stderr.write(f"bridge[{os.getpid()}]: {message}\n")
    sys.stderr.flush()


def _stop_on(signum, _frame):
    log(f"received {signal.Signals(signum).name}, exiting")
    sys.exit(0)


def main():
    if not (URL and KEY and SECRET):
        log("exiting: missing credentials. Create ~/.exabeam-mcp.env with "
            "EXABEAM_MCP_URL, EXABEAM_API_KEY, EXABEAM_API_SECRET.")
        sys.exit(1)
    if "--closure" in sys.argv:
        asyncio.run(_then_drop(_closure(sys.argv[sys.argv.index("--closure") + 1:])))
        return
    if "--lookup" in sys.argv:
        asyncio.run(_then_drop(_lookup(sys.argv[sys.argv.index("--lookup") + 1:])))
        return
    if "--check" in sys.argv:
        asyncio.run(_then_drop(_check()))
        return
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, _stop_on)
    log(f"starting, connecting to {urlparse(URL).netloc}")
    try:
        asyncio.run(_serve())
    except Exception as e:  # noqa: BLE001  the server must say why it died
        log("exiting after an error: " + "; ".join(f"{type(x).__name__}: {x}" for x in leaf_errors(e)))
        sys.exit(1)
    log("the client closed the connection, exiting")


if __name__ == "__main__":
    main()
