# /// script
# requires-python = ">=3.11"
# dependencies = ["pytest>=8.0"]
# ///
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Checks for the deterministic parts: confidence, raw-log sampling, and the read-only bridge.

Run:  uv run --with pytest --with neo4j pytest -q tests/
"""
import ast
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "skills" / "score-case"))
from scoring import confidence, plan, plan_timeline, stage_count, validate  # noqa: E402

BASE = {"summary": "s", "reasoning": [], "recommendedActions": [], "whatWouldChangeMyMind": [],
        "devilsAdvocate": {"argument": "a", "rebuttal": "r"}}


def v(**kw):
    return {**BASE, "falsePositiveIndicators": [], "truePositiveIndicators": [], **kw}


# Expected values come from AIScoring's computeConfidence on the same inputs.
def test_matches_aiscoring():
    chained = v(verdict="LIKELY_TRUE_POSITIVE", truePositiveIndicators=["a", "b", "c"], falsePositiveIndicators=["x"],
                stages=["execution", "persistence", "discovery", "reconnaissance"], evidenceGaps=["g"], confidence=0.9)
    assert confidence(chained)["value"] == 0.9
    assert confidence(chained, 1)["value"] == 0.86
    assert confidence(chained, 3)["value"] == 0.82
    four_sources = v(verdict="LIKELY_FALSE_POSITIVE", falsePositiveIndicators=["x"], stages=["credentialAccess"],
                     corroboratingSources=["Okta", "Microsoft 365", "Azure AD", "Proofpoint"], evidenceGaps=list("abcd"))
    assert confidence(four_sources)["value"] == 0.25


def test_recon_and_discovery_are_one_step():
    assert stage_count(["reconnaissance", "discovery"]) == 1
    assert stage_count(["discovery", "collection", "exfiltration", "impact"]) == 4


def test_abstention_is_capped():
    out = confidence(v(verdict="INVESTIGATE", truePositiveIndicators=["a"] * 9))
    assert out["value"] <= 0.6


def test_doubt_never_flips_a_reading():
    weak = v(verdict="LIKELY_TRUE_POSITIVE", truePositiveIndicators=["a"], stages=["execution"], evidenceGaps=list("abcdef"))
    assert confidence(weak, 5)["value"] >= 0.5


def test_self_report_is_ignored_but_recorded():
    a = confidence(v(verdict="LIKELY_FALSE_POSITIVE", falsePositiveIndicators=["x"], confidence=0.99))
    b = confidence(v(verdict="LIKELY_FALSE_POSITIVE", falsePositiveIndicators=["x"], confidence=0.1))
    assert a["value"] == b["value"] and a["overconfidence"] > 0
    assert confidence(v(verdict="LIKELY_FALSE_POSITIVE", confidence=95))["selfReported"] == 0.95


def test_validate_requires_devils_advocate():
    bad = v(verdict="INVESTIGATE")
    del bad["devilsAdvocate"]
    assert any("devilsAdvocate" in e for e in validate(bad))
    assert validate(v(verdict="NOPE", stages=["hacking"])) and not validate(v(verdict="INVESTIGATE"))


def test_plan_samples_each_rule_and_shares_the_cap():
    busy = plan([{"rule": "A"}] * 25 + [{"rule": "B"}] * 2)
    assert len(busy["pick"]) == 12 and busy["pick"][0] == 0 and 24 in busy["pick"]  # first and last of A
    many = plan([{"rule": f"R{i}"} for i in range(55)])
    assert len(many["pick"]) == 50 and many["gaps"] == ["raw logs: 5 of 55 rules had no logs pulled, the search limit was reached"]


def test_bridge_is_read_only():
    tree = ast.parse((ROOT / "connector" / "exabeam-mcp-bridge.py").read_text())
    node = next(n for n in ast.walk(tree) if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "READ_TOOLS")
    tools = {e.value for e in node.value.args[0].elts}
    writes = {"exabeam_update_alert", "exabeam_update_case", "exabeam_create_case", "exabeam_create_case_notes"}
    assert tools and not tools & writes
    assert json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text())["mcpServers"]["exabeam"]["args"][-1].endswith("exabeam-mcp-bridge.py")


from history import label_from_reason, summarise  # noqa: E402


def test_closure_labels_match_aiscoring_explicit_reasons():
    assert label_from_reason("False Positive or Duplicate") == "FP"
    assert label_from_reason("Benign True Positive") == "FP"  # benign wins, as in AIScoring
    assert label_from_reason("Confirmed Threat") == "TP"
    assert label_from_reason("Already Mitigated / Resolved") is None
    assert label_from_reason("Low Risk") is None and label_from_reason("") is None


def test_history_puts_past_true_positives_first():
    cases = [{"number": str(i), "analyst": "FP", "reason": "fp", "shared": []} for i in range(6)]
    cases.append({"number": "99", "analyst": "TP", "reason": "Confirmed Threat", "shared": ["alice"]})
    out = summarise("R", cases)
    assert out["examples"][0]["case"] == "99" and len(out["examples"]) == 5
    assert out["allCases"] == {"cases": 7, "analystFalsePositive": 6, "analystTruePositive": 1, "unlabelled": 0}
    assert out["sameEntities"]["cases"] == 1


def test_analyst_feedback_outranks_closure_whatever_the_order(tmp_path, monkeypatch):
    import history
    monkeypatch.setattr(history, "HOME", tmp_path)
    monkeypatch.setattr(history, "STORE", tmp_path / "verdicts.jsonl")
    history.append({"type": "feedback", "caseNumber": "1", "label": "FP", "note": "backup job"})
    history.append({"type": "label", "caseNumber": "1", "reason": "Confirmed Threat", "label": "TP"})
    history.append({"type": "label", "caseNumber": "2", "reason": "False Positive", "label": "FP"})
    _, outcomes = history.load()
    assert outcomes["1"]["label"] == "FP" and outcomes["1"]["source"] == "analyst"
    assert outcomes["1"]["note"] == "backup job" and outcomes["1"]["reason"] == "Confirmed Threat"
    assert outcomes["2"] == {"label": "FP", "source": "closure", "reason": "False Positive"}


# ---- the three fixes: verbatim prompt, labels stripped in the bridge, closures out of view ----

def _bridge_functions():
    """The bridge's pure helpers, without importing mcp/httpx."""
    tree = ast.parse((ROOT / "connector" / "exabeam-mcp-bridge.py").read_text())
    keep = [n for n in tree.body
            if (isinstance(n, ast.FunctionDef) and n.name in ("strip_labels", "find_first", "unlabel_text", "leaf_errors", "retry_delay", "error_text"))
            or (isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") in ("LABEL_FIELDS", "LABEL_PATTERN", "READ_TOOLS"))]
    ns = {"json": json, "re": re, "httpx": __import__("httpx")}
    exec(compile(ast.Module(body=keep, type_ignores=[]), "bridge", "exec"), ns)
    return ns


def test_prompt_is_aiscoring_verbatim():
    import pytest
    source = ROOT.parent / "AIScoring" / "server" / "prompts" / "deep-investigation.md"
    if not source.exists():
        pytest.skip("AIScoring checkout not next to this repo")
    assert (ROOT / "skills" / "score-case" / "reference" / "deep-investigation.md").read_bytes() == source.read_bytes()


def test_bridge_strips_the_disposition_and_hides_notes():
    b = _bridge_functions()
    case = {"case_number": 5968, "Stage": "CLOSED", "closed_reason": "False Positive", "assignee": "x",
            "case_close_supporting_reason": "benign", "rules": [{"name": "R", "status": "closed"}], "title": "t"}
    out = json.loads(b["unlabel_text"](json.dumps(case)))
    assert out == {"case_number": 5968, "rules": [{"name": "R"}], "title": "t"}
    assert "withheld" in b["unlabel_text"]("Case 5968 closed as False Positive")  # fail closed
    assert "exabeam_get_case_notes" not in b["READ_TOOLS"]
    assert b["find_first"]({"data": [{"x": 1}, {"closed_reason": "Benign"}]}, ("closed_reason",)) == "Benign"


def test_bridge_strips_the_camelcase_disposition_this_tenant_returns():
    b = _bridge_functions()
    case = {"caseNumber": 6795, "closedReason": "False Positive", "supportingReason": "backup job",
            "caseClosedTimestamp": "2026-10-26T15:17:06", "lastModifiedBy": "an.analyst",
            "alertDescription": "False Positive: it was the backup job", "alertName": "t", "riskScore": 90,
            "detections": [{"lastModifiedBy": "system", "name": "R"}]}
    out = json.loads(b["unlabel_text"](json.dumps(case)))
    assert out == {"caseNumber": 6795, "alertName": "t", "riskScore": 90, "detections": [{"name": "R"}]}


def test_record_does_not_print_the_closure_it_just_fetched(tmp_path, monkeypatch, capsys):
    import history
    monkeypatch.setattr(history, "HOME", tmp_path)
    monkeypatch.setattr(history, "STORE", tmp_path / "verdicts.jsonl")
    monkeypatch.setattr(history, "fetch_closures", lambda ids: {i: {"closedReason": "False Positive"} for i in ids})
    history.cmd_record({"caseNumber": 7, "caseId": "id-7", "model": "m", "verdict": {"verdict": "INVESTIGATE"}})
    seen = capsys.readouterr()
    assert "False Positive" not in seen.out + seen.err
    assert '"label": "FP"' in (tmp_path / "verdicts.jsonl").read_text()  # still saved, just not shown


def test_record_ignores_a_closure_from_the_model_and_refresh_skips_the_current_case(tmp_path, monkeypatch):
    import history
    monkeypatch.setattr(history, "HOME", tmp_path)
    monkeypatch.setattr(history, "STORE", tmp_path / "verdicts.jsonl")
    asked = []
    monkeypatch.setattr(history, "fetch_closures", lambda ids: asked.append(list(ids)) or {
        i: {"closedReason": "False Positive"} for i in ids})
    history.cmd_record({"caseNumber": 1, "caseId": "id-1", "model": "m", "verdict": {"verdict": "INVESTIGATE"},
                        "closedReason": "made up by the model"})
    history.cmd_record({"caseNumber": 2, "caseId": "id-2", "model": "m", "verdict": {"verdict": "INVESTIGATE"}})
    lines = [json.loads(x) for x in (tmp_path / "verdicts.jsonl").read_text().splitlines()]
    assert all("closedReason" not in x for x in lines if x["type"] == "verdict")
    assert asked == [["id-1"], ["id-2"]]
    # Unlabel both, then look up history for case 2: only case 1's closure may be fetched.
    (tmp_path / "verdicts.jsonl").write_text("".join(json.dumps(x) + "\n" for x in lines if x["type"] != "label"))
    asked.clear()
    from neo4j.exceptions import ServiceUnavailable

    def no_graph():
        raise ServiceUnavailable("stubbed")
    monkeypatch.setattr(history, "driver", no_graph)
    import pytest
    with pytest.raises(SystemExit, match="rule history unavailable"):
        history.cmd_context({"caseNumber": "2", "rules": ["R"]})
    assert asked == [["id-1"]]


def test_closure_refresh_reaches_every_open_case_and_missing_auth_reads_as_unavailable(tmp_path, monkeypatch):
    import pytest
    import history
    monkeypatch.setattr(history, "HOME", tmp_path)
    monkeypatch.setattr(history, "STORE", tmp_path / "verdicts.jsonl")
    monkeypatch.delenv("NEO4J_AUTH", raising=False)
    for n in range(1, 16):
        history.append({"type": "verdict", "caseNumber": str(n), "caseId": f"id-{n}", "model": "m"})
    asked = []
    monkeypatch.setattr(history, "fetch_closures", lambda ids: asked.append(list(ids)) or {})
    for _ in range(30):
        with pytest.raises(SystemExit, match="rule history unavailable: NEO4J_AUTH"):
            history.cmd_context({"caseNumber": "15", "rules": ["R"]})
    assert all(len(batch) == history.REFRESH_PER_CONTEXT and "id-15" not in batch for batch in asked)
    assert {i for batch in asked for i in batch} == {f"id-{n}" for n in range(1, 15)}


def test_bridge_drops_disposition_keys_it_has_never_seen():
    """The strip list is a denylist, so a tenant that names the field differently must not leak."""
    b = _bridge_functions()
    case = {"caseNumber": 1, "closureNote": "x", "caseClosedBy": "a", "resolutionCode": "b",
            "dispositionText": "c", "caseAssignmentTimestamp": "t", "queueName": "q", "caseStatusChangedAt": "t", "markedFalsePositive": True, "false_positive_flag": 1,
            "riskScore": 9, "detections": [{"name": "R", "mitre": ["T1053"]}]}
    out = json.loads(b["unlabel_text"](json.dumps(case)))
    assert out == {"caseNumber": 1, "riskScore": 9, "detections": [{"name": "R", "mitre": ["T1053"]}]}


def test_history_store_is_private(tmp_path, monkeypatch):
    import history
    monkeypatch.setattr(history, "HOME", tmp_path / "h")
    monkeypatch.setattr(history, "STORE", tmp_path / "h" / "verdicts.jsonl")
    history.append({"type": "feedback", "caseNumber": "1", "label": "FP", "note": "n"})
    assert (tmp_path / "h").stat().st_mode & 0o077 == 0
    assert (tmp_path / "h" / "verdicts.jsonl").stat().st_mode & 0o077 == 0


def test_bridge_retries_rate_limits_and_unwraps_task_group_errors():
    import httpx
    b = _bridge_functions()
    limited = httpx.HTTPStatusError("429", request=httpx.Request("POST", "https://x"),
                                    response=httpx.Response(429, headers={"Retry-After": "3"}))
    nested = BaseExceptionGroup("g", [ExceptionGroup("inner", [limited])])
    assert b["leaf_errors"](nested) == [limited]
    assert b["retry_delay"](nested, 0) == 3
    unheaded = httpx.HTTPStatusError("429", request=limited.request, response=httpx.Response(429))
    assert b["retry_delay"](ExceptionGroup("g", [unheaded]), 2) == 4
    assert b["retry_delay"](ExceptionGroup("g", [ValueError("no")]), 0) is None


def _run_bridge(tmp_path, env_file):
    import os
    import shutil
    import subprocess
    import pytest
    if not shutil.which("uv"):
        pytest.skip("uv not installed")
    (tmp_path / ".exabeam-mcp.env").write_text(env_file)
    env = {**os.environ, "HOME": str(tmp_path)}
    return subprocess.Popen(["uv", "run", "--quiet", str(ROOT / "connector" / "exabeam-mcp-bridge.py")],
                            env=env, stdin=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def test_bridge_says_why_it_exits_without_credentials(tmp_path):
    proc = _run_bridge(tmp_path, "")
    _, err = proc.communicate(timeout=60)
    assert proc.returncode == 1 and "missing credentials" in err


def test_bridge_logs_its_exit_when_the_client_goes_away_or_it_is_stopped(tmp_path):
    import signal
    creds = "EXABEAM_MCP_URL=https://example.invalid/mcp\nEXABEAM_API_KEY=k\nEXABEAM_API_SECRET=s\n"
    closed = _run_bridge(tmp_path, creds)
    _, err = closed.communicate(timeout=60)  # stdin closes: the client went away
    assert closed.returncode == 0 and "starting" in err and "client closed the connection" in err
    stopped = _run_bridge(tmp_path, creds)
    stopped.stderr.readline()  # wait for "starting" so the handler is installed
    stopped.send_signal(signal.SIGTERM)
    _, err = stopped.communicate(timeout=60)
    assert "received SIGTERM" in err


def test_bridge_retries_dropped_sessions_but_not_refusals():
    b = _bridge_functions()

    class McpError(Exception):
        pass

    class BrokenResourceError(Exception):
        pass

    assert b["retry_delay"](ExceptionGroup("g", [BrokenResourceError()]), 1) == 2
    assert b["retry_delay"](McpError("Session terminated"), 0) == 1
    assert b["retry_delay"](McpError("Invalid params"), 0) is None
    assert b["retry_delay"](PermissionError("403"), 0) is None


def test_bridge_shows_the_exabeam_error_instead_of_withholding_it():
    from types import SimpleNamespace as NS
    b = _bridge_functions()
    failed = NS(isError=True, content=[NS(text="404 case not found: 6785"), NS(text=None)])
    assert b["error_text"](failed) == "Exabeam returned an error: 404 case not found: 6785"
    assert b["error_text"](NS(isError=True, content=[NS(text="x" * 900)])).endswith("x" * 500)
    assert b["error_text"](NS(isError=False, content=[NS(text="{}")])) is None


def _detection(rule, n, filter_="id: \"a\"", start="2026-10-23T07:06:57.376", end="2026-10-23T07:08:57.376"):
    dto = {"detectionId": f"d{n}", "approxLogTime": f"2026-10-23T07:{n:02d}:00",
           "rules": [{"ruleName": r} for r in rule]}
    if filter_:
        dto["searchQuery"] = {"eventFilter": filter_, "eventFromTimeMillis": start, "eventToTimeMillis": end}
    return {"type": "detection", "alertCaseDetectionDto": dto}


def test_plan_timeline_builds_the_searches_so_the_model_copies_instead_of_converting():
    page1 = {"threatTimelines": [_detection(["B", "A"], 1), _detection(["B", "A"], 2, filter_="")]}
    page2 = {"threatTimelines": [_detection(["C"], 3, start="2026-10-23T07:00:00+00:00")]}
    out = plan_timeline([page1, page2])
    assert [s["detection"] for s in out["searches"]] == ["d1", "d3"]  # d2 has no search_query
    first, second = (s["arg0"] for s in out["searches"])
    assert first == {"filter": 'id: "a"', "startTime": "2026-10-23T07:06:57.376Z", "endTime": "2026-10-23T07:08:57.376Z",
                     "fields": ["rawLogs", "activity", "event_name", "outcome", "vendor", "product", "approxLogTime", "time"],
                     "orderBy": ["approxLogTime DESC"], "limit": 50}
    assert second["startTime"] == "2026-10-23T07:00:00+00:00"  # a zone is left alone
    assert out["timeline"] == {"detections": 3, "shown": 3, "note": None}


def test_plan_timeline_keeps_the_newest_fifty_and_says_so():
    page = {"threatTimelines": [_detection(["R"], n % 60, filter_="") for n in range(60)]}
    out = plan_timeline([page])
    assert out["timeline"]["shown"] == 50 and out["timeline"]["detections"] == 60
    assert out["timeline"]["note"] == "The timeline holds the 50 most recent of 60 detections. Earlier detections exist but are not shown."
