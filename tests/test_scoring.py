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
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "skills" / "score-case"))
from scoring import confidence, plan, stage_count, validate  # noqa: E402

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
    assert json.loads((ROOT / ".mcp.json").read_text())["mcpServers"]["exabeam"]["args"][-1].endswith("exabeam-mcp-bridge.py")


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
            if (isinstance(n, ast.FunctionDef) and n.name in ("strip_labels", "find_first", "unlabel_text"))
            or (isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") in ("LABEL_FIELDS", "READ_TOOLS"))]
    ns = {"json": json}
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
