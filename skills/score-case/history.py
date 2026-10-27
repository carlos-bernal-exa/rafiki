# /// script
# requires-python = ">=3.11"
# dependencies = ["neo4j>=5.20,<6"]
# ///
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Scoring history: an append-only JSONL store, projected into Neo4j for rule history.

  uv run history.py record   < record.json    # after scoring a case
  uv run history.py feedback --case N --label FP|TP --note "<why>" [--analyst NAME]
  uv run history.py context  < current.json   # rule history for a case being scored

Exabeam closure reasons are fetched here, through the bridge's --closure, never by the model:
the bridge strips them from everything the model reads, so a case cannot see its own answer.

The JSONL at $AISCORING_HOME/verdicts.jsonl (default ~/.aiscoring) is the source of truth.
Neo4j is a projection with AIScoring's schema plus the analyst's word on each case:

  (Rule)-[:FIRED_ON]->(Case)<-[:JUDGED]-(Verdict)
  (Case)-[:INVOLVES]->(Entity)
  (Feedback {label, note, analyst, at})-[:ON]->(Case)

A case's analyst label comes from analyst feedback when there is any, and from the Exabeam
closure reason only when there is not. Feedback carries the analyst's reasoning, which is what
makes an earlier case useful as a reference; a closure reason is one dropdown value.

`context` reports what ANALYSTS concluded on earlier cases where the same rules fired. Model
verdicts are kept for comparison but never counted: a past model false-positive call reused as
evidence for the next one would compound its own mistakes. The case being scored is always
excluded, so its own closure cannot leak into its score.
"""
import json
import os
import random
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

HOME = Path(os.environ.get("AISCORING_HOME", "~/.aiscoring")).expanduser()
STORE = HOME / "verdicts.jsonl"

# Closure reasons that state the disposition outright, from AIScoring eval/metrics.ts.
# ponytail: explicit reasons only. AIScoring also reads the closure narrative for ambiguous
# reasons ("Already Mitigated", "Resolved", "Other", "Low Risk"); those stay unlabelled here.
# Port its narrative rules if too many closures come back null.
FP_REASONS = [r"false positive", r"duplicate", r"benign", r"policy or setup", r"rule misconfiguration"]
TP_REASONS = [r"confirmed threat", r"malicious", r"true positive", r"high risk"]

EXAMPLES_PER_RULE = 5
REFRESH_PER_CONTEXT = 10  # unlabelled earlier cases whose closure is re-checked per lookup
BRIDGE = Path(__file__).resolve().parents[2] / "connector" / "exabeam-mcp-bridge.py"


def label_from_reason(reason):
    """Same order as AIScoring: FP reasons win, then TP. Ambiguous and unknown reasons are None,
    because a wrong label is worse than a missing one."""
    if any(re.search(p, reason or "", re.I) for p in FP_REASONS):
        return "FP"
    if any(re.search(p, reason or "", re.I) for p in TP_REASONS):
        return "TP"
    return None


# ---- store ----

def append(entry):
    # The store holds case numbers, rule names and user/host names from a live tenant.
    HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
    with os.fdopen(os.open(STORE, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600), "a") as f:
        f.write(json.dumps(entry) + "\n")


def load():
    """Latest verdict per (case, model), and per case the analyst outcome: the latest feedback
    if there is any, else the latest closure label."""
    verdicts, closures, feedback = {}, {}, {}
    if STORE.exists():
        for line in STORE.read_text().splitlines():
            if not line.strip():
                continue
            e = json.loads(line)
            if e["type"] == "verdict":
                verdicts[(e["caseNumber"], e.get("model", ""))] = e
            elif e["type"] == "label":
                closures[e["caseNumber"]] = {"label": e["label"], "source": "closure", "reason": e["reason"]}
            elif e["type"] == "feedback":
                feedback[e["caseNumber"]] = {"label": e["label"], "source": "analyst", "note": e.get("note"),
                                             "analyst": e.get("analyst")}
    outcomes = {}
    for case in closures.keys() | feedback.keys():
        outcomes[case] = {**closures.get(case, {}), **feedback.get(case, {})}
    return verdicts, outcomes


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def entity_ids(users, devices):
    return [f"user:{u}" for u in users or [] if u] + [f"device:{d}" for d in devices or [] if d]


# ---- closures ----

def fetch_closures(case_ids):
    """{caseId: {"stage", "closedReason"}} from Exabeam, or {} if the lookup fails. A failed
    lookup only means fewer labels; it must not stop a score from being recorded."""
    if not case_ids:
        return {}
    try:
        out = subprocess.run(["uv", "run", "--quiet", str(BRIDGE), "--closure", *case_ids],
                             capture_output=True, text=True, timeout=120, check=True)
        return json.loads(out.stdout)
    except (subprocess.SubprocessError, OSError, ValueError) as e:
        sys.stderr.write(f"closure lookup failed, continuing without it: {e}\n")
        return {}


def save_closures(case_numbers_by_id):
    """Fetch closures and append a label entry for each case that has a closure reason."""
    for case_id, closure in fetch_closures(list(case_numbers_by_id)).items():
        if closure.get("closedReason"):
            # quiet: this runs inside the model's session, and the case just scored must not show
            # its own outcome. Earlier cases reach the model through `context`, as counts.
            cmd_label(case_numbers_by_id[case_id], closure["closedReason"], quiet=True)


# ---- graph ----

def driver():
    from neo4j import GraphDatabase
    uri = os.environ.get("NEO4J_URI", "bolt://localhost:7688")
    auth = os.environ.get("NEO4J_AUTH") or _env_file().get("NEO4J_AUTH", "")
    if "/" not in auth:
        sys.exit(f"rule history unavailable: NEO4J_AUTH is not set, expected user/password in the environment or {HOME / 'neo4j.env'}")
    user, password = auth.split("/", 1)
    # OFF: the rebuild query names labels and properties that don't exist in an empty graph, and
    # the server's "unknown label" warnings otherwise fill the output the model reads.
    return GraphDatabase.driver(uri, auth=(user, password), notifications_min_severity="OFF")


def _env_file():
    p = HOME / "neo4j.env"
    if not p.exists():
        return {}
    return dict(line.split("=", 1) for line in p.read_text().split() if "=" in line)


def rebuild(session, verdicts, outcomes):
    """Wipe and rebuild from the store, as AIScoring does: a projection that is merged into can
    keep edges for superseded verdicts, and a stale edge looks current.
    ponytail: rebuilt on every `context` call. Fine for thousands of cases; switch to an
    incremental MERGE in `record` when a rebuild gets slow."""
    session.run("MATCH (n) DETACH DELETE n")
    session.run("CREATE INDEX rule_name IF NOT EXISTS FOR (r:Rule) ON (r.name)")
    session.run("CREATE INDEX case_number IF NOT EXISTS FOR (c:Case) ON (c.number)")
    rows = []
    for (case, model), v in verdicts.items():
        outcome = outcomes.get(case, {})
        rows.append({
            "number": case, "title": v.get("title"), "model": model, "ranAt": v["ranAt"],
            "verdict": v["verdict"]["verdict"], "confidence": v.get("confidence"),
            "analystVerdict": outcome.get("label"), "labelSource": outcome.get("source"),
            "closedReason": outcome.get("reason"), "note": outcome.get("note"), "analyst": outcome.get("analyst"),
            "rules": v.get("rules", []),
            "entities": [{"id": i, "kind": i.split(":", 1)[0], "value": i.split(":", 1)[1]}
                         for i in entity_ids(v.get("users"), v.get("devices"))],
        })
    session.run(
        """UNWIND $rows AS row
           MERGE (c:Case {number: row.number})
             SET c.title = row.title, c.analystVerdict = row.analystVerdict, c.labelSource = row.labelSource,
                 c.closedReason = row.closedReason, c.analystNote = row.note
           MERGE (v:Verdict {key: row.number + '|' + row.model})
             SET v.verdict = row.verdict, v.confidence = row.confidence, v.model = row.model, v.ranAt = row.ranAt
           MERGE (v)-[:JUDGED]->(c)
           FOREACH (_ IN CASE WHEN row.labelSource = 'analyst' THEN [1] ELSE [] END |
             MERGE (fb:Feedback {case: row.number})
               SET fb.label = row.analystVerdict, fb.note = row.note, fb.analyst = row.analyst
             MERGE (fb)-[:ON]->(c))
           FOREACH (r IN row.rules |
             MERGE (rule:Rule {name: r.name}) SET rule.severity = r.severity
             MERGE (rule)-[f:FIRED_ON]->(c) SET f.occurrences = r.occurrences)
           FOREACH (e IN row.entities |
             MERGE (ent:Entity {id: e.id}) SET ent.kind = e.kind, ent.value = e.value
             MERGE (c)-[:INVOLVES]->(ent))""",
        rows=rows,
    )


CONTEXT_QUERY = """
UNWIND $rules AS ruleName
MATCH (r:Rule {name: ruleName})-[:FIRED_ON]->(c:Case)
WHERE c.number <> $current
OPTIONAL MATCH (c)-[:INVOLVES]->(e:Entity) WHERE e.id IN $entities
WITH ruleName, c, collect(DISTINCT e.value) AS shared
WITH ruleName, collect({number: c.number, analyst: c.analystVerdict, source: c.labelSource, reason: c.closedReason,
                         note: c.analystNote, shared: shared}) AS cases
RETURN ruleName, cases
"""


def summarise(rule, cases):
    def counts(cs):
        return {"cases": len(cs),
                "analystFalsePositive": sum(c["analyst"] == "FP" for c in cs),
                "analystTruePositive": sum(c["analyst"] == "TP" for c in cs),
                "unlabelled": sum(c["analyst"] is None for c in cs)}
    same = [c for c in cases if c["shared"]]
    # True positives first (a past real incident on this rule is the example most worth seeing),
    # then cases with analyst feedback, since those say why, then shared entities.
    order = {"TP": 0, "FP": 1, None: 2}
    examples = sorted(cases, key=lambda c: (order[c["analyst"]], c.get("source") != "analyst",
                                            not c["shared"]))[:EXAMPLES_PER_RULE]
    return {
        "rule": rule,
        "allCases": counts(cases),
        "sameEntities": counts(same),
        "examples": [{k: v for k, v in {
            "case": c["number"], "analyst": c["analyst"], "labelFrom": c.get("source"),
            "analystNote": c.get("note"), "closedReason": c["reason"], "sharedEntities": c["shared"],
        }.items() if v is not None} for c in examples],
    }


# ---- commands ----

def cmd_record(data):
    for key in ("caseNumber", "caseId", "model", "verdict"):
        if key not in data:
            sys.exit(f"record needs {key}")
    data.pop("closedReason", None)  # closures come from fetch_closures only
    data["caseNumber"] = str(data["caseNumber"])
    append({"type": "verdict", "ranAt": now(), **data})
    print(f"recorded case {data['caseNumber']} in {STORE}")
    save_closures({data["caseId"]: data["caseNumber"]})


def cmd_label(case, reason, quiet=False):
    label = label_from_reason(reason)
    append({"type": "label", "at": now(), "caseNumber": case, "reason": reason, "label": label})
    if not quiet:
        print(f"case {case}: closedReason {reason!r} -> {label or 'unlabelled (ambiguous or unknown reason)'}",
              file=sys.stderr)


def cmd_feedback(case, label, note, analyst):
    label = label.upper()
    if label not in ("FP", "TP"):
        sys.exit("--label must be FP or TP")
    verdicts, _ = load()
    model_calls = [v["verdict"]["verdict"] for (c, _), v in verdicts.items() if c == case]
    append({"type": "feedback", "at": now(), "caseNumber": case, "label": label, "note": note, "analyst": analyst})
    if not model_calls:
        print(f"case {case}: feedback saved, but the case has no recorded score, so it has no rules "
              "in the graph yet. Score it, or it will not show up as history.")
        return
    expected = {"FP": "LIKELY_FALSE_POSITIVE", "TP": "LIKELY_TRUE_POSITIVE"}[label]
    agreed = sum(v == expected for v in model_calls)
    print(f"case {case}: analyst says {label}; saved. Model agreed on {agreed} of {len(model_calls)} recorded score(s).")


def cmd_context(data):
    current = str(data["caseNumber"])
    verdicts, outcomes = load()
    # Earlier cases that were open when scored may have closed since. Never the current case.
    pending = {v["caseId"]: c for (c, _), v in verdicts.items()
               if c != current and c not in outcomes and v.get("caseId")}
    # A random pick, so cases that stay open can't keep the rest from ever being checked.
    # ponytail: stateless; track last-checked per case if the pending set grows far past the limit.
    picked = random.sample(list(pending), min(len(pending), REFRESH_PER_CONTEXT))
    save_closures({case_id: pending[case_id] for case_id in picked})
    verdicts, outcomes = load()
    from neo4j.exceptions import Neo4jError, ServiceUnavailable
    try:
        with driver() as d, d.session() as s:
            rebuild(s, verdicts, outcomes)
            records = s.run(CONTEXT_QUERY, rules=data.get("rules", []), current=current,
                            entities=entity_ids(data.get("users"), data.get("devices"))).data()
    except (ServiceUnavailable, Neo4jError, OSError) as e:
        sys.exit(f"rule history unavailable: {e}")
    found = {r["ruleName"]: summarise(r["ruleName"], r["cases"]) for r in records}
    print(json.dumps({
        "storedCases": len({c for c, _ in verdicts}),
        "rules": [found.get(name, {"rule": name, "allCases": {"cases": 0}}) for name in data.get("rules", [])],
    }, indent=2))


def main(argv):
    if not argv or argv[0] not in ("record", "feedback", "context"):
        sys.exit(__doc__)
    arg = lambda flag, default=None: argv[argv.index(flag) + 1] if flag in argv else default  # noqa: E731
    if argv[0] == "feedback":
        if not arg("--case") or not arg("--label"):
            sys.exit("feedback needs --case and --label")
        cmd_feedback(arg("--case"), arg("--label"), arg("--note", ""), arg("--analyst", os.environ.get("USER")))
    elif argv[0] == "record":
        cmd_record(json.load(sys.stdin))
    else:
        cmd_context(json.load(sys.stdin))


if __name__ == "__main__":
    main(sys.argv[1:])
