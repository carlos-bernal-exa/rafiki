<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# aiscoring

A Claude Code plugin that scores Exabeam New-Scale cases. Give it a case number and it pulls the
threat timeline, a sample of raw logs and entity context through the Exabeam MCP. It returns
`LIKELY_TRUE_POSITIVE`, `INVESTIGATE` or `LIKELY_FALSE_POSITIVE`, with a confidence computed from
the evidence.

It is read-only. It never updates, closes or annotates anything in Exabeam.

## Where it comes from

The method is AIScoring's `deep-investigation` prompt (`AIScoring/server/prompts/deep-investigation.md`),
moved from a web app into a skill that gathers its own evidence. The Exabeam bridge comes from socxen.

| Piece | Source | Here |
|---|---|---|
| Investigation method | AIScoring `deep-investigation.md` | `skills/score-case/SKILL.md` |
| Verdict shape | AIScoring `verdict-schema.ts` | JSON in `SKILL.md`, checked by `scoring.py confidence` |
| Computed confidence | AIScoring `confidence.ts` | `scoring.py confidence` |
| Raw-log sampling (10 per rule, 50 searches, 100 lines) | AIScoring `planRawLogSearches` | `scoring.py plan` |
| Rule/case/entity graph | AIScoring `graph.ts` | `history.py` |
| Closure reason to FP/TP | AIScoring `eval/metrics.ts` (explicit reasons only) | `history.py` |
| Exabeam MCP bridge, Unicode canonicalizer | socxen `plugin/connector/` | `connector/` |

The Python port gives the same results as the TypeScript. I ran both on 18 verdicts and 7
sampling timelines and every value matched. The coefficients in `scoring.py` were tuned in
AIScoring against analyst closures, so retune them there and copy them over.

## How it differs from socxen

socxen investigates and then acts: it opens cases, writes notes, and dismisses alerts once you
approve. aiscoring only scores. The bridge has an allowlist of 16 read tools. Write tools don't
appear in `list_tools`, and `call_tool` refuses them, so no prompt can make it change a case.
That is also why the permission pack, the write-side neutralizer and the audit log were left
out. The allowlist does what they did.

Two habits carried over from AIScoring matter for accuracy:

- The skill ignores `stage`, `closedReason`, the assignee and case notes. A closed case carries
  the analyst's verdict, and a score that reads it is copying the answer.
- The model's own `confidence` gets reported as `selfReported` and nothing else. The number shown
  comes from the indicators, the tactic or source count, evidence gaps, and sources that failed
  to load.

## Rule history

Every score is appended to `~/.aiscoring/verdicts.jsonl`. So is the analyst's call on a case.
After a score, the analyst can say "this is a false positive, it's the nightly backup job" and
the skill saves the label and the reason as feedback:

```bash
uv run skills/score-case/history.py feedback --case 5968 --label FP --note "nightly Veeam backup, CHG-1182"
```

Feedback is the main label. The Exabeam closure reason is saved too, but it only labels a case
that has no feedback, because a dropdown value doesn't say why and the analyst's note does. A
later call replaces an earlier one. The skill saves feedback only when the analyst states it,
never from case fields or log text. When the next case comes in, `history.py context` rebuilds a
Neo4j graph from that file, using AIScoring's schema, and asks: on earlier cases where these
rules fired, what did analysts conclude, and why? It asks for all earlier cases and for those
that share this case's users or devices, and returns the analysts' notes with the examples.

Three rules keep the history honest:

- It counts analyst feedback and closures only. Earlier model verdicts are stored but never counted, so one
  wrong false-positive call can't become evidence for the next.
- It leaves out the case being scored, so the case's own closure can't leak into its score.
- History never enters the computed confidence. The skill treats it as a prior to test against
  this case's logs, not as an indicator.

AIScoring's graph only feeds its tuning page. Using history while a case is being scored is new
in this plugin.

Closure reasons map to FP or TP with AIScoring's explicit-reason lists. Ambiguous reasons such as
"Already Mitigated / Resolved" or "Low Risk" stay unlabelled, because AIScoring decides those by
reading the closure narrative and that part isn't ported yet.

The JSONL is the source of truth. The graph is wiped and rebuilt on every query, so you can
delete it at any time. If Neo4j is down, scoring continues and the report says history was
unavailable.

Neo4j runs in its own container on 127.0.0.1:7475 (browser) and 127.0.0.1:7688 (bolt), apart
from AIScoring's 7474/7687. Both tools wipe their database on rebuild, so sharing one container
would erase each other's data.

```bash
mkdir -p ~/.aiscoring && echo "NEO4J_AUTH=neo4j/<a long password>" > ~/.aiscoring/neo4j.env
NEO4J_AUTH=neo4j/<same password> docker compose up -d
```

## Install

Credentials live in `~/.exabeam-mcp.env`, the same file socxen uses:

```
EXABEAM_MCP_URL=https://api.<region>.exabeam.cloud/mcp
EXABEAM_API_KEY=...
EXABEAM_API_SECRET=...
```

Check the connection:

```bash
uv run connector/exabeam-mcp-bridge.py --check
```

Install it from this checkout. The repo is its own marketplace, and the install reads the
plugin straight from this folder, so edits show up after a restart:

```bash
claude plugin marketplace add /path/to/aiscoring-plugin
claude plugin install aiscoring@aiscoring
```

Or load it for one session only:

```bash
claude --plugin-dir /path/to/aiscoring-plugin
```

Then ask it to "score case 5968".

## Tests

```bash
uv run --with pytest pytest -q tests/
```
