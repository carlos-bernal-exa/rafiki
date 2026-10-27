<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# aiscoring

A Claude Code plugin that scores Exabeam New-Scale cases. Give it a case number and it pulls the
case, its threat timeline and a sample of raw logs through the Exabeam MCP. It returns
`LIKELY_TRUE_POSITIVE`, `INVESTIGATE` or `LIKELY_FALSE_POSITIVE`, with a confidence computed from
the evidence.

It is read-only. It never updates, closes or annotates anything in Exabeam.

## Where it comes from

The reasoning is AIScoring's `deep-investigation` prompt, copied unchanged to
`skills/score-case/reference/deep-investigation.md`. A test fails if it drifts from the AIScoring
checkout next to this repo. `SKILL.md` only adds what a web app's code did before the model ran:
gathering the evidence, plus a table mapping the prompt's payload names to what was gathered.
The Exabeam bridge comes from socxen.

| Piece | Source | Here |
|---|---|---|
| Investigation prompt (verbatim) | AIScoring `deep-investigation.md` | `skills/score-case/reference/` |
| Evidence gathering | AIScoring `exabeam.ts`, `scoring.ts` `buildPayload` | `skills/score-case/SKILL.md` |
| Hiding the disposition | AIScoring `stripLabels` | the bridge's `strip_labels` |
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
approve. aiscoring only scores. The bridge has an allowlist of 15 read tools. Write tools don't
appear in `list_tools`, and `call_tool` refuses them, so no prompt can make it change a case.
That is also why the permission pack, the write-side neutralizer and the audit log were left
out. The allowlist does what they did.

Where it differs from AIScoring:

- **The model gathers the evidence.** In AIScoring, code fetches the case and logs before the
  model runs. Here the model calls the MCP tools itself, following `SKILL.md`.
- **The bridge hides the answer.** AIScoring's code strips stage, closure, queue and assignee
  before the model sees a case. Here the bridge strips the same keys, plus status fields, from
  every case and alert result, and doesn't expose case notes. A result it can't parse as JSON is
  withheld, not passed through. Closure reasons for the history are fetched by `history.py`
  through `exabeam-mcp-bridge.py --closure`, outside the model's view.
- **Raw logs use AIScoring's fields.** Each detection's own `search_query`, keeping `rawLogs`
  (the original log line, where finding fields like `indicators` and `riskState` live), the
  timestamp and vendor/product.
- **No entity context.** The MCP has no entity lookup, so roles, departments and service-account
  flags aren't available. The skill handles that the way AIScoring handles a prompt variant that
  omits a section: it tells the model the section is withheld on purpose, and it doesn't count as
  a missing source, so confidence isn't marked down for it on every case.
- **The model is whichever Claude model the session runs.** AIScoring's default for this prompt
  is `gemini-3.8-flash`, so the same prompt may score differently here.

One habit carried over unchanged:

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

You need Claude Code, [uv](https://docs.astral.sh/uv/) and an Exabeam New-Scale API key and secret.

```bash
git clone <repo-url> aiscoring-plugin && cd aiscoring-plugin
./install.sh
```

The script asks for your MCP URL, key and secret and saves them to `~/.exabeam-mcp.env` (mode
600). It checks the connection, then installs the plugin. Restart Claude Code and ask it to
"score case 5968".

Once the repo is published, Claude Code 2.1.275 or later installs it in one line, though you
still need the credentials file from `./install.sh`:

```
/plugin install aiscoring --marketplace <org>/<repo>
```

Rule history needs Neo4j in Docker. Add `--with-history` and the script generates a password,
saves it to `~/.aiscoring/neo4j.env` and starts the container. Scoring works without it.

`./install.sh --check` tests an existing install and changes nothing. To try the plugin for one
session without installing, run `claude --plugin-dir /path/to/aiscoring-plugin`.

## Guardrails

- **Read-only.** The bridge exposes 15 read tools. Anything else is hidden from the tool list and
  refused if called.
- **Blind scoring.** The bridge removes the analyst's disposition from case and alert results,
  using a list of known field names plus a pattern that catches names it has not seen (anything
  with "close", "closure", "resolution", "disposition" or "false positive" in the key). Free text
  is not scanned, so a note typed into a description can still reach the model. A result that is
  not JSON is withheld.
- **Local data.** `~/.aiscoring/verdicts.jsonl` holds case numbers, rule names and user and host
  names from your tenant. The directory is created with mode 700 and the file with mode 600.
  Nothing leaves your machine except the Exabeam calls and the model session itself.
- **Untrusted logs.** The skill tells the model to treat text inside logs as evidence, never as an
  instruction.

## Tests

```bash
uv run --with pytest --with neo4j pytest -q tests/
```
