# /// script
# requires-python = ">=3.11"
# ///
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Deterministic arithmetic for score-case, ported from AIScoring (server/confidence.ts,
server/exabeam.ts planRawLogSearches). The model gathers evidence and writes the verdict;
this script does the parts a model gets wrong by hand.

  uv run scoring.py plan        < detections.json   # which detections to pull raw logs for
  uv run scoring.py confidence  [--unavailable N] < verdict.json

`plan` input:  [{"rule": "<rule name(s)>"}, ...] in timeline order (other keys are ignored).
`plan` output: {"pick": [indices], "sampling": [...], "gaps": [...]}.

`confidence` prints the computed confidence and the factors behind it. The verdict's own
`confidence` field is reported as `selfReported` but never used.
"""
import json
import math
import sys

# ---- raw-log sampling (planRawLogSearches) ----

DETECTION_CAP = 50      # detections searched per case; each is one search
SAMPLES_PER_RULE = 10   # a rule firing again yields the same kind of log


def evenly_spaced(length, count):
    if count <= 1:
        return [0]
    # floor(x + .5), not round(): Python rounds half to even, AIScoring (JS) rounds half up.
    return sorted({math.floor(i * (length - 1) / (count - 1) + 0.5) for i in range(count)})


def plan(detections):
    by_rule = {}
    for i, d in enumerate(detections):
        by_rule.setdefault(d.get("rule") or "unnamed detection", []).append(i)

    # Fair share of the cap, smallest rules first, so unused share flows to busier rules.
    share, left = {}, DETECTION_CAP
    ordered = sorted(by_rule.items(), key=lambda kv: len(kv[1]))
    for n, (rule, found) in enumerate(ordered):
        share[rule] = min(SAMPLES_PER_RULE, len(found), left // (len(ordered) - n))
        left -= share[rule]

    pick, sampling, skipped = [], [], 0
    for rule, found in by_rule.items():
        room = share[rule]
        if room == 0:
            skipped += 1
            continue
        chosen = [found[i] for i in evenly_spaced(len(found), room)]
        pick.extend(chosen)
        if len(found) > 1:
            sampling.append(
                f'"{rule}" fired {len(found)} times; logs pulled for {len(chosen)} of them, spread first to last, since the rest repeat the same rule'
                if len(found) > len(chosen) else f'"{rule}" fired {len(found)} times; logs pulled for all of them')
    gaps = [f"raw logs: {skipped} of {len(by_rule)} rules had no logs pulled, the search limit was reached"] if skipped else []
    return {"pick": sorted(pick), "sampling": sampling, "gaps": gaps}


# ---- confidence (computeConfidence) ----

VERDICTS = ("LIKELY_TRUE_POSITIVE", "INVESTIGATE", "LIKELY_FALSE_POSITIVE")
TACTICS = {
    "reconnaissance", "resourceDevelopment", "initialAccess", "execution", "persistence",
    "privilegeEscalation", "defenseEvasion", "credentialAccess", "discovery", "lateralMovement",
    "collection", "commandAndControl", "exfiltration", "impact",
}
# Likelihood ratios. Calibrated in AIScoring against analyst closures; retune there, not here.
LR_NONE, LR_SINGLE, LR_PARTIAL, LR_COHERENT = 0.45, 1.0, 2.5, 6.0
LR_AGREE, MAX_AGREE = 1.3, 5
LR_OPPOSE, MAX_OPPOSE = 1 / 1.3, 4
PER_GAP, MAX_GAPS = 1.15, 3
PER_UNAVAILABLE, MAX_UNAVAILABLE = 1.4, 2
PRIOR, ABSTENTION_CAP, FLOOR, CEILING = 0.5, 0.6, 0.05, 0.95


def stage_count(stages):
    present = set(stages or [])
    looking = bool(present & {"reconnaissance", "discovery"})  # both are "looking around"
    return len(present - {"reconnaissance", "discovery"}) + looking


def source_count(sources):
    return len({s.strip().lower() for s in sources or [] if s.strip()})


def corroboration(stages, sources):
    if stages is None and source_count(sources) == 0:
        return 1.0, "corroboration not assessed, no tactics or sources recorded"
    by_stage, by_source = stage_count(stages), max(0, source_count(sources) - 1)
    if by_source > by_stage:
        strength, of = by_source, f"{source_count(sources)} independent sources ({', '.join(dict.fromkeys(sources))})"
    else:
        strength = by_stage
        of = f"{strength} distinct tactic{'' if strength == 1 else 's'}" + (f" ({', '.join(dict.fromkeys(stages))})" if stages else "")
    if strength >= 3:
        return LR_COHERENT, f"{of}: coherent progression"
    if strength == 2:
        return LR_PARTIAL, f"{of}: partial pattern"
    if strength == 1:
        return LR_SINGLE, f"{of}: worth a closer look"
    return LR_NONE, f"{of}: isolated detection"


def validate(v):
    errors = []
    if v.get("verdict") not in VERDICTS:
        errors.append(f"verdict must be one of {VERDICTS}")
    for key in ("summary",):
        if not isinstance(v.get(key), str):
            errors.append(f"{key} must be a string")
    for key in ("reasoning", "falsePositiveIndicators", "truePositiveIndicators", "recommendedActions", "whatWouldChangeMyMind"):
        if not isinstance(v.get(key), list):
            errors.append(f"{key} must be a list")
    bad = set(v.get("stages") or []) - TACTICS
    if bad:
        errors.append(f"unknown stages {sorted(bad)}")
    if not (isinstance(v.get("devilsAdvocate"), dict) and v["devilsAdvocate"].get("argument") and v["devilsAdvocate"].get("rebuttal")):
        errors.append("devilsAdvocate.argument and .rebuttal are mandatory")
    return errors


def confidence(v, unavailable=0):
    odds = lambda p: p / (1 - p)  # noqa: E731
    prob = lambda o: o / (1 + o)  # noqa: E731
    factors = [{"label": "prior, no opinion before reading the case", "delta": PRIOR}]
    strength = 1.0

    def push(label, lr):
        nonlocal strength
        before = prob(odds(PRIOR) * strength)
        strength *= lr
        factors.append({"label": label, "lr": round(lr, 2), "delta": round(prob(odds(PRIOR) * strength) - before, 2)})

    def doubt(label, divisor):
        # Doubt pulls toward 50/50 but never across it: it cannot flip a verdict.
        nonlocal strength
        before = prob(odds(PRIOR) * strength)
        strength = max(1, strength / divisor) if strength >= 1 else min(1, strength * divisor)
        factors.append({"label": label, "shrink": round(divisor, 2), "delta": round(prob(odds(PRIOR) * strength) - before, 2)})

    tp, fp = v.get("truePositiveIndicators", []), v.get("falsePositiveIndicators", [])
    verdict = v["verdict"]
    supporting, contradicting, kind, other = {
        "LIKELY_TRUE_POSITIVE": (tp, fp, "true-positive", "false-positive"),
        "LIKELY_FALSE_POSITIVE": (fp, tp, "false-positive", "true-positive"),
    }.get(verdict, ([], [], "", ""))

    if agree := min(len(supporting), MAX_AGREE):
        push(f"{len(supporting)} {kind} indicator(s) supporting the verdict", LR_AGREE ** agree)
    if against := min(len(contradicting), MAX_OPPOSE):
        push(f"{len(contradicting)} {other} indicator(s) cutting against it", LR_OPPOSE ** against)

    lr, label = corroboration(v.get("stages"), v.get("corroboratingSources"))
    if verdict == "LIKELY_TRUE_POSITIVE":
        push(label, lr)
    elif verdict == "LIKELY_FALSE_POSITIVE":
        push(label, 1 / lr)
    else:
        factors.append({"label": label, "lr": 1, "delta": 0})

    evidence_strength = round(strength, 2)
    gaps = len(v.get("evidenceGaps") or [])
    if gaps:
        doubt(f"{gaps} evidence gap(s)", PER_GAP ** min(gaps, MAX_GAPS))
    if unavailable:
        doubt(f"{unavailable} source(s) could not be fetched", PER_UNAVAILABLE ** min(unavailable, MAX_UNAVAILABLE))

    value = prob(odds(PRIOR) * strength)
    if verdict == "INVESTIGATE" and value > ABSTENTION_CAP:
        factors.append({"label": "capped, an abstention must not outrank a decided case", "delta": round(ABSTENTION_CAP - value, 2)})
        value = ABSTENTION_CAP
    out = {"value": round(min(CEILING, max(FLOOR, value)), 2), "evidenceStrength": evidence_strength, "factors": factors}
    if isinstance(v.get("confidence"), (int, float)):
        self_reported = v["confidence"] / 100 if 2 <= v["confidence"] <= 100 else v["confidence"]
        out["selfReported"] = self_reported
        if (gap := round(self_reported - out["value"], 2)) > 0:
            out["overconfidence"] = gap
    return out


def main(argv):
    if not argv or argv[0] not in ("plan", "confidence"):
        sys.exit(__doc__)
    data = json.load(sys.stdin)
    if argv[0] == "plan":
        print(json.dumps(plan(data), indent=2))
        return
    unavailable = int(argv[argv.index("--unavailable") + 1]) if "--unavailable" in argv else 0
    if errors := validate(data):
        sys.exit("invalid verdict:\n  " + "\n  ".join(errors))
    print(json.dumps(confidence(data, unavailable), indent=2))


if __name__ == "__main__":
    main(sys.argv[1:])
