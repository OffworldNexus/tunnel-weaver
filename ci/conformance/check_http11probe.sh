#!/usr/bin/env bash
# Compare two Http11Probe runs — the origin probed directly (baseline) and
# the same origin probed through the tunnel — and fail on translation
# regressions.
#
# Usage: check_http11probe.sh <baseline.json> <tunnel.json> <expectations.txt>
#
# The tunnel is a proxy, so "the same as the origin" is the wrong target for
# every test: a smuggling vector the origin tolerates MUST be refused at the
# edge, and edge-generated errors (400/405/403) legitimately differ from the
# origin's. The expectations file therefore lists, per test id, the verdict
# the *tunnel* must produce (`Pass`, `Warn`, `Fail`, `Error`, `Skip`) with a
# justification. Any test not listed must have the tunnel verdict be at least
# as good as the baseline (Pass ≥ Warn ≥ Fail/Error).
set -euo pipefail

baseline="$1"
tunnel="$2"
expectations="$3"

for f in "$baseline" "$tunnel"; do
  if [ ! -s "$f" ]; then
    echo "::error::Http11Probe produced no report at $f"
    exit 1
  fi
done

python3 - "$baseline" "$tunnel" "$expectations" <<'PY'
import json, re, sys

baseline = {r["id"]: r for r in json.load(open(sys.argv[1]))["results"]}
tunnel = {r["id"]: r for r in json.load(open(sys.argv[2]))["results"]}

expected = {}
for line in open(sys.argv[3]):
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    parts = line.split(None, 2)
    if len(parts) < 2:
        continue
    expected[parts[0].upper()] = parts[1]

rank = {"Pass": 3, "Warn": 2, "Skip": 2, "Fail": 1, "Error": 0}
status = 0
regressions, improvements, pinned_ok, pinned_bad = [], [], [], []

for tid, t in sorted(tunnel.items()):
    tv = t["verdict"]
    if tid.upper() in expected:
        want = expected[tid.upper()]
        if tv == want:
            pinned_ok.append(f"{tid}: {tv}")
        else:
            pinned_bad.append(f"{tid}: tunnel={tv} expected={want} (baseline={baseline.get(tid,{}).get('verdict','?')})")
            status = 1
        continue
    b = baseline.get(tid)
    if b is None:
        continue
    bv = b["verdict"]
    if rank.get(tv, 0) < rank.get(bv, 0):
        regressions.append(f"{tid} [{t['category']}]: origin={bv} tunnel={tv} status={t.get('statusCode')} conn={t.get('connectionState')}")
        status = 1
    elif rank.get(tv, 0) > rank.get(bv, 0):
        improvements.append(f"{tid}: origin={bv} tunnel={tv}")

for tid in expected:
    if tid not in {k.upper() for k in tunnel}:
        print(f"::warning::expectation for unknown test id {tid}")

print(f"baseline: {json.load(open(sys.argv[1]))['summary']}")
print(f"tunnel:   {json.load(open(sys.argv[2]))['summary']}")
if improvements:
    print(f"\n{len(improvements)} test(s) where the edge is stricter than the origin (fine):")
    for i in improvements: print("  +", i)
if pinned_ok:
    print(f"\n{len(pinned_ok)} pinned expectation(s) hold")
if pinned_bad:
    print(f"\n{len(pinned_bad)} pinned expectation(s) violated:")
    for p in pinned_bad: print("::error::" + p)
if regressions:
    print(f"\n{len(regressions)} translation regression(s): the tunnel does worse than the origin it fronts:")
    for r in regressions: print("::error::" + r)
sys.exit(status)
PY
