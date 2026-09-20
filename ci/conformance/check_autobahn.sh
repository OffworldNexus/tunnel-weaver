#!/usr/bin/env bash
# Fail unless every Autobahn case that is not OK/INFORMATIONAL is
# allow-listed.
#
# Usage: check_autobahn.sh <reports/clients/index.json> <allowlist.txt>
#
# Autobahn's behaviour values: OK, NON-STRICT, INFORMATIONAL, UNIMPLEMENTED,
# FAILED, UNCLEAN (close). Only OK, NON-STRICT and INFORMATIONAL pass. The
# allow-list holds one case id per line (e.g. `6.4.2`) with a justification.
set -euo pipefail

index="$1"
allowlist="$2"

if [ ! -s "$index" ]; then
  echo "::error::Autobahn produced no report at $index (did the echo origin come up?)"
  exit 1
fi

mapfile -t bad < <(
  python3 - "$index" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
ok = {"OK", "NON-STRICT", "INFORMATIONAL"}
for agent, cases in data.items():
    for case, r in sorted(cases.items(), key=lambda kv: [int(x) for x in kv[0].split(".")]):
        b = r.get("behavior", "")
        bc = r.get("behaviorClose", "OK")
        if b not in ok or bc not in ok:
            print(f"{case} {b}/{bc}")
PY
)

mapfile -t allowed < <(grep -vE '^\s*(#|$)' "$allowlist" | awk '{print $1}')

status=0
for entry in "${bad[@]:-}"; do
  [ -z "$entry" ] && continue
  case="${entry%% *}"
  if printf '%s\n' "${allowed[@]:-}" | grep -qx -- "$case"; then
    echo "allow-listed: $entry"
  else
    echo "::error::Autobahn case $entry is not allow-listed"
    status=1
  fi
done

total=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(sum(len(v) for v in d.values()))' "$index")
echo "Autobahn: $total cases, ${#bad[@]} not OK"
exit $status
