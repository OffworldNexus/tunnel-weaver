#!/usr/bin/env bash
# Fail unless every h2spec failure is allow-listed.
#
# Usage: check_h2spec.sh <junit.xml> <allowlist.txt>
#
# The allow-list holds one h2spec case id per line (e.g. `5.1/9`) followed
# by a one-line justification; blank lines and `#` comments are ignored. A
# failing case that is not listed fails the job; a listed case that now
# passes is reported so the entry can be removed.
set -euo pipefail

report="$1"
allowlist="$2"

if [ ! -s "$report" ]; then
  echo "::error::h2spec produced no report at $report"
  exit 1
fi

# h2spec's JUnit puts `<group>/<section>` in `package` (e.g. `http2/3.5`,
# `generic/3.5`, `hpack/4.2` — the same section number exists in several
# groups) and the case description in `classname`; cases within a section
# are numbered in document order. The id we print is
# `<group>/<section>/<n>`, e.g. `http2/3.5/2`. Both `<failure>` and
# `<error>` count as failing.
mapfile -t failed < <(
  python3 - "$report" <<'PY'
import sys, xml.etree.ElementTree as ET
from collections import defaultdict
root = ET.parse(sys.argv[1]).getroot()
counter = defaultdict(int)
for tc in root.iter("testcase"):
    pkg = tc.get("package", "")
    counter[pkg] += 1
    if tc.find("failure") is not None or tc.find("error") is not None:
        print(f"{pkg}/{counter[pkg]}")
PY
)

mapfile -t allowed < <(grep -vE '^\s*(#|$)' "$allowlist" | awk '{print $1}')

status=0
for case in "${failed[@]:-}"; do
  [ -z "$case" ] && continue
  if printf '%s\n' "${allowed[@]:-}" | grep -qx -- "$case"; then
    echo "allow-listed failure: $case"
  else
    echo "::error::h2spec case $case failed and is not allow-listed"
    status=1
  fi
done

for case in "${allowed[@]:-}"; do
  [ -z "$case" ] && continue
  if ! printf '%s\n' "${failed[@]:-}" | grep -qx -- "$case"; then
    echo "::warning::allow-listed h2spec case $case now passes; remove it from $allowlist"
  fi
done

total=$(grep -c "<testcase" "$report" || true)
echo "h2spec: $total cases, ${#failed[@]} failed (${status:+non-allow-listed: }$( [ $status -eq 0 ] && echo 0 || echo ">0" ))"
exit $status
