#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The `webrtc-browser` conformance suite: headless Chromium and Firefox (Playwright 1.64.0) against
# busbar's terminating datagram path, using this repo's own harness (testing/webrtc-conformance).
# Legs: CONTROL (the browser against itself), NEGATIVE CONTROL (the subject with its line echo broken
# must grade red on media alone) and SUBJECT (armed or red). Pass only when all three hold.
#
# The subject builds on the host against $BUSBAR_CHECKOUT through a run-time overlay workspace (the
# subject is a separate test host using core-connector's public door adapter, not a shipping
# workspace member; nothing is committed). The original digest-pinned Playwright browsers run
# from a read-only offline bundle in the same candidate-private network namespace.
# Needs CONFORMANCE_OUT, BUSBAR_CHECKOUT, CARGO_TARGET_DIR (run.sh provides them).
set -uo pipefail

BROWSER_TOOLS=/opt/busbar-conformance/webrtc
PW_VERSION="$(python3 -I -c 'import json;print(json.load(open("testing/webrtc-conformance/package.json"))["devDependencies"]["playwright"])')"
REPO="$(pwd)"
H="$REPO/testing/webrtc-conformance"
OUT="${CONFORMANCE_OUT:?}"
BC="${BUSBAR_CHECKOUT:?}"
TARGET="${CARGO_TARGET_DIR:-$REPO/target}"
export CARGO_TARGET_DIR="$TARGET"
REPORTS="$OUT/reports"
W="$(mktemp -d "${TMPDIR:-/tmp}/webrtc-browser.XXXXXX")"
trap 'rm -rf "$W"' EXIT
REAL_NODE="$(command -v node)"
LOG="$OUT/log.txt"
: >"$LOG"
say() { printf 'webrtc-browser: %s\n' "$*" | tee -a "$LOG" >&2; }

verdict() { # <status> <armed> <reason>
  python3 -I - "$OUT/verdict.json" "$1" "$2" "$3" "$PW_VERSION" <<'PY'
import json, sys
out, status, armed, reason, ver = sys.argv[1:6]
json.dump({"suite": "webrtc-browser", "status": status, "armed": armed == "true",
           "standard": "W3C WebRTC / RFC 8825 (ICE, DTLS-SRTP, SCTP data channels), browser interop",
           "plan": "Playwright headless Chromium and Firefox: control, negative control, subject",
           "spec_version": "playwright " + ver, "reason": reason[:2000]}, open(out, "w"), indent=2)
PY
}

# ---- the subject: an overlay workspace that builds against $BUSBAR_CHECKOUT ----
mkdir -p "$W/ws"
cp -R "$H/subject" "$W/ws/subject"
python3 -I - "$REPO" "$BC" "$W/ws" <<'PY'
import re, sys, os
repo, bc, ws = sys.argv[1:4]
root = open(f"{repo}/Cargo.toml").read()
root = re.sub(r"members = \[[^\]]*\]", 'members = ["subject"]', root, count=1)
crates = sorted(d for d in os.listdir(f"{bc}/crates") if os.path.isfile(f"{bc}/crates/{d}/Cargo.toml"))
names = {}
for d in crates:
    m = re.search(r'^name\s*=\s*"([^"]+)"', open(f"{bc}/crates/{d}/Cargo.toml").read(), re.M)
    if m:
        names[m.group(1)] = d
root += '\n[patch."https://github.com/GetBusbar/busbar"]\n'
for n, d in names.items():
    root += f'{n} = {{ path = "{bc}/crates/{d}" }}\n'
open(f"{ws}/Cargo.toml", "w").write(root)
sub = open(f"{ws}/subject/Cargo.toml").read()
sub = sub.replace('busbar-transport-webrtc = { path = "../../../transport-webrtc" }',
                  f'busbar-transport-webrtc = {{ path = "{repo}/transport-webrtc" }}')
open(f"{ws}/subject/Cargo.toml", "w").write(sub)

PY
cp "$BC/Cargo.lock" "$W/ws/Cargo.lock"
# The page the subject embeds is found relative to src/main.rs.
mkdir -p "$W/ws/page" && cp "$H/page/index.html" "$W/ws/page/index.html"

say "building webrtc-conformance-subject against busbar ${BUSBAR_PIN:-$BC}"
if ! CARGO_TARGET_DIR="$TARGET" cargo build --manifest-path "$W/ws/Cargo.toml" -p webrtc-conformance-subject >>"$LOG" 2>&1; then
  tail -n 40 "$LOG" >&2
  verdict fail true "the webrtc-conformance-subject did not build against busbar ${BUSBAR_PIN:-}: see log.txt"
  exit 1
fi
# ---- the browsers: immutable, pinned offline tools in this candidate namespace ----
if [ ! -f "$BROWSER_TOOLS/node_modules/playwright/index.mjs" ] || \
   [ ! -x "$BROWSER_TOOLS/bin/chromium" ] || [ ! -x "$BROWSER_TOOLS/bin/firefox" ]; then
  verdict fail true "controller-staged pinned offline browser bundle is unavailable"
  exit 1
fi
export PLAYWRIGHT_BROWSERS_PATH="$BROWSER_TOOLS/browsers"
# The subject and browsers share only the candidate's private loopback namespace.
export WEBRTC_SUBJECT_HOST=127.0.0.1

# ---- the three legs, through the repo's own run.sh ----
rm -rf "$REPORTS"
fails=""; notrun=""
leg() { # <name> <run.sh mode>
  say "=== leg $1"
  local rc=0
  bash "$H/scripts/run.sh" "$2" >"$W/leg.log" 2>&1 || rc=$?
  cat "$W/leg.log" | tee -a "$LOG" | tail -n 25 >&2
  say "leg $1: exit $rc"
  case "$rc" in
    0) ;;
    3) notrun="$notrun $1" ;;
    *) fails="$fails $1" ;;
  esac
}
rc=0; bash "$H/scripts/run.sh" --selftest >>"$LOG" 2>&1 || rc=$?
[ "$rc" -eq 0 ] || fails="$fails judgement-selftest"
leg control --control
leg negative-control --negative-control
leg subject --subject

detail="$("$REAL_NODE" -e '
  const fs = require("fs");
  for (const t of ["control", "negative-control", "negative-close-control", "subject"]) {
    try { const v = JSON.parse(fs.readFileSync(process.argv[1] + "/" + t + "/verdict.json", "utf8"));
      console.log(t + ": " + v.status + " (" + v.reason + ")"); } catch (e) { console.log(t + ": no verdict"); }
  }' "$REPORTS" | tr '\n' ' ')"
if [ -n "$fails" ]; then
  verdict fail true "legs failed:$fails. $detail"; exit 1
elif [ -n "$notrun" ]; then
  verdict not-run true "legs not run:$notrun. $detail"; exit 3
fi
verdict pass true "control, negative control and subject held for chromium and firefox. $detail"
