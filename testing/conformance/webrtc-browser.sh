#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The `webrtc-browser` conformance suite: headless Chromium and Firefox (Playwright 1.64.0) against
# busbar's terminating datagram path, using this repo's own harness (testing/webrtc-conformance).
# Legs: CONTROL (the browser against itself), NEGATIVE CONTROL (the subject with its line echo broken
# must grade red on media alone) and SUBJECT (armed or red). Pass only when all three hold.
#
# The subject builds on the host against $BUSBAR_CHECKOUT through a run-time overlay workspace (the
# subject mounts busbar's doors.rs by path and is not a workspace member, so it cannot build in
# place; nothing is committed). The browsers run in the official Playwright image pinned by digest,
# on the host network, so they reach the subject at the host's first non-loopback IPv4.
# Needs CONFORMANCE_OUT, BUSBAR_CHECKOUT, CARGO_TARGET_DIR (run.sh provides them).
set -uo pipefail

IMAGE="mcr.microsoft.com/playwright:v1.64.0-noble@sha256:06a9939e57531807f8d5fd76ce44b53165ffb7d7501d87ab10e285c20b1e971f"
PW_VERSION="$(python3 -I -c 'import json;print(json.load(open("testing/webrtc-conformance/package.json"))["devDependencies"]["playwright"])')"
REPO="$(pwd)"
H="$REPO/testing/webrtc-conformance"
OUT="${CONFORMANCE_OUT:?}"
BC="${BUSBAR_CHECKOUT:?}"
TARGET="${CARGO_TARGET_DIR:-$REPO/target}"
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
sub = sub.replace("busbar-transport-webrtc = { workspace = true }",
                  f'busbar-transport-webrtc = {{ path = "{repo}/transport-webrtc" }}')
open(f"{ws}/subject/Cargo.toml", "w").write(sub)
src = open(f"{ws}/subject/src/main.rs").read()
src = src.replace("../../../../crates/busbar/src/root/doors.rs", f"{bc}/crates/busbar/src/root/doors.rs")
open(f"{ws}/subject/src/main.rs", "w").write(src)
PY
cp "$REPO/Cargo.lock" "$W/ws/Cargo.lock"
# The page the subject embeds is found relative to src/main.rs.
mkdir -p "$W/ws/page" && cp "$H/page/index.html" "$W/ws/page/index.html"

say "building webrtc-conformance-subject against busbar ${BUSBAR_PIN:-$BC}"
if ! CARGO_TARGET_DIR="$TARGET" cargo build --manifest-path "$W/ws/Cargo.toml" -p webrtc-conformance-subject >>"$LOG" 2>&1; then
  tail -n 40 "$LOG" >&2
  verdict fail true "the webrtc-conformance-subject did not build against busbar ${BUSBAR_PIN:-}: see log.txt"
  exit 1
fi
# run.sh looks for the subject at <repo>/target/debug; put it there if the target dir differs.
mkdir -p "$REPO/target/debug"
if [ "$TARGET/debug/webrtc-conformance-subject" != "$REPO/target/debug/webrtc-conformance-subject" ]; then
  cp "$TARGET/debug/webrtc-conformance-subject" "$REPO/target/debug/webrtc-conformance-subject"
fi

# ---- the browsers: node shim that runs bin/drive.mjs's browser legs in the pinned image ----
command -v docker >/dev/null || { verdict not-run true "docker is not available for the browser image"; exit 3; }
mkdir -p "$W/pw" "$W/shim"
cp "$H/package.json" "$H/package-lock.json" "$W/pw/"
if ! docker run --rm --network host -v "$W/pw:/pw" -w /pw "$IMAGE" npm ci --ignore-scripts --no-audit --no-fund >>"$LOG" 2>&1; then
  verdict not-run true "npm ci of the locked Playwright $PW_VERSION failed in the browser image"
  exit 3
fi
cat >"$W/shim/node" <<SHIM
#!/usr/bin/env bash
# Browser legs (drive.mjs --url ...) run in the Playwright image; everything else is plain node.
case " \$* " in
  *"drive.mjs"*" --url "*)
    exec docker run --rm --network host --ipc=host --init --user "\$(id -u):\$(id -g)" -e HOME=/tmp \\
      -v "$REPO:$REPO" -v "$W/pw/node_modules:$H/node_modules:ro" -w "$H" \\
      "$IMAGE" node "\$@" ;;
  *) exec "$REAL_NODE" "\$@" ;;
esac
SHIM
chmod +x "$W/shim/node"
export PATH="$W/shim:$PATH"

# ---- the three legs, through the repo's own run.sh ----
rm -rf "$H/reports"
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
rc=0; "$REAL_NODE" "$H/bin/drive.mjs" --selftest >>"$LOG" 2>&1 || rc=$?
[ "$rc" -eq 0 ] || fails="$fails judgement-selftest"
leg control --control
leg negative-control --negative-control
leg subject --subject

detail="$("$REAL_NODE" -e '
  const fs = require("fs");
  for (const t of ["control", "negative-control", "subject"]) {
    try { const v = JSON.parse(fs.readFileSync(process.argv[1] + "/reports/" + t + "/verdict.json", "utf8"));
      console.log(t + ": " + v.status + " (" + v.reason + ")"); } catch (e) { console.log(t + ": no verdict"); }
  }' "$H" | tr '\n' ' ')"
mkdir -p "$OUT/reports" && cp -R "$H/reports/." "$OUT/reports/" 2>/dev/null || true
if [ -n "$fails" ]; then
  verdict fail true "legs failed:$fails. $detail"; exit 1
elif [ -n "$notrun" ]; then
  verdict not-run true "legs not run:$notrun. $detail"; exit 3
fi
verdict pass true "control, negative control and subject held for chromium and firefox. $detail"
