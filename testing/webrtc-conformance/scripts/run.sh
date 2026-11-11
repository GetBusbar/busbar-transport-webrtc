#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# THE BROWSER CELL: headless Chromium and Firefox drive a real offer/answer, data-channel echo and
# media round trip against busbar's terminating datagram path (the webrtc-conformance-subject),
# in a control-always + subject-armed-or-red shape.
#
# MODES
#   --selftest                 the judgement and the page's close cell bite on captured fixtures
#                              (no browser, no subject)
#   --control                  the page's own control (the browser against itself) must PASS
#   --negative-control         the subject with its line echo broken MUST grade red on media alone,
#                              then --negative-close-control
#   --negative-close-control   the subject with its close receipt suppressed MUST grade red on close
#   --subject                  the cell against the subject; ARMED OR RED
#
# The subject uses core-connector's public door adapter and builds as a separate test host in
# testing/conformance/webrtc-browser.sh's overlay against a busbar checkout, which places the binary
# at SUBJECT_BIN before any subject leg runs.
#
# Browsers are the instrument: a browser that does not launch makes a leg exit 3 (not-run), never
# a pass. The subject advertises candidate-private loopback for signaling and ICE.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$ROOT/../.." && pwd)"
DRIVE="$ROOT/bin/drive.mjs"
FIXTURES="$ROOT/fixtures"
TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
# Measured source stays read-only; every leg, including recursive close control,
# uses the declared output workspace or the writable build target fallback.
REPORTS_DIR="${CONFORMANCE_OUT:-$TARGET_DIR/conformance/webrtc-browser}/reports"
SUBJECT_BIN="$TARGET_DIR/debug/webrtc-conformance-subject"

mode="${1:---selftest}"

# Temporary files and directories this run made, removed on exit.
SCRATCH=()

status_of() {
  node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")).status)' "$1"
}

selftest() {
  echo "== judgement selftest =="
  node "$DRIVE" --selftest
  node --test "$ROOT/page/close_test.mjs"
  local tmp
  tmp="$(mktemp -d)"
  SCRATCH+=("$tmp")
  node "$DRIVE" --judge "$FIXTURES/good.txt" --armed true --out "$tmp/good.json"
  [ "$(status_of "$tmp/good.json")" = "pass" ] || { echo "FAIL: good fixture is not pass" >&2; return 1; }
  echo "  ok: good fixture -> pass"
  if node "$DRIVE" --judge "$FIXTURES/bad.txt" --armed true --out "$tmp/bad.json"; then
    echo "FAIL: the bad fixture was accepted (exit 0)" >&2
    return 1
  fi
  [ "$(status_of "$tmp/bad.json")" = "fail" ] || { echo "FAIL: bad fixture is not fail" >&2; return 1; }
  echo "  ok: bad fixture -> fail"
  node "$DRIVE" --judge "$FIXTURES/good.txt" --armed false --out "$tmp/unarmed.json" || true
  [ "$(status_of "$tmp/unarmed.json")" = "not-run" ] || { echo "FAIL: unarmed + good is not not-run" >&2; return 1; }
  echo "  ok: unarmed + good fixture -> not-run (NOT pass)"
  echo
  echo "webrtc-conformance selftest: all judgement checks passed"
}

host() {
  # Subject signaling, ICE and browser traffic stay in the candidate namespace.
  echo 127.0.0.1
}

# Start the subject with "$@"; sets SUBJECT_PID and SUBJECT_URL.
start_subject() {
  if [ ! -x "$SUBJECT_BIN" ]; then
    echo "  RED: no webrtc-conformance-subject at $SUBJECT_BIN (NOT ARMED)" >&2
    return 1
  fi
  local out
  out="$(mktemp)"
  SCRATCH+=("$out" "$out.err")
  WEBRTC_SUBJECT_HOST="$(host)" "$SUBJECT_BIN" "$@" >"$out" 2>"$out.err" &
  SUBJECT_PID=$!
  SUBJECT_URL=""
  for _ in $(seq 1 300); do
    SUBJECT_URL="$(sed -n 's/^WEBRTC_SUBJECT_URL=//p' "$out" | head -n1)"
    [ -n "$SUBJECT_URL" ] && break
    kill -0 "$SUBJECT_PID" 2>/dev/null || break
    sleep 0.1
  done
  if [ -z "$SUBJECT_URL" ]; then
    echo "  RED: the subject did not come up" >&2
    cat "$out.err" >&2 || true
    return 1
  fi
  echo "  subject at $SUBJECT_URL"
}

stop_subject() {
  [ -n "${SUBJECT_PID:-}" ] && kill "$SUBJECT_PID" 2>/dev/null || true
  wait "${SUBJECT_PID:-}" 2>/dev/null || true
}
cleanup() {
  stop_subject
  [ "${#SCRATCH[@]}" -eq 0 ] || rm -rf "${SCRATCH[@]}"
}
trap cleanup EXIT

drive() {
  # $1: page mode (cell|control); $2: report tag. A leg is judged only on its own fresh verdict.
  rm -rf "${REPORTS_DIR:?}/$2"
  mkdir -p "$REPORTS_DIR/$2"
  node "$DRIVE" --url "$SUBJECT_URL" --mode "$1" --out "$REPORTS_DIR/$2"
}

case "$mode" in
  --selftest) selftest ;;
  --control)
    start_subject
    drive control control
    ;;
  --negative-control)
    start_subject --break media
    rc=0
    drive cell negative-control || rc=$?
    [ "$rc" -eq 3 ] && exit 3
    # It must be red, and red on the media cells alone: the channel cells passing shows the
    # instrument reached the subject, the media cells failing shows it catches a broken line.
    node -e '
      const v = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
      // A browser that did not launch leaves the leg not-run, whatever the other one graded.
      if (/browser unavailable/.test(v.reason)) process.exit(3);
      const red = (b, c) => !(v.browsers[b] && v.browsers[b][c] && v.browsers[b][c].pass);
      const ok = v.status === "fail" &&
        ["chromium", "firefox"].every((b) => red(b, "media-round-trip") && !red(b, "channel-text"));
      console.log("webrtc-conformance: negative-control " + (ok ? "bites" : "DOES NOT BITE") + ": " + v.reason);
      process.exit(ok ? 0 : 1);
    ' "$REPORTS_DIR/negative-control/verdict.json"
    stop_subject
    SUBJECT_PID=""
    bash "$0" --negative-close-control
    ;;
  --negative-close-control)
    start_subject --break close
    rc=0
    drive cell negative-close-control || rc=$?
    [ "$rc" -eq 3 ] && exit 3
    node -e '
      const v = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
      if (/browser unavailable/.test(v.reason)) process.exit(3);
      const ok = v.status === "fail" && ["chromium", "firefox"].every((b) =>
        v.browsers[b]?.close?.pass === false && v.browsers[b]?.["channel-text"]?.pass === true);
      console.log("webrtc-conformance: negative-close-control " + (ok ? "bites" : "DOES NOT BITE"));
      process.exit(ok ? 0 : 1);
    ' "$REPORTS_DIR/negative-close-control/verdict.json"
    ;;
  --subject)
    if ! start_subject; then
      mkdir -p "$REPORTS_DIR/subject"
      echo '{"armed":false,"status":"not-run","reason":"the subject did not build or boot","browsers":{}}' \
        >"$REPORTS_DIR/subject/verdict.json"
      exit 1
    fi
    drive cell subject
    ;;
  *)
    echo "usage: $0 --selftest|--control|--negative-control|--negative-close-control|--subject" >&2
    exit 2
    ;;
esac
