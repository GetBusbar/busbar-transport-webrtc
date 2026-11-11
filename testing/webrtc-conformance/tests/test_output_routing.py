#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise report routing with read-only source and controlled tool processes."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[3]
TAGS = ("control", "negative-control", "negative-close-control", "subject")


class OutputRouting(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="webrtc-output-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.source = self.work / "read-only source"
        self.harness = self.source / "testing/webrtc-conformance"
        shutil.copytree(REPO / "testing/webrtc-conformance", self.harness,
                        ignore=shutil.ignore_patterns("tests", "reports", "node_modules"))
        adapter = self.source / "testing/conformance/webrtc-browser.sh"
        adapter.parent.mkdir()
        shutil.copyfile(REPO / "testing/conformance/webrtc-browser.sh", adapter)
        (self.source / "Cargo.toml").write_text('[workspace]\nmembers = []\n')
        self.target = self.work / "writable target"
        self.target.mkdir()
        self.core = self.work / "core"
        (self.core / "crates").mkdir(parents=True)
        (self.core / "Cargo.lock").write_text("version = 4\n")
        self.bin = self.work / "tools"
        self.bin.mkdir()
        self.subject = self.bin / "subject"
        self.write_executable(self.subject, """
import signal
print('WEBRTC_SUBJECT_URL=http://127.0.0.1:12345/', flush=True)
while True:
    signal.pause()
""")
        self.write_executable(self.bin / "cargo", """
import os, shutil
from pathlib import Path
output = Path(os.environ['CARGO_TARGET_DIR']) / 'debug/webrtc-conformance-subject'
output.parent.mkdir(parents=True, exist_ok=True)
shutil.copyfile(os.environ['CONTROLLED_SUBJECT'], output)
output.chmod(0o755)
""")
        self.write_executable(self.bin / "node", """
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
if args and args[0].endswith('/bin/drive.mjs') and '--url' in args:
    if os.environ.get('TEST_BROWSER_DIAGNOSTIC'):
        print('underlying browser launch diagnostic', file=sys.stderr)
        print('\\n'.join('diagnostic context ' + str(index) for index in range(30)), file=sys.stderr)
    output = Path(args[args.index('--out') + 1])
    output.mkdir(parents=True, exist_ok=True)
    negative = output.name.startswith('negative-')
    browsers = {name: {'channel-text': {'pass': True},
                      'media-round-trip': {'pass': output.name != 'negative-control'},
                      'close': {'pass': output.name != 'negative-close-control'}}
                for name in ('chromium', 'firefox')}
    (output / 'verdict.json').write_text(json.dumps({
        'status': 'fail' if negative else 'pass', 'armed': True,
        'reason': 'controlled output-routing fixture', 'browsers': browsers}))
    sys.exit(1 if negative else 0)
os.execv(os.environ['TEST_REAL_NODE'], [os.environ['TEST_REAL_NODE'], *args])
""")
        browser_tools = self.work / "browser tools"
        (browser_tools / "node_modules/playwright").mkdir(parents=True)
        (browser_tools / "node_modules/playwright/index.mjs").touch()
        (browser_tools / "bin").mkdir()
        for browser in ("chromium", "firefox"):
            self.write_executable(browser_tools / "bin" / browser, "raise SystemExit(0)\n")
        # Relocate only the copied adapter's fixed tool mount in this harness test.
        adapter.write_text(adapter.read_text().replace(
            "BROWSER_TOOLS=/opt/busbar-conformance/webrtc",
            'BROWSER_TOOLS="' + str(browser_tools) + '"'))
        self.environment = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                                CARGO_TARGET_DIR=str(self.target), BUSBAR_CHECKOUT=str(self.core),
                                CONTROLLED_SUBJECT=str(self.subject), TEST_REAL_NODE=shutil.which("node"),
                                TMPDIR=str(self.work))
        self.environment.pop("CONFORMANCE_OUT", None)
        self.original = self.source_digest()
        for path in self.source.rglob("*"):
            path.chmod(0o555 if path.is_dir() or path.stat().st_mode & 0o111 else 0o444)
        self.source.chmod(0o555)
        self.addCleanup(self.restore_permissions)
        self.assertFalse(os.access(self.harness, os.W_OK), "run this test as a non-root user")

    def write_executable(self, path, source):
        path.write_text(f"#!{sys.executable}\n" + source.lstrip())
        path.chmod(0o755)

    def restore_permissions(self):
        self.source.chmod(0o755)
        for path in self.source.rglob("*"):
            if path.is_dir():
                path.chmod(0o755)

    def source_digest(self):
        return {str(path.relative_to(self.source)): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in self.source.rglob("*") if path.is_file()}

    def run_script(self, relative, *args, expected=0):
        with subprocess.Popen(["bash", str(self.source / relative), *args], cwd=self.source,
                              env=self.environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, start_new_session=True) as process:
            try:
                stdout, stderr = process.communicate(timeout=20)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                stdout, stderr = process.communicate()
                self.fail("controlled harness timed out: " + stdout + stderr)
        result = subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
        self.assertEqual(result.returncode, expected, stdout + stderr)
        self.assertEqual(self.source_digest(), self.original)
        return result

    def assert_reports(self, reports):
        for tag in TAGS:
            verdict = json.loads((reports / tag / "verdict.json").read_text())
            self.assertEqual(verdict["status"], "fail" if tag.startswith("negative-") else "pass")

    def test_adapter_keeps_all_legs_in_declared_output(self):
        output = self.work / "declared conformance output"
        output.mkdir()
        self.environment["CONFORMANCE_OUT"] = str(output)
        self.environment["TEST_BROWSER_DIAGNOSTIC"] = "1"
        result = self.run_script("testing/conformance/webrtc-browser.sh")
        self.assertIn("underlying browser launch diagnostic", result.stderr)
        self.assert_reports(output / "reports")
        verdict = json.loads((output / "verdict.json").read_text())
        self.assertEqual(verdict["status"], "pass")
        for tag in TAGS:
            self.assertIn(tag + ": ", verdict["reason"])
        self.assertNotIn("no verdict", verdict["reason"])
        self.assertFalse((self.source / "target").exists())

    def test_direct_legs_use_target_fallback_including_recursive_close_control(self):
        binary = self.target / "debug/webrtc-conformance-subject"
        binary.parent.mkdir()
        shutil.copyfile(self.subject, binary)
        binary.chmod(0o755)
        for mode in ("--control", "--negative-control", "--subject"):
            self.run_script("testing/webrtc-conformance/scripts/run.sh", mode)
        self.assert_reports(self.target / "conformance/webrtc-browser/reports")

    def test_missing_subject_writes_not_run_under_writable_target(self):
        self.run_script("testing/webrtc-conformance/scripts/run.sh", "--subject", expected=1)
        verdict = json.loads((self.target / "conformance/webrtc-browser/reports/subject/verdict.json").read_text())
        self.assertEqual(verdict["status"], "not-run")
        self.assertFalse(verdict["armed"])


if __name__ == "__main__":
    unittest.main()
