# Offline webrtc conformance tools

The controller stages Playwright 1.64.0, Chromium 1248, Firefox 1555, and the pinned image's runtime libraries and fonts before admitting a candidate. Run this from the reviewed source checkout, with both destinations outside the candidate tree:

```sh
python3 testing/conformance/stage-tools.py --output /controller/tools/webrtc --cache /controller/public-downloads
```

The stager verifies the immutable public OCI manifests and layers and each NPM lockfile's SHA-512 integrity before unpacking. It executes no downloaded code or package scripts. It writes `webrtc-inputs.json` beside the bundle using `busbar.native-conformance-inputs/1`: every regular file has a SHA-256 and executable-mode flag, and public input provenance is retained. Symlink and hardlink aliases become separate regular files. Supply this manifest through the controller's protected `BUSBAR_CONFORMANCE_INPUTS` interface; the controller independently verifies the tree and mounts it read-only at `/opt/busbar-conformance/webrtc`.

The suite executes only that fixed mount. Its subjects and external judges communicate over the candidate's private loopback interface. Missing tools fail the required evaluation. No candidate package manager, Docker socket, host network, shared host IPC, or privilege is used. Existing control, negative-control, and subject grading criteria remain authoritative.

The browser ELF interpreter strings are relocated to the bundled Ubuntu loader; executable code and existing ELF offsets are unchanged. The deterministic relocation and original public image digest are recorded by the reviewed stager and final file manifest. Each browser gets the bundled libraries and font configuration. Chromium and Firefox explicitly enable loopback ICE candidates. The controller must provide a writable HOME and private temporary space. Browser launch failure never counts as a passing protocol result.
