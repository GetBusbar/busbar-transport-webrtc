<!-- fleet:header:begin (rendered by `busbar-release plugin heal` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-transport-webrtc

First-party signed kind:transport plugin cdylib: the webrtc transport, packaged as a droppable busbar plugin. Drop the signed tarball into plugins/.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `transport` | `webrtc` | `busbar-transport-webrtc-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

<!-- fleet:header:end -->

## What it is for

`busbar-transport-webrtc` is a `kind: transport` busbar plugin: the webrtc framer (BUSBAR-1.6.0 l.754-767). It holds ICE, SRTP (AEAD-AES-GCM only) and SCTP data channels over the host's datagram port and DTLS layer; SRTP keys arrive through the keying-material item.

Media-level ICE credentials, certificate fingerprints and DTLS setup roles override session defaults for the association. Retained path history and pending output pieces are each limited to 1,024 entries; exceeding either limit fails the association. The output limit includes channel open, close, failure and writable notifications.

## Config

Configured under the `webrtc` module name. The framer reads no setting: `{}` (or nothing), and any key is refused.

## Build

```bash
cargo build --release -p busbar-transport-webrtc-plugin
```

## Tests

```bash
cargo test --workspace --locked
```

The browser interop cell (`testing/webrtc-conformance`: headless Chromium and Firefox against busbar's terminating datagram path) is busbar's `webrtc-browser` conformance suite (`conformance/registry.toml` in busbar). Its subject mounts busbar's own `doors.rs` and drives the connector's datagram path, so it runs from a busbar checkout under that suite, not from this repo's `ci.yml` (whose `extra_test` is empty for that reason). The close cell requires the subject to observe the data-channel END, and its negative control suppresses that receipt.

## Known residual: upstream copies of secrets are not zeroised

This plugin zeroises the SRTP keying material, the derived keys and the ICE password that its own types hold (`zeroize`, with tests). Rendezvous-term diagnostics redact both ICE passwords. Plugin-owned session-description buffers are wiped when released, and their diagnostics are redacted. ICE nomination ignores attributes after MESSAGE-INTEGRITY so unauthenticated trailing attributes cannot nominate a path. Its AES-GCM packet cipher uses the SDK's managed provider, whose default native allocator cleanses the owned context and cipher-state allocations before freeing them. The GNU/Linux tests in `transport-webrtc/tests/zeroise_session_key.rs` require complete live and pre-free memory reads of those actual allocations, with positive and negative controls; other platforms retain cipher behavior and free receipts without claiming native-memory wiping proof. These tests do not prove wiping every stack copy, register or upstream secret.

The published `str0m` and `dimpl` crates still retain upstream secret copies, and `ring` remains in use for HMAC-SHA1, SHA-256 and randomness. Exploiting residual freed-memory copies needs read access to the process's memory. The test `known_residual_upstream_copies_of_the_keying_material_are_freed_unzeroed` in `transport-webrtc/src/tests/zeroise_tests.rs` follows the actual upstream `KeyingMaterial` payload through the accepted association and observes it at deallocation (it fails once that payload is zeroised). `keying_material_the_plugin_holds_on_the_accepted_path_is_zeroised` observes the plugin's own initialized keying payloads. These observations do not scan opaque upstream structures or their padding.

The cipher authenticates SRTCP before updating its per-source replay window, and refuses duplicate or stale reports within the receive key epoch. On transmit, the pinned media stack's global SRTCP index must increase within its cipher key epoch; reuse or exhaustion refuses encryption and ends the association before further wire output. This does not change RTP processing or replace the pinned media dependency.

## License

Apache-2.0. See [LICENSE](LICENSE).
