<!-- fleet:header:begin (rendered by `busbar-release plugin heal` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-transport-webrtc

First-party signed kind:transport plugin cdylib: the webrtc transport, packaged as a droppable busbar plugin. Drop the signed tarball into plugins/.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `transport` | `webrtc` | `busbar-transport-webrtc-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

[![ci](https://github.com/GetBusbar/busbar-transport-webrtc/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-transport-webrtc/actions/workflows/ci.yml)
<!-- fleet:header:end -->

## What it is for

`busbar-transport-webrtc` is a `kind: transport` busbar plugin: the webrtc framer (BUSBAR-1.6.0 l.754-767). It holds ICE, SRTP (AEAD-AES-GCM only) and SCTP data channels over the host's datagram port and DTLS layer; SRTP keys arrive through the keying-material item.

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

The browser interop cell (`testing/webrtc-conformance`: headless Chromium and Firefox against busbar's terminating datagram path) is busbar's `webrtc-browser` conformance suite (`conformance/registry.toml` in busbar). Its subject mounts busbar's own `doors.rs` and drives the connector's datagram path, so it runs from a busbar checkout under that suite, not from this repo's `ci.yml` (whose `extra_test` is empty for that reason).

## Known residual: upstream copies of secrets are not zeroised

This plugin zeroises the SRTP keying material, the keys derived from it and the ICE password that its own types hold (`zeroize`, with tests). The published `str0m`, `dimpl` and `ring` crates it builds on do not zeroise their internal copies of these secrets when they drop them, so copies may remain in freed memory until it is reused. Exploiting this needs read access to the process's memory. It is a known residual risk, not fixed here. The test `known_residual_upstream_copies_of_the_keying_material_are_freed_unzeroed` in `transport-webrtc/tests/zeroise.rs` asserts it as known (it fails once upstream starts zeroising), and `keying_material_the_plugin_holds_on_the_accepted_path_is_zeroised` gates the plugin's own copies.

## License

Apache-2.0. See [LICENSE](LICENSE).
