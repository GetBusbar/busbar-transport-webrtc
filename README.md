<!-- fleet:header:begin (rendered by `busbar-release plugin heal` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-transport-webrtc

First-party signed kind:transport plugin cdylib: the webrtc transport, packaged as a droppable busbar plugin. Drop the signed tarball into plugins/.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `transport` | `webrtc` | `busbar-transport-webrtc-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

[![ci](https://github.com/GetBusbar/busbar-transport-webrtc/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-transport-webrtc/actions/workflows/ci.yml)
<!-- fleet:header:end -->

The webrtc framer, a busbar transport plugin (BUSBAR-1.6.0 l.754-767): ICE, SRTP (AEAD-AES-GCM only), SCTP over the host's udp carrier and DTLS layer; SRTP keys arrive through the keying-material item.

## Known residual: upstream copies of secrets are not zeroised

This plugin zeroises the SRTP keying material, the keys derived from it and the ICE password that its own types hold (`zeroize`, with tests). The published `str0m`, `dimpl` and `ring` crates it builds on do not zeroise their internal copies of these secrets when they drop them, so copies may remain in freed memory until it is reused. Exploiting this needs read access to the process's memory. It is a known residual risk, not fixed here. The ignored witness test `keying_material_on_the_accepted_path_is_never_freed_unzeroed` in `transport-webrtc/tests/zeroise.rs` measures it.
