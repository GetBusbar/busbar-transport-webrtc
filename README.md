<!-- fleet:header:begin (rendered by `busbar-release plugin heal` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-transport-webrtc

First-party signed kind:transport plugin cdylib: the webrtc transport, packaged as a droppable busbar plugin. Drop the signed tarball into plugins/.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `transport` | `webrtc` | `busbar-transport-webrtc-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

[![ci](https://github.com/GetBusbar/busbar-transport-webrtc/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-transport-webrtc/actions/workflows/ci.yml)
<!-- fleet:header:end -->

The webrtc framer, a busbar transport plugin (BUSBAR-1.6.0 l.754-767): ICE, SRTP (AEAD-AES-GCM only), SCTP over the host's udp carrier and DTLS layer; SRTP keys arrive through the keying-material item.
