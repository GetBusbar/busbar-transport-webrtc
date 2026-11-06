// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host shim as the media stack sees it: no certificate of its own, the role it is set to, and
//! what it hands back from the relay.

use super::*;

#[test]
fn the_host_makes_no_certificate_and_a_fresh_shim_per_association() {
    assert!(
        Host.generate_certificate().is_none(),
        "the host's certificate is presented, never made"
    );
    let cert = DtlsCert {
        certificate: b"public".to_vec(),
        private_key: Vec::new(),
    };
    let shim = Host
        .new_dtls(&cert, Instant::now(), DtlsVersion::Dtls12, None)
        .expect("a shim");
    assert!(
        !shim.is_active(),
        "a shim is passive until the stack sets its role"
    );
    assert!(
        shim.protocol_version().is_none(),
        "the shim negotiates no protocol"
    );
    assert!(!shim.is_closed());
}

#[test]
fn the_shim_reports_the_role_it_is_set_to() {
    let mut shim = Shim::default();
    shim.set_active(true);
    assert!(shim.is_active());
    shim.set_active(false);
    assert!(!shim.is_active());
}

#[test]
fn relayed_data_too_large_for_the_stacks_buffer_is_dropped_and_the_next_is_handed_on() {
    let mut shim = Shim::default();
    shim.connected();
    shim.opened(&[1; 64]);
    shim.opened(&[2; 8]);
    let mut buf = [0_u8; 16];
    assert!(matches!(shim.poll_output(&mut buf), DtlsOutput::Connected));
    match shim.poll_output(&mut buf) {
        DtlsOutput::ApplicationData(d) => {
            assert_eq!(d, &[2; 8], "the oversized datagram was skipped")
        }
        _ => panic!("the plaintext that fits is handed on"),
    }
    shim.send_application_data(&[3; 64]).expect("connected");
    shim.send_application_data(&[4; 8]).expect("connected");
    match shim.poll_output(&mut buf) {
        DtlsOutput::Packet(p) => {
            assert_eq!(p[0], SEAL);
            assert_eq!(&p[1..], &[4; 8], "the oversized seal was skipped");
        }
        _ => panic!("the plaintext to seal that fits is handed on"),
    }
    assert!(matches!(shim.poll_output(&mut buf), DtlsOutput::Timeout(_)));
}
