// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn managed_gcm_preserves_ring_wire_bytes_and_refuses_modified_packets() {
    use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey};

    for algorithm in [&AES_128_GCM, &AES_256_GCM] {
        let key = vec![0x73; algorithm.key_len()];
        let mut cipher = Gcm::new(algorithm, &key).unwrap();
        let reference = LessSafeKey::new(UnboundKey::new(algorithm, &key).unwrap());
        for (index, len) in [0, 1, 15, 16, 17, 64, 1031].into_iter().enumerate() {
            let nonce = [u8::try_from(index).unwrap(); 12];
            let plain = vec![0x45; len];
            let header = vec![0x56; index * 257];
            let mut expected = plain.clone();
            reference
                .seal_in_place_append_tag(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::from(&header),
                    &mut expected,
                )
                .unwrap();
            let mut sealed = vec![0; len + 16];
            cipher.seal(&nonce, &header, &plain, &mut sealed).unwrap();
            assert_eq!(sealed, expected);
            let mut opened = vec![0xa5; len];
            let third = header.len() / 3;
            let aads = [
                &header[..third],
                &header[third..2 * third],
                &header[2 * third..],
            ];
            assert_eq!(
                cipher.open(&nonce, &aads, &sealed, &mut opened).unwrap(),
                len
            );
            assert_eq!(opened, plain);
            *sealed.last_mut().unwrap() ^= 1;
            assert!(cipher.open(&nonce, &aads, &sealed, &mut opened).is_err());
            assert!(opened.iter().all(|byte| *byte == 0));
            *sealed.last_mut().unwrap() ^= 1;
            assert_eq!(
                cipher.open(&nonce, &aads, &sealed, &mut opened).unwrap(),
                len
            );
            assert_eq!(opened, plain);
        }
    }
}
