//! Shared-secret handshake authentication and length-preserving ChaCha20.
//!
//! This is intentionally NOT authenticated encryption. Routing headers and
//! session errors are public; encrypted traffic is malleable. Use TLS inside
//! the tunnel when protection against active attackers is required.

use std::fmt;
use std::sync::Arc;

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

use crate::wire::{CookieInput, Direction, VERSION};

pub const SECRET_MIN_LEN: usize = 32;
pub const PROOF_LEN: usize = 32;
/// Public version/flags, session ID, and exchange ID. Everything following
/// these existing nine bytes is encrypted, including the client's rx_lag.
pub const ROUTING_LEN: usize = 9;

#[derive(Clone)]
pub struct SharedSecret(Arc<[u8]>);

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedSecret(<redacted>)")
    }
}

impl SharedSecret {
    /// Raw high-entropy bytes, not a password. At least 256 bits are required.
    pub fn new(bytes: Vec<u8>) -> Option<Self> {
        (bytes.len() >= SECRET_MIN_LEN).then(|| Self(bytes.into()))
    }

    fn mac(
        &self,
        label: &[u8],
        input: &CookieInput<'_>,
        cookie: &[u8; 20],
        session: u32,
    ) -> Hmac<Sha256> {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.0).expect("HMAC key length");
        mac.update(label);
        mac.update(&transcript(input, cookie, session));
        mac
    }

    pub fn client_proof(&self, input: &CookieInput<'_>, cookie: &[u8; 20]) -> [u8; PROOF_LEN] {
        self.mac(b"cloudyday v2 client proof", input, cookie, 0)
            .finalize()
            .into_bytes()
            .into()
    }

    pub fn verify_client(
        &self,
        input: &CookieInput<'_>,
        cookie: &[u8; 20],
        proof: &[u8; PROOF_LEN],
    ) -> bool {
        self.mac(b"cloudyday v2 client proof", input, cookie, 0)
            .verify_slice(proof)
            .is_ok()
    }

    pub fn server_proof(
        &self,
        input: &CookieInput<'_>,
        cookie: &[u8; 20],
        session: u32,
    ) -> [u8; PROOF_LEN] {
        self.mac(b"cloudyday v2 server proof", input, cookie, session)
            .finalize()
            .into_bytes()
            .into()
    }

    pub fn verify_server(
        &self,
        input: &CookieInput<'_>,
        cookie: &[u8; 20],
        session: u32,
        proof: &[u8; PROOF_LEN],
    ) -> bool {
        self.mac(b"cloudyday v2 server proof", input, cookie, session)
            .verify_slice(proof)
            .is_ok()
    }

    /// Keys come from the secret, never from the publicly transmitted proof.
    pub fn session_keys(
        &self,
        input: &CookieInput<'_>,
        cookie: &[u8; 20],
        session: u32,
    ) -> SessionKeys {
        let salt = Sha256::digest(transcript(input, cookie, session));
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), &self.0);
        let mut client_to_server = [0; 32];
        let mut server_to_client = [0; 32];
        hkdf.expand(b"cloudyday v2 client to server", &mut client_to_server)
            .expect("32-byte HKDF output");
        hkdf.expand(b"cloudyday v2 server to client", &mut server_to_client)
            .expect("32-byte HKDF output");
        SessionKeys {
            client_to_server,
            server_to_client,
        }
    }
}

fn transcript(input: &CookieInput<'_>, cookie: &[u8; 20], session: u32) -> Vec<u8> {
    let mut bytes = vec![VERSION];
    bytes.extend_from_slice(input.domain_wire);
    bytes.extend_from_slice(input.client_nonce);
    bytes.extend_from_slice(input.server_nonce);
    bytes.extend_from_slice(&input.u.to_be_bytes());
    bytes.extend_from_slice(&input.d.to_be_bytes());
    bytes.extend_from_slice(cookie);
    bytes.extend_from_slice(&session.to_be_bytes());
    bytes
}

#[derive(Clone)]
pub struct SessionKeys {
    client_to_server: [u8; 32],
    server_to_client: [u8; 32],
}

impl fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionKeys(<redacted>)")
    }
}

impl SessionKeys {
    /// Symmetric encryption/decryption, with no transmitted nonce or tag.
    /// Callers MUST send each exchange only once or reuse the exact ciphertext;
    /// never encrypt different bytes with the same keys/direction/exchange ID.
    pub fn apply(&self, bytes: &mut [u8], direction: Direction) -> Option<()> {
        let minimum = ROUTING_LEN + usize::from(direction == Direction::ClientToServer);
        if bytes.len() < minimum {
            return None;
        }
        if bytes[1..5] == [0; 4] || bytes[5..9] == [0; 4] {
            return None;
        }
        let key = match direction {
            Direction::ClientToServer => &self.client_to_server,
            Direction::ServerToClient => &self.server_to_client,
        };
        // 00000000 || session_id (BE) || exchange_id (BE), IETF 96-bit nonce.
        // The stream begins at block counter zero; each envelope is <=512 bytes.
        let mut nonce = [0; 12];
        nonce[4..].copy_from_slice(&bytes[1..9]);
        let mut cipher = ChaCha20::new(key.into(), (&nonce).into());
        cipher.apply_keystream(&mut bytes[ROUTING_LEN..]);
        Some(())
    }
}

#[cfg(test)]
pub(crate) fn fixture_keys() -> SessionKeys {
    let input = CookieInput {
        domain_wire: b"\x01t\x07example\x03com\x00",
        client_nonce: &std::array::from_fn(|i| i as u8),
        server_nonce: &std::array::from_fn(|i| (i + 16) as u8),
        u: 111,
        d: 182,
    };
    let cookie = input.make(&std::array::from_fn(|i| i as u8), 1_700_000_030);
    SharedSecret::new((0..32).collect())
        .unwrap()
        .session_keys(&input, &cookie, 0x01020304)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{Envelope, Frame};

    #[test]
    fn secret_validation_and_redaction() {
        assert!(SharedSecret::new(vec![0; 31]).is_none());
        assert_eq!(
            format!("{:?}", SharedSecret::new(vec![0; 32]).unwrap()),
            "SharedSecret(<redacted>)"
        );
        assert_eq!(format!("{:?}", fixture_keys()), "SessionKeys(<redacted>)");
    }

    #[test]
    fn proofs_bind_identity_parameters_cookie_and_assigned_session() {
        let secret = SharedSecret::new(vec![7; 32]).unwrap();
        let input = CookieInput {
            domain_wire: b"\x01t\x00",
            client_nonce: &[1; 16],
            server_nonce: &[2; 16],
            u: 100,
            d: 180,
        };
        let cookie = input.make(&[3; 32], 1_700_000_030);
        let proof = secret.client_proof(&input, &cookie);
        assert!(secret.verify_client(&input, &cookie, &proof));
        assert!(
            !SharedSecret::new(vec![8; 32])
                .unwrap()
                .verify_client(&input, &cookie, &proof)
        );
        for other in [
            CookieInput {
                domain_wire: b"\x01u\x00",
                ..input
            },
            CookieInput {
                client_nonce: &[2; 16],
                ..input
            },
            CookieInput {
                server_nonce: &[3; 16],
                ..input
            },
            CookieInput { u: 101, ..input },
            CookieInput { d: 181, ..input },
        ] {
            assert!(!secret.verify_client(&other, &cookie, &proof));
        }
        let mut changed = cookie;
        changed[0] ^= 1;
        assert!(!secret.verify_client(&input, &changed, &proof));
        let server = secret.server_proof(&input, &cookie, 1);
        assert!(secret.verify_server(&input, &cookie, 1, &server));
        assert!(!secret.verify_server(&input, &cookie, 2, &server));
        assert!(!secret.verify_server(&input, &cookie, 1, &proof));
    }

    #[test]
    fn independent_python_handshake_kdf_and_chacha20_vectors() {
        let hex = |s: &str| {
            s.split_whitespace()
                .map(|b| u8::from_str_radix(b, 16).unwrap())
                .collect::<Vec<_>>()
        };
        let cn = std::array::from_fn(|i| i as u8);
        let sn = std::array::from_fn(|i| (i + 16) as u8);
        let input = CookieInput {
            domain_wire: b"\x01t\x07example\x03com\x00",
            client_nonce: &cn,
            server_nonce: &sn,
            u: 111,
            d: 182,
        };
        let secret = SharedSecret::new((0..32).collect()).unwrap();
        let cookie = input.make(&std::array::from_fn(|i| i as u8), 1_700_000_030);
        assert_eq!(
            cookie.as_slice(),
            hex("65 53 f1 1e fd e9 2d 55 c4 c5 41 7c 2c 9e f0 3a a5 19 86 96")
        );
        assert_eq!(
            secret.client_proof(&input, &cookie).as_slice(),
            hex(
                "d4 46 94 f0 e1 51 c9 84 63 ec 89 7b e7 60 55 f1 72 8b bd 2a 15 0e 30 61 e6 99 20 9f fb 72 e1 80"
            )
        );
        assert_eq!(
            secret.server_proof(&input, &cookie, 0x01020304).as_slice(),
            hex(
                "c6 d3 e8 d7 76 8e ad 65 f4 76 df a3 ff d5 30 de 5d ab 3a 87 1c 36 af b3 b3 bd e5 65 be bf 40 78"
            )
        );
        let keys = secret.session_keys(&input, &cookie, 0x01020304);
        assert_eq!(
            keys.client_to_server.as_slice(),
            hex(
                "e0 7c 09 f3 c6 59 38 3e c5 c2 28 bd 4a d7 8b 1c bd 24 39 d5 3e 49 6d be 81 70 3e 03 7c 76 24 49"
            )
        );
        assert_eq!(
            keys.server_to_client.as_slice(),
            hex(
                "f3 cd 3c a2 18 86 97 00 0f e2 79 61 df c4 de 28 e0 b0 5a 15 a3 5a 9a b3 08 0c c8 1b 3b 98 e2 ad"
            )
        );
        let mut mixed = hex(
            "40 01 02 03 04 00 00 00 06 01 12 0e 00 00 00 01 00 00 00 03 00 00 00 02 00 1e 10 0d 00 00 00 01 00 00 00 00 68 65 6c 6c 6f",
        );
        keys.apply(&mut mixed, Direction::ClientToServer).unwrap();
        assert_eq!(
            mixed,
            hex(
                "40 01 02 03 04 00 00 00 06 b6 5b ad 27 69 06 26 4c c9 4e 08 2e 8a 04 d6 f3 d1 ba dc d1 c4 e5 71 f1 20 ad d2 d5 f2 a7 69 56"
            )
        );
        let mut ack =
            hex("40 01 02 03 04 00 00 00 07 12 0e 00 00 00 01 00 00 00 21 00 00 00 00 00 00");
        keys.apply(&mut ack, Direction::ServerToClient).unwrap();
        assert_eq!(
            ack,
            hex("40 01 02 03 04 00 00 00 07 af 1b a3 70 ee d7 cb c9 01 a5 c6 05 c3 c6 ed 8a")
        );
        let next = secret.session_keys(&input, &cookie, 0x01020305);
        assert_ne!(keys.client_to_server, next.client_to_server);
        assert_ne!(keys.server_to_client, next.server_to_client);
    }

    #[test]
    fn encryption_has_zero_overhead_and_separates_direction_and_exchange() {
        let keys = fixture_keys();
        let raw = Envelope::client(
            0x01020304,
            1,
            255,
            vec![Frame::Segment {
                stream: 1,
                seq: 0,
                payload: b"hello".to_vec(),
            }],
        )
        .encode();
        let mut encrypted = raw.clone();
        keys.apply(&mut encrypted, Direction::ClientToServer)
            .unwrap();
        assert_eq!(encrypted.len(), raw.len());
        assert_eq!(&encrypted[..9], &raw[..9]);
        assert_ne!(&encrypted[9..], &raw[9..]);
        let mut other = raw.clone();
        keys.apply(&mut other, Direction::ServerToClient).unwrap();
        assert_ne!(other[9..], encrypted[9..]);
        other = raw.clone();
        other[8] = 2;
        keys.apply(&mut other, Direction::ClientToServer).unwrap();
        assert_ne!(other[9..], encrypted[9..]);
        keys.apply(&mut encrypted, Direction::ClientToServer)
            .unwrap();
        assert_eq!(encrypted, raw);
        // Explicitly demonstrate the accepted limitation: ciphertext bit flips
        // cause the same plaintext bit flips; there is no integrity check.
        keys.apply(&mut encrypted, Direction::ClientToServer)
            .unwrap();
        let last = encrypted.len() - 1;
        encrypted[last] ^= 1;
        keys.apply(&mut encrypted, Direction::ClientToServer)
            .unwrap();
        assert_eq!(encrypted[last], raw[last] ^ 1);
    }
}
