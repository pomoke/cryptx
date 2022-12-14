use crate::common::CryptoHash;
use crate::pke::arith_n::ModNItem;
// mqv.rs - FHMQV authenticated key exchange.
use crate::wire;
use crate::{aes, sha256::SHA256};

use super::arith::P25519FieldItem;
use super::ec25519::{ECCError, EdwardsPoint, G};
use hex::ToHex;
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
pub trait AuthenticatedKEX<const N: usize> {}

/// Full-hashed Menezes-Qu-Vanstone.
#[derive(Debug)]
pub struct FHMQV {
    pubkey: EdwardsPoint,
    privkey: [u8; 32],
    session_key: [u8; 32],
    session_pubkey: EdwardsPoint,
    ///Public key, session key
    remote_cred: Option<(EdwardsPoint, EdwardsPoint)>,
}

impl FHMQV {
    pub fn new(privkey: [u8; 32], session_key: [u8; 32]) -> Self {
        let mut privkey = privkey;
        let mut session_key = session_key;
        //privkey[0] &= 0xf8;
        privkey[31] = (privkey[31] & 0x7f) | 0x40;
        //session_key[0] &= 0xf8;
        session_key[31] = (session_key[31] & 0x7f) | 0x40;
        let public_key = privkey * G;
        let session_pk = session_key * G;
        Self {
            pubkey: public_key,
            privkey: privkey,
            session_key: session_key,
            session_pubkey: session_pk,
            remote_cred: None,
        }
    }

    /// Generate (\hat A,X) or (\hat B,Y) and send.
    pub fn send(&self) -> ([u8; 32], [u8; 32]) {
        (
            self.pubkey.encode_point(),
            self.session_pubkey.encode_point(),
        )
    }

    /// Set received key.
    ///
    /// If any point is of subgroup of 8, then will return error.
    pub fn set_remote_key(
        &mut self,
        remote_public_key: [u8; 32],
        remote_session_key: [u8; 32],
    ) -> Result<(), ECCError> {
        let remote_pk: Result<EdwardsPoint, ECCError> = remote_public_key.try_into();
        let remote_sk: Result<EdwardsPoint, ECCError> = remote_session_key.try_into();
        if let (Ok(pk), Ok(sk)) = (remote_pk, remote_sk) {
            let pk_nok = pk.is_cofactor();
            let sk_nok = sk.is_cofactor();
            let nok = pk_nok | sk_nok;
            if nok {
                return Err(ECCError::SmallOrderAttack);
            }
            self.remote_cred = Some((pk, sk));
            Ok(())
        } else {
            Err(ECCError::InvalidPoint)
        }
    }

    /// Compute shared session key for server (recipient).
    ///
    /// Server holds b,y.
    /// If no remote keys provided, `None` will be returned.
    pub fn key_server(&self) -> Result<[u8; 32], ECCError> {
        if let Some((remote_pk, remote_sk)) = self.remote_cred {
            let y = self.session_key;
            let b = self.privkey;
            let a_pk = remote_pk.encode_point();
            let b_pk = self.pubkey.encode_point();
            let x_pk = remote_sk.encode_point();
            let y_pk = self.session_pubkey.encode_point();

            let mut data_d: Vec<u8> = vec![];
            data_d.extend_from_slice(&x_pk[..]);
            data_d.extend_from_slice(&y_pk[..]);
            data_d.extend_from_slice(&a_pk[..]);
            data_d.extend_from_slice(&b_pk[..]);
            let d = SHA256::hash(&data_d);

            let mut data_e: Vec<u8> = vec![];
            data_e.extend_from_slice(&y_pk[..]);
            data_e.extend_from_slice(&x_pk[..]);
            data_e.extend_from_slice(&a_pk[..]);
            data_e.extend_from_slice(&b_pk[..]);
            let e = SHA256::hash(&data_e);

            /*
            let s = y + e * b;
            let s2 = s.clone();
            let a_coeff = s * d;
            let point = EdwardsPoint::mul_add(s2.into(), remote_sk, a_coeff.into(), remote_pk);
            */
            let s1 = remote_sk * b * e;
            let s2 = remote_sk * y;
            let s2 = s1 + s2;

            let s3 = remote_pk * b * e;
            let s4 = remote_pk * y;
            let s4 = s3 + s4;
            let s4 = s4 * d;
            let point = s2 + s4;
            //let point = s.pack()*(remote_sk + d.pack()*remote_pk);
            let point_bin = point.encode_point();
            let mut data_key: Vec<u8> = vec![];
            data_key.extend_from_slice(&point_bin[..]);
            data_key.extend_from_slice(&a_pk[..]);
            data_key.extend_from_slice(&b_pk[..]);
            data_key.extend_from_slice(&x_pk[..]);
            data_key.extend_from_slice(&y_pk[..]);
            let shared_key = SHA256::hash(&data_key);

            Ok(shared_key)
        } else {
            Err(ECCError::NoExchange)
        }
    }

    /// Compute shared session key for client (initator).
    ///
    /// If no remote keys provided, `None` will be returned.
    pub fn key_client(&self) -> Result<[u8; 32], ECCError> {
        if let Some((remote_pk, remote_sk)) = self.remote_cred {
            let x = self.session_key;
            let a = self.privkey;
            let b_pk = remote_pk.encode_point();
            let a_pk = self.pubkey.encode_point();
            let y_pk = remote_sk.encode_point();
            let x_pk = self.session_pubkey.encode_point();

            let mut data_d: Vec<u8> = vec![];
            data_d.extend_from_slice(&x_pk[..]);
            data_d.extend_from_slice(&y_pk[..]);
            data_d.extend_from_slice(&a_pk[..]);
            data_d.extend_from_slice(&b_pk[..]);
            let d = SHA256::hash(&data_d);

            let mut data_e: Vec<u8> = vec![];
            data_e.extend_from_slice(&y_pk[..]);
            data_e.extend_from_slice(&x_pk[..]);
            data_e.extend_from_slice(&a_pk[..]);
            data_e.extend_from_slice(&b_pk[..]);
            let e = SHA256::hash(&data_e);

            //let s = x + d * a;
            //let s2 = s.clone();
            //let a_coeff = s * e;
            //let point = EdwardsPoint::mul_add(s2.into(), remote_sk, a_coeff.into(), remote_pk);
            let s1 = remote_sk * a * d;
            let s2 = remote_sk * x;
            let s2 = s1 + s2;

            let s3 = remote_pk * a * d;
            let s4 = remote_pk * x;
            let s4 = s3 + s4;
            let s4 = s4 * e;
            let point = s2 + s4;
            //let point = s.pack()*(remote_sk + e.pack()*remote_pk);
            let point_bin = point.encode_point();
            let mut data_key: Vec<u8> = vec![];
            data_key.extend_from_slice(&point_bin[..]);
            data_key.extend_from_slice(&a_pk[..]);
            data_key.extend_from_slice(&b_pk[..]);
            data_key.extend_from_slice(&x_pk[..]);
            data_key.extend_from_slice(&y_pk[..]);
            let shared_key = SHA256::hash(&data_key);

            Ok(shared_key)
        } else {
            Err(ECCError::NoExchange)
        }
    }
}

impl AuthenticatedKEX<32> for FHMQV {}

#[test]
fn test_fhmqv() {
    let mut rng = ChaCha20Rng::from_entropy();
    for _ in 0..10 {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        rng.fill_bytes(&mut a[..]);
        rng.fill_bytes(&mut b[..]);
        rng.fill_bytes(&mut x[..]);
        rng.fill_bytes(&mut y[..]);

        let mut client = FHMQV::new(a, x);
        let mut server = FHMQV::new(b, y);

        let (send_a, send_x) = client.send();
        let (send_b, send_y) = server.send();

        server.set_remote_key(send_a, send_x).unwrap();
        client.set_remote_key(send_b, send_y).unwrap();
        assert_eq!(
            server.pubkey.x.pack(),
            client.remote_cred.unwrap().0.x.pack()
        );
        assert_eq!(
            server.pubkey.y.pack(),
            client.remote_cred.unwrap().0.y.pack()
        );
        assert_eq!(
            client.pubkey.x.pack(),
            server.remote_cred.unwrap().0.x.pack()
        );
        assert_eq!(
            client.pubkey.y.pack(),
            server.remote_cred.unwrap().0.y.pack()
        );

        assert_eq!(
            server.pubkey.encode_point(),
            client.remote_cred.unwrap().0.encode_point()
        );
        assert_eq!(
            client.pubkey.encode_point(),
            server.remote_cred.unwrap().0.encode_point()
        );
        assert_eq!(
            server.session_pubkey.encode_point(),
            client.remote_cred.unwrap().1.encode_point()
        );
        assert_eq!(
            client.session_pubkey.encode_point(),
            server.remote_cred.unwrap().1.encode_point()
        );

        //println!("client: {:?}", client);
        //println!("server: {:?}", server);
        assert_eq!(server.key_server().unwrap(), client.key_client().unwrap());
    }
}
