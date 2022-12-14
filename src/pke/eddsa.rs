use crate::sha256::SHA256;

// EdDSA - Signature on Twisted Edward curve.
// This implentation uses legacy parameters, and is not compatible with modern parameters based impls.
use super::ec25519::{ECCError, EdwardsPoint, G};

/// This is not an ed25519, but ElGamal over edward25519.
pub struct ElGamal;

impl ElGamal {
    pub fn sign(key: [u8; 32], data: Vec<u8>) -> [u8; 64] {
        let pubkey = key * G;
        let mut secret_source = vec![];
        secret_source.extend_from_slice(&key[..]);
        secret_source.extend_from_slice(&data);
        let k = SHA256::do_hash(&secret_source);
        let m = SHA256::do_hash(&data);
        let m = m * G;
        let c = k * pubkey + m;

        let k = k * G;
        let k = k.encode_point();
        let c = c.encode_point();
        let mut result = [0u8; 64];
        for i in 0..32 {
            result[i] = k[i];
            result[32 + i] = c[i];
        }

        result
    }

    pub fn verify(pubkey: [u8; 32], data: Vec<u8>, sign: [u8; 64]) -> Result<bool, ECCError> {
        let pubkey = EdwardsPoint::recover_point(pubkey).ok_or(ECCError::InvalidPoint)?;
        let mut k = [0u8; 32];
        let mut c = [0u8; 32];
        for i in 0..32 {
            k[i] = sign[i];
            c[i] = sign[32 + i];
        }
        let k = EdwardsPoint::recover_point(k).ok_or(ECCError::InvalidPoint)?;
        let c = EdwardsPoint::recover_point(c).ok_or(ECCError::InvalidPoint)?;
        todo!()
    }
}
