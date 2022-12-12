// EdDSA - Signature on Twisted Edward curve.
// This implentation uses legacy parameters, and is not compatible with modern parameters based impls.
use super::ec25519::{ECCError, EdwardsPoint};

pub struct Ed25519;

impl Ed25519 {
    pub fn sign(key: [u8; 32], data: Vec<u8>) -> [u8; 64] {
        todo!()
    }

    pub fn verify(pubkey: [u8; 32], data: Vec<u8>, sign: [u8; 64]) -> Result<bool, ECCError> {
        todo!()
    }
}
