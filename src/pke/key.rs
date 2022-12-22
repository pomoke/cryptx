// x25519 based encryption
use crate::mp::LargeInt;
use anyhow::Result;
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;

pub struct X25519PrivateKey(LargeInt<32>);
/// Public Key for curve22519
///
/// Any 32-byte integer is a valid public key.
pub struct X25519PublicKey(LargeInt<32>);

impl X25519PrivateKey {
    pub fn new() -> Result<Self> {
        // Get a 32 byte safe random number.
        let mut rng = ChaCha20Rng::from_entropy();
        todo!()
    }

    pub fn pubkey() -> X25519PublicKey {
        todo!()
    }
}
