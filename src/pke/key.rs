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
        let mut ret = Self(LargeInt { data: [0;32] });
        rng.fill_bytes(&mut ret.0.data[..]);
        // Clear bit 
        ret.0.data[0] &= 0b1111_1000;
        ret.0.data[31] &= 0b0111_1111;
        ret.0.data[31] |= 0b0100_0000;
        Ok(ret)
    } 

    pub fn pubkey() -> X25519PublicKey {
        todo!()
    }
}