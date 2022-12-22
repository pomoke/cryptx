use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::sha256::SHA256;

use super::curve25519::{MontgomeryCurvePoint, G};

pub struct ECDH;

impl ECDH {
    pub fn pubkey(a: [u8; 32]) -> [u8; 32] {
        MontgomeryCurvePoint::scalar_mul(G, a)
    }

    pub fn compute(a: [u8; 32], bp: [u8; 32]) -> [u8; 32] {
        let sk = MontgomeryCurvePoint::scalar_mul(bp, a);
        SHA256::do_hash(&sk[..])
    }
}
