use num_bigint::BigUint;
use std::ops::{Add, Mul};

// Arithmetric over n (order of G).
const N: [u32; 8] = [
    0x5cf5d3ed, 0x5812631a, 0xa2f79cd6, 0x14def9de, 0x00000000, 0x00000000, 0x00000000, 0x10000000,
];

#[derive(Clone)]
pub struct ModNItem(BigUint);

impl ModNItem {
    pub fn from_bytes(a: [u8; 32]) -> Self {
        Self(BigUint::from_bytes_le(&a[..]))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut ret = [0u8; 32];
        let bytes = self.0.to_bytes_le();
        for i in 0..(bytes.len()) {
            ret[i] = bytes[i];
        }
        ret
    }
}

impl Add<ModNItem> for ModNItem {
    type Output = ModNItem;
    fn add(self, rhs: ModNItem) -> Self::Output {
        let n = BigUint::from_slice(&N[..]);
        ModNItem((self.0 + rhs.0) % n)
    }
}

impl Mul<ModNItem> for ModNItem {
    type Output = ModNItem;
    fn mul(self, rhs: ModNItem) -> Self::Output {
        let n = BigUint::from_slice(&N[..]);
        ModNItem((self.0 * rhs.0) % n)
    }
}

impl From<[u8; 32]> for ModNItem {
    fn from(t: [u8; 32]) -> Self {
        Self::from_bytes(t)
    }
}

impl From<ModNItem> for [u8; 32] {
    fn from(t: ModNItem) -> [u8; 32] {
        t.to_bytes()
    }
}
