use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

// Operations over curve25519.
// parameters:
// y^2 = x^3 + 486662x^2 + x mod (2^255 - 19)
// p = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
// A = 0x0000000000000000000000000000000000000000000000000000000000076d06
// contains 8*q elements.
use crate::mp::LargeInt;
use crate::pke::arith::P25519FieldItem;
use std::ops::{Add, Mul};
const B: P25519FieldItem = P25519FieldItem([486662, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
const C121665: P25519FieldItem =
    P25519FieldItem([121665, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
pub const G: [u8; 32] = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// This struct describes point on curve25519.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MontgomeryCurvePoint {
    pub x: P25519FieldItem,
    pub y: P25519FieldItem,
    pub z: P25519FieldItem,
}

impl MontgomeryCurvePoint {
    pub fn normalize(&mut self) {
        self.x = self.x * self.z.inverse();
        self.y = self.y * self.z.inverse();
        self.z = 1.into();
    }

    pub fn scalar_mul(point: [u8; 32], scalar: [u8; 32]) -> [u8; 32] {
        let mut clamped;
        let mut a: P25519FieldItem = 0.into();
        let mut b;
        let mut c = a;
        let mut d = a;
        let mut e;
        let mut f;
        let mut x: P25519FieldItem = point.into();
        b = x;

        clamped = scalar;
        clamped[0] &= 0xf8;
        clamped[31] = (clamped[31] & 0x7f) | 0x40;

        a.0[0] = 1;
        d.0[0] = 1;

        for i in (0..255).rev() {
            let bit = (clamped[i >> 3] >> (i & 7)) & 1;
            a.swap(&mut b, bit as i64);
            c.swap(&mut d, bit as i64);
            e = a + c;
            a = a - c;
            c = b + d;
            b = b - d;
            d = e * e;
            f = a * a;
            a = c * a;
            c = b * e;
            e = a + c;
            a = a - c;
            b = a * a;
            c = d - f;
            a = c * C121665;
            a = a + d;
            c = c * a;
            a = d * f;
            d = b * x;
            b = e * e;
            a.swap(&mut b, bit as i64);
            c.swap(&mut d, bit as i64);
        }
        c = c.inverse();
        a = a * c;
        a.pack()
    }
}

#[test]
fn test_montegomery_mul() {
    let mut rng = ChaCha20Rng::from_entropy();
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    rng.fill_bytes(&mut a[..]);
    rng.fill_bytes(&mut b[..]);
    let a_pub = MontgomeryCurvePoint::scalar_mul(G, a);
    let b_pub = MontgomeryCurvePoint::scalar_mul(G, b);
    let k1 = MontgomeryCurvePoint::scalar_mul(a_pub, b);
    let k2 = MontgomeryCurvePoint::scalar_mul(b_pub, a);
    assert_eq!(k1, k2);
}
