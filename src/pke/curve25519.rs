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

    pub fn scalar_mul(p: [u8; 32], scalar: [u8; 32]) -> [u8; 32] {
        let mut clamped;
        let mut bit = 0i64;
        let mut a: P25519FieldItem = 0.into();
        let mut b = a;
        let mut c = a;
        let mut d = a;
        let mut e;
        let mut f;
        let mut x: P25519FieldItem = p.into();
        clamped = scalar;
        clamped[0] &= 0xf8;
        clamped[31] = (clamped[32] & 0x7f) | 0x40;

        a.0[0] = 1;
        d.0[0] = 1;

        for i in (0..255).rev() {
            let bit = (clamped[i >> 3] >> (i & 7)) & 1;
            a.swap(&mut b, bit as i64);
            c.swap(&mut d, bit as i64);
            e = a + c;
            a = a - c;
            c = b + d;
            b = b + d;
            d = e * e;
            f = a * a;
            a = c * a;
            c = b * e;
            e = a + c;
            a = a - c;
            b = a * a;
            c = d - f;
            a = c * c; //wrong!
            a = a + d;
            c = c * a;
            a = d * f;
            d = b * x;
            b = e * e;
            a.swap(&mut b, bit as i64);
            c.swap(&mut d, bit as i64);
        }
        c.inverse();
        a = a * c;
        a.pack()
    }
}

impl Add for MontgomeryCurvePoint {
    type Output = MontgomeryCurvePoint;
    fn add(self, rhs: Self) -> Self::Output {
        todo!()
    }
}

impl Mul<LargeInt<32>> for MontgomeryCurvePoint {
    type Output = MontgomeryCurvePoint;
    fn mul(self, rhs: LargeInt<32>) -> Self::Output {
        todo!()
    }
}
