// Operations over curve25519
// parameters:
// y^2 = x^3 + 486662x^2 + x mod (2^255 - 19)
// p = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
// A = 0x0000000000000000000000000000000000000000000000000000000000076d06
// contains 8*q elements.
use crate::mp::LargeInt;
use std::ops::{Add, Mul};

/// This struct describes point on curve25519.
#[derive(Debug)]
struct MontgomeryCurvePoint {
    pub x: LargeInt<32>,
    pub y: LargeInt<32>,
}

impl MontgomeryCurvePoint {}

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
