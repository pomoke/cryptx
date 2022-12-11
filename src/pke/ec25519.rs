use serde::{Deserialize, Serialize};

// Operations over ec25519.
// parameters:
// A                     B
// 486664x^2 + y^2 = 1 + 486660x^2*y^2 mod (2^255-19)
// p = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed

// Though ec25519 and curve25519 can be mapped,
// this conversion will not be used as one key can be safely used on only on algorithm.
use crate::pke::arith::P25519FieldItem;
use std::ops::{Add, Mul};
const A: P25519FieldItem = P25519FieldItem([486664, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
const B: P25519FieldItem = P25519FieldItem([486660, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

/// This struct describes point on curve25519.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdwardsPoint {
    pub x: P25519FieldItem,
    pub y: P25519FieldItem,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdwardsPointCompute {
    pub x: P25519FieldItem,
    pub y: P25519FieldItem,
    pub z: P25519FieldItem,
    pub t: P25519FieldItem,
}

impl EdwardsPointCompute {
    pub fn normalize(&self) -> EdwardsPoint {
        todo!();
    }
}

/// We need aP + bQ, but curve25519 is not optimal.
/// curve25519 is optimized for variable base and scale, but work terrible for addition.
impl EdwardsPoint {}

impl Add<EdwardsPoint> for EdwardsPoint {
    type Output = EdwardsPoint;
    fn add(self, rhs: EdwardsPoint) -> Self::Output {
        todo!()
    }
}
