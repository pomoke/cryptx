use super::arith::{ITEM25519, ONE, TWO, ZERO};
use hex::{FromHex, ToHex};
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// Operations over ec25519.
// parameters (classic):
// A                     D                  p
// 486664x^2 + y^2 = 1 + 486660x^2*y^2 mod (2^255-19)
// p = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed

// Though ec25519 and curve25519 can be mapped,
// this conversion will not be used as one key can be safely used on only on algorithm.
use crate::pke::arith::P25519FieldItem;
use core::panic;
use std::ops::{Add, Mul};
pub const A: P25519FieldItem =
    P25519FieldItem([27912, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
pub const D: P25519FieldItem =
    P25519FieldItem([27908, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
pub const EIGHT: [u8; 32] = [
    8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
/// Base point G.
/// see: https://fastd.readthedocs.io/en/stable/crypto/ec25519.html
pub const G: EdwardsPoint = EdwardsPoint {
    x: P25519FieldItem([
        0x6bd4, 0x7ffe, 0xfa39, 0x228c, 0x96e1, 0xeb23, 0xb726, 0x6a8e, 0x7434, 0x668b, 0xa3d6,
        0xdd26, 0x5e19, 0x219f, 0x4350, 0x547c,
    ]),
    y: P25519FieldItem([
        0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
        0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
    ]),
};

/// Constant 'zero' E
pub const E: EdwardsPoint = EdwardsPoint {
    x: P25519FieldItem([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
    y: P25519FieldItem([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
};

#[derive(Error, Debug)]
pub enum ECCError {
    #[error("invalid point.")]
    InvalidPoint,
    #[error("key exchange has not commenced properly.")]
    NoExchange,
    #[error("attempt to attack - point over small subgroup.")]
    SmallOrderAttack,
}

/// This struct describes point on curve25519.
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct EdwardsPoint {
    pub x: P25519FieldItem,
    pub y: P25519FieldItem,
}

/// We need aP + bQ, only aP does not work.
/// curve25519 is optimized for variable base and scale, but work terrible for addition.
impl EdwardsPoint {
    pub fn pack(&self) -> ([u8; 32], [u8; 32]) {
        let ret_x = self.x.pack();
        let ret_y = self.y.pack();
        (ret_x, ret_y)
    }

    /// computes aP+bQ .
    pub fn mul_add(a: [u8; 32], p: Self, b: [u8; 32], q: Self) -> Self {
        a * p + b * q
    }

    pub fn recover_point(point: [u8; 32]) -> Option<Self> {
        // y^2 = sqrt((1-ax^2)/(1-dx^2))
        // which y depends on sign bit.
        let sign = (point[31] & 0x80) != 0;
        let mut point = point;
        point[31] &= 0x7f;
        let x: P25519FieldItem = point.into();
        let mut a = ONE - A * x * x;
        a.carry();
        let mut b = ONE - D * x * x;
        b.carry();
        let c = a * (b.inverse());
        let y = c.sqrt();
        match (y, sign) {
            (Some(k), true) => Some(Self { x: x, y: k.1 }),
            (Some(k), false) => Some(Self { x: x, y: k.0 }),
            (None, _) => None,
        }
    }

    pub fn encode_point(&self) -> [u8; 32] {
        let mut ret: [u8; 32] = self.x.into();
        let mut x = self.x;
        ret[31] &= 0x7f;
        let a = A * x * x - ONE;
        let b = D * x * x - ONE;
        let c = a * (b.inverse());
        let y_sqrt = c.sqrt();
        let y = self.y;
        if let Some((y1, y2)) = y_sqrt {
            if y.pack() == y1.pack() {
                ret[31] &= 0x7f;
            } else if y.pack() == y2.pack() {
                ret[31] |= 0x80;
            } else {
                println!(
                    "y,y1,y2: {} {} {}",
                    y.pack().encode_hex::<String>(),
                    y1.pack().encode_hex::<String>(),
                    y2.pack().encode_hex::<String>()
                );
                panic!()
            }
        } else {
            panic!()
        }
        // Check for which sign.
        ret
    }

    /// Check if the point is in subgroup of size 8.
    pub fn is_cofactor(&self) -> bool {
        (*self * EIGHT).pack() == self.pack()
    }

    pub fn get_pubkey(privkey: [u8; 32]) -> [u8; 32] {
        let point = privkey * G;
        point.encode_point()
    }
}

impl TryFrom<[u8; 32]> for EdwardsPoint {
    type Error = ECCError;
    fn try_from(point: [u8; 32]) -> Result<EdwardsPoint, ECCError> {
        EdwardsPoint::recover_point(point).ok_or(ECCError::InvalidPoint)
    }
}

impl From<EdwardsPoint> for [u8; 32] {
    fn from(point: EdwardsPoint) -> Self {
        point.encode_point()
    }
}

// This is very slow.
impl Add<EdwardsPoint> for EdwardsPoint {
    type Output = EdwardsPoint;
    fn add(self, rhs: EdwardsPoint) -> Self::Output {
        // On twisted edwards curve, the addition rule is complete.
        // That is, addition and doubling is the same rule.
        let one: P25519FieldItem = 1.into();
        let x = self.x * rhs.y + self.y * rhs.x;
        let y = self.y * rhs.y - A * self.x * rhs.x;
        let x_rev: P25519FieldItem = one + D * self.x * self.y * rhs.x * rhs.y;
        let y_rev: P25519FieldItem = one - D * self.x * self.y * rhs.x * rhs.y;

        EdwardsPoint {
            x: x * (x_rev.inverse()),
            y: y * (y_rev.inverse()),
        }
    }
}

/// WARNING: This does not handle cofactor!
impl Mul<[u8; 32]> for EdwardsPoint {
    type Output = EdwardsPoint;
    fn mul(self, rhs: [u8; 32]) -> Self::Output {
        let mut clamped = rhs;
        //clamped[0] &= 0xf8;
        //clamped[31] = (clamped[31] & 0x7f) | 0x40;
        let mut ret: EdwardsPointCompute = E.into();
        let mut ret2: EdwardsPointCompute = E.into();
        let mut b: EdwardsPointCompute = self.into();
        let e: EdwardsPointCompute = E.into();
        for i in 0..256 {
            ret2 = ret + b;
            if (rhs[i >> 3] & (1 << (i & 0x7))) != 0 {
                ret = ret2;
            } else {
                ret = ret;
            }
            b = b.double();
        }

        ret.into()
    }
}

impl Mul<EdwardsPoint> for [u8; 32] {
    type Output = EdwardsPoint;
    fn mul(self, rhs: EdwardsPoint) -> Self::Output {
        rhs * self
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct EdwardsPointCompute {
    pub x: P25519FieldItem,
    pub y: P25519FieldItem,
    pub z: P25519FieldItem,
    pub t: P25519FieldItem,
}

impl EdwardsPointCompute {
    /// Doubling based on dbl-2008-hwcd.
    pub fn double(&self) -> Self {
        let mut a: P25519FieldItem = 0.into();
        let mut b: P25519FieldItem = 0.into();
        let mut c: P25519FieldItem = 0.into();
        let mut d: P25519FieldItem = 0.into();
        let mut e: P25519FieldItem = 0.into();
        let mut f: P25519FieldItem = 0.into();
        let mut g: P25519FieldItem = 0.into();
        let mut h: P25519FieldItem = 0.into();
        let mut t0: P25519FieldItem = 0.into();
        let mut t1: P25519FieldItem = 0.into();
        let two: P25519FieldItem = 2.into();

        a = self.x * self.x;
        b = self.y * self.y;
        t0 = self.z * self.z;
        c = TWO * t0;
        d = A * a;
        t0 = self.x + self.y;
        t1 = t0 * t0;
        t0 = t1 - a;
        e = t0 - b;
        g = d + b;
        f = g - c;
        h = d - b;

        Self {
            x: e * f,
            y: g * h,
            t: e * h,
            z: f * g,
        }
    }
}

impl From<EdwardsPoint> for EdwardsPointCompute {
    fn from(p: EdwardsPoint) -> Self {
        Self {
            x: p.x,
            y: p.y,
            z: 1.into(),
            t: p.x * p.y,
        }
    }
}

impl From<EdwardsPointCompute> for EdwardsPoint {
    fn from(p: EdwardsPointCompute) -> Self {
        Self {
            x: p.x * (p.z.inverse()),
            y: p.y * (p.z.inverse()),
        }
    }
}

impl Add<EdwardsPointCompute> for EdwardsPointCompute {
    type Output = EdwardsPointCompute;
    /// Addition based on add-2008-hwcd-2.
    /// This will not work for double!
    fn add(self, rhs: EdwardsPointCompute) -> Self::Output {
        let mut a: P25519FieldItem = 0.into();
        let mut b: P25519FieldItem = 0.into();
        let mut c: P25519FieldItem = 0.into();
        let mut d: P25519FieldItem = 0.into();
        let mut e: P25519FieldItem = 0.into();
        let mut f: P25519FieldItem = 0.into();
        let mut g: P25519FieldItem = 0.into();
        let mut h: P25519FieldItem = 0.into();
        let mut t0: P25519FieldItem = 0.into();
        let mut t1: P25519FieldItem = 0.into();

        a = self.x * rhs.x;
        b = self.y * rhs.y;
        c = self.z * rhs.t;
        d = self.t * rhs.z;
        e = d + c;
        t0 = self.x - self.y;
        t1 = rhs.x + rhs.y;
        t0 = t0 * t1;
        t0 = t0 + b;
        f = t0 - a;
        g = b + A * a;
        h = d - c;

        Self {
            x: e * f,
            y: g * h,
            t: e * h,
            z: f * g,
        }
    }
}

#[cfg(test)]
#[test]
fn test_edwards_add() {
    let (x, y) = (G + G + G).pack();
    println!("{} {}", x.encode_hex::<String>(), y.encode_hex::<String>());
    let g: EdwardsPointCompute = G.into();
    let g_2: EdwardsPoint = g.double().into();
    let g_2_2 = g + g.double();
    let g_2_2: EdwardsPoint = g_2_2.into();
    let (x, y) = g_2.pack();
    println!("{} {}", x.encode_hex::<String>(), y.encode_hex::<String>());
    let (x, y) = g_2_2.pack();
    println!("{} {}", x.encode_hex::<String>(), y.encode_hex::<String>());
    let g_100 = G * [1u8; 32];
    let (x, y) = g_100.pack();
    println!(
        "{} {} {}",
        x.encode_hex::<String>(),
        y.encode_hex::<String>(),
        g_100.encode_point().encode_hex::<String>()
    );
}

#[test]
fn test_edward_key_compress() {
    let p = EdwardsPoint::recover_point(G.x.into()).unwrap();
    println!("x {}", p.x.pack().encode_hex::<String>());
    let p = G + G;
    let p_compressed = p.encode_point();
    let p_decompressed = EdwardsPoint::recover_point(p_compressed).unwrap();
    println!("origin {:?} {:?}", p.x.pack(), p.y.pack());
    println!("compressed {:?}", p_compressed);
    println!(
        "restored {:?} {:?}",
        p_decompressed.x.pack(),
        p_decompressed.y.pack()
    );

    let mut rng = ChaCha20Rng::from_entropy();
    for i in 0..10 {
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key[..]);
        //println!("key {}",key.encode_hex::<String>());
        let point = key * G;
        let point2 = point.encode_point();
        //println!("point {} {}",point.x.pack().encode_hex::<String>(),point.y.pack().encode_hex::<String>());
        assert_eq!(
            point.y.pack(),
            EdwardsPoint::recover_point(point2).unwrap().y.pack()
        );
    }

    let key =
        <[u8; 32]>::from_hex("a6e3f62ee9e153ce2f5c6689789358cc9ece27c18f41ff1063edb6687a7a352e")
            .unwrap();
    let point = key * G;
    let point2 = point.encode_point();
    assert_eq!(
        point.y.pack(),
        EdwardsPoint::recover_point(point2).unwrap().y.pack()
    );
    assert_eq!(
        point.x.pack(),
        EdwardsPoint::recover_point(point2).unwrap().x.pack()
    );
}
