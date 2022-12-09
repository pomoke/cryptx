use crate::mp::LargeInt;
use serde::{Deserialize, Serialize};
use std::ops::{Add, BitAnd, BitOr, BitXor, Mul, Not, Sub};

/// Curve25519FieldItem
/// This struct stores a number within p=2^255-19.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct Curve25519FieldItem([i64; 16]);

impl Curve25519FieldItem {
    pub fn carry(&mut self) {
        for i in 0..16 {
            let carry = self.0[i] >> 16;
            self.0[i] -= carry << 16;
            if i < 15 {
                self.0[i + 1] += carry;
            } else {
                self.0[0] += 38 * carry;
            }
        }
    }

    pub fn carry_new(&self) -> Self {
        let mut ret = self.clone();
        ret.carry();
        ret
    }

    pub fn inverse(&self) -> Self {
        let mut c = Curve25519FieldItem([0i64; 16]);
        for i in 0..16 {
            c.0[i] = self.0[i];
        }

        for i in (0..254).rev() {
            c = c * c;
            if i != 2 && i != 4 {
                c = c * *self;
            }
        }
        c
    }

    pub fn swap(&mut self, q: &mut Self, bit: i64) {
        let mut t = !(bit - 1);
        let c = t;
        for i in 0..16 {
            t = c & (self.0[i] ^ q.0[i]);
            self.0[i] ^= t;
            q.0[i] ^= t;
        }
    }

    pub fn pack(&self) -> [u8; 32] {
        let mut carry = 0i64;
        let mut m = Self([0; 16]);
        let mut t = Self([0; 16]);
        let mut ret = [0u8; 32];
        t = *self;
        t.carry();
        t.carry();
        t.carry();

        for j in 0..2 {
            m.0[0] = t.0[0] - 0xffed;
            for i in 1..15 {
                m.0[i] = t.0[i] - 0xffff - ((m.0[i - 1] >> 16) & 1);
                m.0[i - 1] &= 0xffff;
            }

            m.0[15] = t.0[15] - 0x7fff - ((m.0[14] >> 16) & 1);
            carry = (m.0[15] >> 16) & 1;
            m.0[14] &= 0xffff;
            t.swap(&mut m, 1 - carry);
        }
        for i in 0..16 {
            ret[2 * i] = t.0[i] as u8;
            ret[2 * i + 1] = (t.0[i] >> 8) as u8;
        }
        ret
    }
}

impl From<LargeInt<16>> for Curve25519FieldItem {
    fn from(data: LargeInt<16>) -> Self {
        data.data.into()
    }
}

impl From<[u8; 16]> for Curve25519FieldItem {
    fn from(input: [u8; 16]) -> Self {
        let mut ret = Self([0; 16]);
        for i in 0..16 {
            ret.0[i] = input[2 * i] as i64 + (input[2 * i + 1] << 8) as i64
        }
        ret
    }
}

impl Add for Curve25519FieldItem {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        let mut ret = [0; 16];
        for i in 0..16 {
            ret[i] = self.0[i] + rhs.0[i];
        }
        Curve25519FieldItem(ret)
    }
}

impl Sub for Curve25519FieldItem {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        let mut ret = [0; 16];
        for i in 0..16 {
            ret[i] = self.0[i] - rhs.0[i];
        }
        Curve25519FieldItem(ret)
    }
}

impl Mul for Curve25519FieldItem {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        let mut product = [0i64; 31];
        let mut ret = [0i64; 16];
        for i in 0..16 {
            for j in 0..16 {
                product[i + j] = self.0[i] * rhs.0[j];
            }
        }

        for i in 0..15 {
            product[i] += 38 * product[i + 16];
        }

        for i in 0..16 {
            ret[i] = product[i];
        }

        Self(ret)
    }
}
