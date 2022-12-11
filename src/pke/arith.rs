use crate::mp::LargeInt;
use serde::{Deserialize, Serialize};
use std::{ops::{Add, BitAnd, BitOr, BitXor, Mul, Not, Sub}, num::Wrapping};
const ITEM25519: P25519FieldItem= P25519FieldItem([0xffed,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0x7fff]);
const ITEM25519_2: P25519FieldItem= P25519FieldItem([0xffda,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff]);
/// This struct stores a number over Z_p=2^255-19.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct P25519FieldItem(pub [i64; 16]);

impl P25519FieldItem {
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

    /// inverse: Get multiplicational reverse.
    /// since p is a prime, there is a^(p-1) = 1
    /// therefore, we have a*a^(p-2) = 1,
    /// so, a^(p-2) is inverse and we can compute it in constant time.
    pub fn inverse(&self) -> Self {
        let mut c = *self;

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
        let mut carry: i64;
        let mut m = Self([0; 16]);
        let mut t: P25519FieldItem;
        let mut ret = [0u8; 32];
        t = *self;
        t.carry();
        t.carry();
        t.carry();

        for _ in 0..2 {
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

    /// Get sqrt(x) over p=2^255-19
    /// Note: some x may not have a square root.
    /// To test residue, check a^((p-1)/2)
    /// For `p mod 8 = 5`, solution is `+- a^((p+3)/8)` .
    pub fn sqrt(&self) -> Option<(Self, Self)> {
        // Check for residue.
        // 0b11111...1110
        let mut b: P25519FieldItem = *self;
        let mut ans: P25519FieldItem = 1.into();
        // a^((p-1)/2)
        for i in 0..254 {
            if i != 0 && i != 3 {
                ans = ans * b;
            }
            let b2 = b * b;
            b = b2;
        }
        ans.clamp();
        println!("residue: {:?}",ans);
        // Compare with 1.
        if ans != 1.into() {
            return None;
        }

        let mut b: P25519FieldItem = 1.into();
        let mut ans: P25519FieldItem = 1.into();
        // Get residue.
        // 0b11111...0110
        // a^((p+3)/8)
        for i in 0..252 {
            b = b * *self;
            if i != 0 {
                ans = ans * b;
            }
        }
        ans.carry();
        // Get another residue.
        let mut ans2 = <i32 as Into<P25519FieldItem>>::into(0) - ans;
        ans2.carry();
        Some((ans, ans2))
    }

    /// Clamp self into range of [0,2^255-19).
    pub fn clamp(&mut self) {
        let mut ret = self.clone();
        let mut ok = true;
        for i in 0..16 {
            ret.0[i] -= ITEM25519.0[i];
            if ret.0[i] < 0 {
                ok = false;
            }
        }
        if ok {
            *self = ret;
            return;
        }
        let mut ret = self.clone();
        let mut ok = true;
        for i in 0..16 {
            ret.0[i] -= ITEM25519_2.0[i];
            if ret.0[i] < 0 {
                ok = false;
            }
        }
        if ok {
            *self = ret;
            return;
        }
    }
}

impl From<LargeInt<32>> for P25519FieldItem {
    fn from(data: LargeInt<32>) -> Self {
        data.data.into()
    }
}

impl From<P25519FieldItem> for [u8; 32] {
    fn from(t: P25519FieldItem) -> Self {
        t.pack()
    }
}

impl From<[u8; 32]> for P25519FieldItem {
    fn from(input: [u8; 32]) -> Self {
        let mut ret = Self([0; 16]);
        for i in 0..16 {
            ret.0[i] = input[2 * i] as i64 + (input[2 * i + 1] << 8) as i64
        }
        ret
    }
}

impl Add for P25519FieldItem {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        let mut ret = [0; 16];
        for i in 0..16 {
            ret[i] = self.0[i] + rhs.0[i];
        }
        P25519FieldItem(ret)
    }
}

impl Sub for P25519FieldItem {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        let mut ret = [0; 16];
        for i in 0..16 {
            ret[i] = self.0[i] - rhs.0[i];
        }
        P25519FieldItem(ret)
    }
}

impl Mul for P25519FieldItem {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        let mut product = [0i64; 31];
        let mut ret = [0i64; 16];

        for i in 0..16 {
            for j in 0..16 {
                product[i + j] += self.0[i] * rhs.0[j];
            }
        }

        for i in 0..15 {
            product[i] += 38 * product[i + 16];
        }

        for i in 0..16 {
            ret[i] = product[i];
        }

        let mut ret = Self(ret);
        ret.carry();
        ret.carry();
        ret.carry();
        ret

    }
}

impl From<i32> for P25519FieldItem {
    fn from(t: i32) -> Self {
        let mut arr = [0 as i64; 16];
        arr[0] = t as i64;
        P25519FieldItem(arr)
    }
}

#[test]
fn sqrt25519()
{
    let c: P25519FieldItem = 7.into();
    println!("{:?}",c.sqrt());
}