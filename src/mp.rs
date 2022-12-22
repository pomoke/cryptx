use crate::util::msb;
use num_bigint::BigUint;
/// Multi Precision Compute.
///
use std::{
    cmp::Ordering,
    num::Wrapping,
    ops::{Add, BitAnd, BitOr, BitXor, Div, Mul, Not, Rem, Shl, Shr, Sub},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct LargeInt<const N: usize>(pub [u32; N]);

impl<const N: usize> Default for LargeInt<N> {
    fn default() -> Self {
        let data = [0u32; N];
        Self(data)
    }
}

impl<const N: usize> LargeInt<N> {
    /// divide self by rhs, return quotient and remainder.
    pub fn div_rem(&self, rhs: &Self) -> (Self, Self) {
        let mut x = self.clone();
        let y = rhs.clone();
        let mut q = [0u32; N];
        // valid digits of self.
        let mut n = x.get_most_significant_word();
        // valid digit of rhs.
        let t = y.get_most_significant_word();
        // Do mod reduction.
        // TODO: we need a faster reduction method.
        if n >= t {
            for i in (0..(32 - msb(y.0[t]))).rev() {
                while x >= y.shift_left_words(n - t) * (1 << i) {
                    q[n - t] += 1 << i;
                    x = x - y.shift_left_words(n - t) * (1 << i);
                }
            }
        }
        n = x.get_most_significant_word();

        // Do in-mod reduction.
        let b1 = u32::MAX;
        let b = u32::MAX as u64 + 1;

        for i in ((t + 1)..=n).rev() {
            if x.0[i] == y.0[t] {
                q[i - t - 1] = u32::MAX; //b-1
            } else {
                q[i - t - 1] =
                    ((x.0[i] as u64 * b as u64 + x.0[i - 1] as u64) / y.0[t] as u64) as u32;
            }

            while q[i - t - 1] as u128
                * (y.0[t] as u128 * b as u128 + if t > 1 { y.0[t - 1] } else { 0 } as u128)
                > (x.0[i] as u128 * b as u128 * b as u128
                    + x.0[i - 1] as u128 * b as u128
                    + if i >= 2 { x.0[i - 2] } else { 0 } as u128)
            {
                q[i - t - 1] -= 1;
            }
            x = x - (q[i - t - 1] * y).shift_left_words(i - t - 1);
            if x.0[N - 1] & 0x8000_0000 != 0 {
                x = x + y.shift_left_words(i - t - 1);
                Wrapping(q[i - t - 1]) = Wrapping(q[i - t - 1]) - Wrapping(1);
            }
        }

        (Self(q), x)
    }

    // compute self**pow mod p.

    pub fn pow_mod(&self, pow: Self, p: Self) -> Self {
        let mut ret = Self::one();
        let mut b = self.clone();
        for i in 0..N {
            for j in 0..32 {
                if (pow.0[i] & (1 << j)) != 0 {
                    ret = (ret * b) % p;
                }
                b = (b * b) % p;
            }
        }
        ret % p
    }

    pub fn pow(&self, pow: Self) -> Self {
        let mut ret = Self::one();
        let mut b = self.clone();
        for i in 0..N {
            for j in 0..32 {
                let ret2 = ret * b;
                if (pow.0[i] & (1 << j)) != 0 {
                    ret = ret2;
                } else {
                    ret = ret;
                }
                b = b * b;
            }
        }
        ret
    }

    #[inline]
    pub fn shift_left_words(&self, n: usize) -> Self {
        let mut ret = [0u32; N];
        for i in 0..(N - n) {
            ret[i + n] = self.0[i];
        }

        Self(ret)
    }

    #[inline]
    pub fn shift_right_words(&self, n: usize) -> Self {
        let mut ret = [0u32; N];
        for i in 0..(N - n) {
            ret[i] = self.0[i + n];
        }

        Self(ret)
    }

    #[inline]
    pub fn one() -> Self {
        let mut ret = [0u32; N];
        ret[0] = 1;
        Self(ret)
    }
    #[inline]
    pub fn get_most_significant_word(&self) -> usize {
        for i in (0..N).rev() {
            if self.0[i] != 0 {
                return i;
            }
        }
        return 0;
    }

    #[inline]
    pub fn get_b_1() -> Self {
        let mut ret = [0u32; N];
        ret[0] = u32::MAX;
        Self(ret)
    }

    #[inline]
    pub fn zero() -> Self {
        Self([0u32; N])
    }

    #[inline]
    pub fn modulus(&self) -> Self {
        todo!()
    }

    #[inline]
    pub fn from_u32(a: u32) -> Self {
        let mut ret = Self([0u32; N]);
        ret.0[0] = a;
        ret
    }

    #[inline]
    pub fn get_msb(&self) -> usize {
        let n = self.get_most_significant_word();
        for i in (0..32).rev() {
            if (self.0[n] & (1 << i)) != 0 {
                return 32 * n + i;
            }
        }
        return 0;
    }
}

impl<const N: usize> Add for LargeInt<N> {
    type Output = LargeInt<N>;
    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        let mut carry = 0;
        let mut ret = [0u32; N];
        for i in 0..N {
            let add: u64 = self.0[i] as u64 + rhs.0[i] as u64 + carry as u64;
            if (add & 0xffffffff_00000000) != 0 {
                carry = 1;
            } else {
                carry = 0;
            }
            ret[i] = add as u32;
        }
        Self(ret)
    }
}

impl<const N: usize> Sub for LargeInt<N> {
    type Output = LargeInt<N>;
    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        let mut carry = 0;
        let mut ret = [0u32; N];
        for i in 0..N {
            let mut sub: i64 = self.0[i] as i64 - rhs.0[i] as i64 - carry as i64;
            // Signed ?
            if sub < 0 {
                //sub = -sub;
                carry = 1;
            } else {
                carry = 0;
            }
            ret[i] = sub as u32;
        }
        Self(ret)
    }
}

/// Clamped multiply.
impl<const N: usize> Mul for LargeInt<N> {
    type Output = LargeInt<N>;
    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        let mut ret = Self([0u32; N]);
        /*
        for i in 0..N {
            let mut b = Self::from_u32(rhs.0[i]);
            b.shift_left_words(i);
            let mut t = Self([0u32;N]);
            //ret = ret + a * b;
        }
        LargeInt(ret)
        */
        let a = BigUint::from_slice(&self.0[..]);
        let b = BigUint::from_slice(&rhs.0[..]);
        let c = a * b;
        for (i, v) in c.iter_u32_digits().enumerate() {
            if (i < N) {
                ret.0[i] = v;
            }
        }
        ret
    }
}

impl<const N: usize> Mul<u32> for LargeInt<N> {
    type Output = LargeInt<N>;
    fn mul(self, rhs: u32) -> Self::Output {
        let mut b = [0u32; N];
        b[0] = rhs;
        self * Self(b)
    }
}

impl<const N: usize> Mul<LargeInt<N>> for u32 {
    type Output = LargeInt<N>;
    fn mul(self, rhs: LargeInt<N>) -> Self::Output {
        rhs * self
    }
}

impl<const N: usize> Div for LargeInt<N> {
    type Output = LargeInt<N>;
    fn div(self, rhs: Self) -> Self::Output {
        let a = BigUint::from_slice(&self.0[..]);
        let b = BigUint::from_slice(&rhs.0[..]);
        let c = a % b;
        let c = c.iter_u32_digits();
        let mut ret = [0u32; N];
        for (i, v) in c.enumerate() {
            if i < N {
                ret[i] = v;
            }
        }
        Self(ret)
        //self.div_rem(&rhs).0
    }
}

impl<const N: usize> Div<u32> for LargeInt<N> {
    type Output = LargeInt<N>;
    fn div(self, rhs: u32) -> Self::Output {
        let mut divisor = Self([0; N]);
        divisor.0[0] = rhs;
        self / divisor
    }
}

impl<const N: usize> Rem for LargeInt<N> {
    type Output = LargeInt<N>;
    fn rem(self, rhs: Self) -> Self::Output {
        let a = BigUint::from_slice(&self.0[..]);
        let b = BigUint::from_slice(&rhs.0[..]);
        let c = a % b;
        let c = c.iter_u32_digits();
        let mut ret = [0u32; N];
        for (i, v) in c.enumerate() {
            if i < N {
                ret[i] = v;
            }
        }
        Self(ret)

        //self.div_rem(&rhs).1
    }
}

impl<const N: usize> Rem<u32> for LargeInt<N> {
    type Output = LargeInt<N>;
    fn rem(self, rhs: u32) -> Self::Output {
        let mut b = Self([0; N]);
        b.0[0] = rhs;
        self.div_rem(&b).1
    }
}

impl<const N: usize> Add for &LargeInt<N> {
    type Output = LargeInt<N>;
    fn add(self, rhs: Self) -> Self::Output {
        *self + *rhs
    }
}

impl<const N: usize> Add<u32> for LargeInt<N> {
    type Output = LargeInt<N>;
    fn add(self, rhs: u32) -> Self::Output {
        let mut add = Self([0u32; N]);
        add.0[0] = rhs;
        self + add
    }
}

impl<const N: usize> Sub<u32> for LargeInt<N> {
    type Output = LargeInt<N>;
    fn sub(self, rhs: u32) -> Self::Output {
        let mut add = Self([0u32; N]);
        add.0[0] = rhs;
        self - add
    }
}

impl<const N: usize> BitXor for &LargeInt<N> {
    type Output = LargeInt<N>;
    fn bitxor(self, rhs: Self) -> Self::Output {
        let mut ret = LargeInt::default();
        for i in 0..N {
            ret.0[i] = self.0[i] ^ rhs.0[i]
        }
        ret
    }
}

impl<const N: usize> Shl<usize> for LargeInt<N> {
    type Output = Self;
    fn shl(self, rhs: usize) -> Self::Output {
        let mut ret = self;
        let words = rhs / 32;
        let bits = rhs % 32;
        self.shift_left_words(words);
        for i in 0..bits {}
        todo!()
    }
}

impl<const N: usize> Shr<usize> for LargeInt<N> {
    type Output = Self;
    fn shr(self, rhs: usize) -> Self::Output {
        let mut ret = self;
        let words = rhs / 32;
        let bits = rhs % 32;
        self.shift_right_words(words);
        for i in 0..bits {
            let mut carry = 0;
            for i in (0..N).rev() {
                let v = (ret.0[i] >> 1) | (carry << 31);
                carry = ret.0[i] & 1;
                ret.0[i] = v;
            }
        }
        ret
    }
}

impl<const N: usize> LargeInt<N> {
    pub fn fast_mod(&self, rhs: &LargeInt<N>) -> Self {
        self + rhs
    }
}

impl<const N: usize> PartialOrd for LargeInt<N> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        /*
        let c = *self - *other;

        // c = 0 ?
        if c == Self([0u32; N]) {
            return Some(Ordering::Equal);
        }
        // Check for sign bit.
        Some(if (c.0[N - 1] & 0xf0000000) != 0 {
            Ordering::Less
        } else {
            Ordering::Greater
        })
        */
        for i in (0..N).rev() {
            if self.0[i] < other.0[i] {
                return Some(Ordering::Less);
            } else if self.0[i] > other.0[i] {
                return Some(Ordering::Greater);
            }
        }
        Some(Ordering::Equal)
    }
}

#[test]
fn test_largeint_add_sub() {
    let a = LargeInt([6, 2]);
    let b = LargeInt([4294967290, 1]);
    let c = a + b;
    assert_eq!(c, LargeInt([0, 4]));
    let a = LargeInt([1, 2]);
    let b = LargeInt([1, 3]);
    assert_eq!(a + b, LargeInt([2, 5]));
    let a = LargeInt([6, 2]);
    let b = LargeInt([4294967290, 1]);
    let c = LargeInt([0, 4]);
    assert_eq!(c - b, a);
    assert_eq!(c - a, b);
}

#[test]
fn test_largeint_mul() {
    let a = LargeInt([1, 0]);
    let b = LargeInt([6, 0]);
    let c = LargeInt([6, 0]);
    assert_eq!(a * b, c);
    let a = LargeInt([65536, 0]);
    let b = LargeInt([65536, 0]);
    let c = LargeInt([0, 1]);
    assert_eq!(a * b, c);
    let a = LargeInt([65537, 0]);
    let b = LargeInt([65537, 0]);
    let c = LargeInt([131073, 1]);
    assert_eq!(a * b, c);
    assert_eq!(LargeInt([2, 0]) * 3, LargeInt([6, 0]))
}

#[test]
fn test_largeint_shift() {
    let a = LargeInt([0, 1, 0, 0]);
    assert_eq!(a.shift_left_words(1), LargeInt([0, 0, 1, 0]));
    assert_eq!(
        LargeInt([0, 0, 0, 1, 1, 1, 0, 0]).get_most_significant_word(),
        5
    );
    assert_eq!(LargeInt([0, 0, 0, 1, 1, 11, 0, 0]).get_msb(), 163);
}

#[test]
fn test_largeint_cmp() {
    let a = LargeInt([1, 0, 0, 0]);
    let b = LargeInt([0, 1, 0, 0]);
    assert!(a < b);
    println!("{:?}", b - a);
    assert!(b > a);
    assert!(LargeInt([0, 0, 0, 0]) < LargeInt([1, 0, 0, 0]));
}

#[test]
fn test_largeint_div() {
    println!("{:?}", LargeInt([7, 0]).div_rem(&LargeInt([2, 0])));
    println!("{:?}", LargeInt([65537, 1]).div_rem(&LargeInt([65536, 0])));
    println!(
        "{:?}",
        LargeInt([0x1, 0x0, 0x0, 0x80000000]).div_rem(&LargeInt([0x3, 0x0, 0x0, 0]))
    );
    println!("{:?}", LargeInt([0x80000000, 1]).div_rem(&LargeInt([1, 0])));
    println!("{:?}", LargeInt([65537, 1]).div_rem(&LargeInt([2, 0])));
    println!(
        "{:?}",
        LargeInt([0, 0, 65536, 0, 0, 0]).div_rem(&LargeInt([1, 1, 0, 0, 0, 0]))
    );
}

#[test]
fn test_largeint_pow() {
    let a = LargeInt([2, 0, 0, 0]);
    let a3 = LargeInt([3, 0, 0, 0]);
    let b = LargeInt([128, 0, 0, 0]);
    let d = LargeInt([63, 0, 0, 0]);
    let c = LargeInt([127, 0, 0, 0]);
    assert_eq!(LargeInt([4, 0, 0, 0]), a.pow_mod(b, c));
    println!("{:?}", a.pow(d));

    let g = LargeInt([5, 0, 0, 0]);
    let p = LargeInt([17, 0, 0, 0]);
    for i in 0..17 {
        let pow = LargeInt([i, 0, 0, 0]);
        println!("5^{} = {:?}", i, g.pow_mod(pow, p));
    }
    let a = LargeInt([1, 2, 0, 0]);
    let b = LargeInt([1, 0, 0, 0]);
    let c = LargeInt([0, 1, 0, 0]);
    println!("{:?}", a.pow_mod(b, c));
}

#[test]
fn test_shift() {
    println!("{:?}", LargeInt([1, 1, 1, 1]) >> 3);
}
