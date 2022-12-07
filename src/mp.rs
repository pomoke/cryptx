/// Multi Precision Compute.
/// 

use std::ops::{Add,Sub,BitAnd,BitOr,BitXor,Not};

#[derive(Clone, Copy, Debug)]
pub struct LargeInt<const N:usize> {
    pub data: [u8;N]
}

impl<const N:usize> Default for LargeInt<N> {
    fn default() -> Self {
        let data = [0u8;N];
        LargeInt{
            data
        }
    }
}

impl<const N:usize> LargeInt<N> {
    fn pow(&self,rhs: Self) -> Self {
        todo!()
    }

}

impl<const N:usize> Add for LargeInt<N> {
    type Output = LargeInt<N>;
    fn add(self, rhs: Self) -> Self::Output {
        todo!()
    }
}

impl<const N:usize> Add for &LargeInt<N> {
    type Output = LargeInt<N>;
    fn add(self, rhs: Self) -> Self::Output {
        todo!()
    }
}

impl<const N:usize> BitXor for &LargeInt<N> {
    type Output = LargeInt<N>;
    fn bitxor(self, rhs: Self) -> Self::Output {
        let mut ret = LargeInt::default();
        for i in 0..N {
            ret.data[i] = self.data[i] ^ rhs.data[i]
        }
        ret
   }
}

impl<const N:usize> LargeInt<N> {
    pub fn fast_mod(&self,rhs: &LargeInt<N>) -> Self{
        self + rhs
    } 
}