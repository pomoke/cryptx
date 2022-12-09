/// Galois Field - GF(2^8)
/// For AES, the mod is x^8 + x^4 + x^3 + x + 1 (01:1b).

pub struct Galois {
    pub coeff: u8,
}

impl Galois {
    pub fn add(a: u8, b: u8) -> u8 {
        a ^ b
    }

    /// over 0x011b
    pub fn mul(a: u8, b: u8) -> u8 {
        let mut im = 0u16;
        let mut multipler = a as u16;
        for i in 0..8 {
            let shift = 1 << i;
            let thisbit: u16 = if b & shift != 0 { multipler } else { 0 };
            im ^= thisbit;
            if multipler & 0x80 != 0 {
                multipler = (multipler << 1) ^ 0x1b;
            } else {
                multipler = multipler << 1;
            }
        }
        im as u8
    }

    pub fn mul_vec(a: [u8; 4], b: [u8; 4]) -> u8 {
        let mut ret = 0u8;
        for i in 0..4 {
            let mult = Self::mul(a[i], b[i]);
            ret = Self::add(ret, mult);
        }
        ret
    }

    /// Over 0x011b.
    pub fn inv(a: u8) -> u8 {
        let im = 0u16;
        todo!()
    }
}

#[test]
fn test_galois_mul() {
    assert_eq!(Galois::mul(0x49, 0x24), 0xdc);
    assert_eq!(Galois::mul(0x24, 0x49), 0xdc);
    assert_eq!(Galois::mul(0x07, 0xd1), 0x1);
}
