// SHA-256 implementation.
// From FIPS PUB 180-2.
use crate::common::{CryptError, CryptoHash};
use hex::{FromHex, ToHex};
use std::num::Wrapping;

const H0: u32 = 0x6a09e667;
const H1: u32 = 0xbb67ae85;
const H2: u32 = 0x3c6ef372;
const H3: u32 = 0xa54ff53a;
const H4: u32 = 0x510e527f;
const H5: u32 = 0x9b05688c;
const H6: u32 = 0x1f83d9ab;
const H7: u32 = 0x5be0cd19;
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

struct SHA256;

impl SHA256 {
    fn do_hash(data: &[u8]) -> [u8; 32] {
        let processed = Self::preprocess(data);
        //println!("processed: {}",processed.encode_hex::<String>());
        Self::process(&processed)
    }

    fn preprocess(data: &[u8]) -> Vec<u8> {
        let mut data = data.to_owned();
        let length = data.len() * 8;
        data.push(0x80);

        // Padding: make bit(L+1+K+64) % 512
        //               byte(L+K+8) % 64

        // Get min K needed.
        let current_length = data.len();
        let mut k = (data.len() + 8) % 64;
        if k % 64 == 0 {
            k = 0;
        } else {
            k = 64 - k;
        }

        // Pad zeroes.
        if k != 0 {
            data.append(&mut [0_u8].repeat(k));
        }

        // Put length, in bits.
        data.append(&mut length.to_be_bytes().to_vec());

        data
    }

    fn process(data: &[u8]) -> [u8; 32] {
        // For each 512 bit(64 bytes).
        assert!(data.len() % 64 == 0);
        let mut h0 = H0;
        let mut h1 = H1;
        let mut h2 = H2;
        let mut h3 = H3;
        let mut h4 = H4;
        let mut h5 = H5;
        let mut h6 = H6;
        let mut h7 = H7;

        for i in 0..(data.len() / 64) {
            let mut w = [0u32; 64];
            // Copy data into w[0:16];
            for j in 0..16 {
                let conv_from = [
                    data[64 * i + 4 * j + 0],
                    data[64 * i + 4 * j + 1],
                    data[64 * i + 4 * j + 2],
                    data[64 * i + 4 * j + 3],
                ];
                w[j] = u32::from_be_bytes(conv_from);
            }
            // Extend words
            for j in 16..64 {
                let s0 = w[j - 15].rotate_right(7) ^ w[j - 15].rotate_right(18) ^ (w[j - 15] >> 3);
                let s1 = w[j - 2].rotate_right(17) ^ w[j - 2].rotate_right(19) ^ (w[j - 2] >> 10);
                let Wrapping(w_j) =
                    Wrapping(w[j - 16]) + Wrapping(s0) + Wrapping(w[j - 7]) + Wrapping(s1);
                w[j] = w_j
            }

            let mut a = h0;
            let mut b = h1;
            let mut c = h2;
            let mut d = h3;
            let mut e = h4;
            let mut f = h5;
            let mut g = h6;
            let mut h = h7;

            for j in 0..64 {
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch = (e & f) ^ ((!e) & g);
                let Wrapping(temp1) =
                    Wrapping(h) + Wrapping(s1) + Wrapping(ch) + Wrapping(K[j]) + Wrapping(w[j]);
                let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let Wrapping(temp2) = Wrapping(s0) + Wrapping(maj);

                h = g;
                g = f;
                f = e;
                Wrapping(e) = Wrapping(d) + Wrapping(temp1);
                d = c;
                c = b;
                b = a;
                Wrapping(a) = Wrapping(temp1) + Wrapping(temp2);
            }
            Wrapping(h0) = Wrapping(h0) + Wrapping(a);
            Wrapping(h1) = Wrapping(h1) + Wrapping(b);
            Wrapping(h2) = Wrapping(h2) + Wrapping(c);
            Wrapping(h3) = Wrapping(h3) + Wrapping(d);
            Wrapping(h4) = Wrapping(h4) + Wrapping(e);
            Wrapping(h5) = Wrapping(h5) + Wrapping(f);
            Wrapping(h6) = Wrapping(h6) + Wrapping(g);
            Wrapping(h7) = Wrapping(h7) + Wrapping(h);
        }
        let mut ret = [0u8; 32];
        [ret[0], ret[1], ret[2], ret[3]] = h0.to_be_bytes();
        [ret[4], ret[5], ret[6], ret[7]] = h1.to_be_bytes();
        [ret[8], ret[9], ret[10], ret[11]] = h2.to_be_bytes();
        [ret[12], ret[13], ret[14], ret[15]] = h3.to_be_bytes();
        [ret[16], ret[17], ret[18], ret[19]] = h4.to_be_bytes();
        [ret[20], ret[21], ret[22], ret[23]] = h5.to_be_bytes();
        [ret[24], ret[25], ret[26], ret[27]] = h6.to_be_bytes();
        [ret[28], ret[29], ret[30], ret[31]] = h7.to_be_bytes();

        ret
    }
}

impl CryptoHash<32> for SHA256 {
    fn hash(data: &[u8]) -> Result<[u8; 32], CryptError> {
        Ok(Self::do_hash(data))
    }
}

#[test]
fn sha256_test() {
    let data = "abc";
    let result = SHA256::hash(data.as_ref()).unwrap();
    let result_str: String = result.encode_hex();
    println!("{}", result_str);
    assert_eq!(
        result,
        <[u8; 32]>::from_hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
            .unwrap()
    );

    let result = SHA256::hash(vec![].as_ref()).unwrap();
    assert_eq!(
        result,
        <[u8; 32]>::from_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            .unwrap()
    );

    let zeroes = vec![0u8];
    let zeroes = zeroes.repeat(128);
    println!("zeroes: {}", zeroes.len());
    assert_eq!(
        SHA256::hash(zeroes.as_ref()).unwrap(),
        <[u8; 32]>::from_hex("38723a2e5e8a17aa7950dc008209944e898f69a7bd10a23c839d341e935fd5ca")
            .unwrap()
    );

    let zeroes = vec![0u8];
    let zeroes = zeroes.repeat(1024);
    println!("zeroes: {}", zeroes.len());
    assert_eq!(
        SHA256::hash(zeroes.as_ref()).unwrap(),
        <[u8; 32]>::from_hex("5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef")
            .unwrap()
    );
}

#[test]
fn assign_unpack_test() {
    let a = 1;
    let b = 2;
    let c;
    {
        Wrapping(c) = Wrapping(a) + Wrapping(b);
    }
    println!("c: {}", c);
    assert_eq!(c, 3);
}
