use std::mem;

use crate::common::*;
use crate::galois::Galois;
use crate::util::*;
use hex::{FromHex, ToHex};
struct Aes {}

struct AesEcb;

impl Crypt<&[u8]> for Aes {
    fn encrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptError> {
        eprintln!("This function encrypts data with AES-ECB, which exposes statistical features and should be avoided.");
        todo!()
    }

    fn decrypt(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptError> {
        todo!()
    }
}

const RoundConst: [u32; 14] = [
    0, 0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0, 0, 0,
];

const SBox: [u8; 256] = [
    //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const RSBox: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

impl Aes {
    pub fn encrypt_block(message: &[u8; 16], key: &[u8]) -> Result<[u8; 16], CryptError> {
        todo!()
    }

    pub fn decrypt_block(message: &[u8; 16], key: &[u8]) -> Result<[u8; 16], CryptError> {
        todo!()
    }

    fn encrypt<const R: usize, const N: usize>(msg: &[u8; 16], key: [[u8; 16]; N]) -> [u8; 16] {
        //Init: add round key
        let mut t = *msg;
        let mut current_key = key[0];
        Self::xor_words(&mut t, &current_key);
        //Do 9 rounds.
        for i in 0..R {
            // SubBytes
            Self::sub_words(&mut t);
            // ShiftRows
            Self::shift_rows(&mut t);
            // MixColumns
            Self::mix_columns(&mut t);
            // AddRoundKey
            Self::xor_words(&mut t, &key[i + 1])
        }
        //Do last round.
        //SubBytes
        Self::sub_words(&mut t);
        //ShiftRows
        Self::shift_rows(&mut t);
        //AddRoundKey
        Self::xor_words(&mut t, &key[N - 1]);

        t
    }

    /// decrypt is a reverse of encrypt.
    /// reverse process order and use inverse xform functions.
    /// See FIPS 197 page 21.
    fn decrypt<const R: usize, const N: usize>(
        cryptmsg: &[u8; 16],
        key: [[u8; 16]; N],
    ) -> [u8; 16] {
        //Init: add round key
        let mut t = *cryptmsg;

        Aes::xor_words(&mut t, &key[N - 1]);

        for i in 0..R {
            Aes::inv_shift_rows(&mut t);
            Aes::rsub_words(&mut t);
            Aes::xor_words(&mut t, &key[N - 2 - i]);
            Aes::inv_mix_columns(&mut t);
        }

        Aes::inv_shift_rows(&mut t);
        Aes::rsub_words(&mut t);
        Aes::xor_words(&mut t, &key[0]);

        t
    }

    fn aes128_key_schedule(key: [u8; 16]) -> [[u8; 16]; 11] {
        const N: usize = 4;
        const Rounds: usize = 11;
        let key32: [u32; N] = Self::bytes_pack_to_word(key);
        let mut words: [u32; N * Rounds] = [0u32; N * Rounds];
        for i in 0..N * Rounds {
            if i < N {
                words[i] = key32[i];
            } else if i >= N && i % N == 0 {
                words[i] = words[i - N]
                    ^ (Self::sub_word32(Self::rot_word32(words[i - 1])))
                    ^ RoundConst[i / N];
            } else if i >= N && N > 6 && i % N == 4 {
                words[i] = words[i - N] ^ Self::sub_word32(words[i - 1])
            } else {
                words[i] = words[i - N] ^ words[i - 1]
            }
        }
        let mut ret: [[u8; 16]; 11] = [[0xff; 16]; 11];
        for i in 0..Rounds {
            for j in 0..4 {
                ret[i][4 * j..4 * j + 4]
                    .copy_from_slice(word_to_bytes(words[4 * i + j]).as_mut_slice());
            }
        }
        ret
    }

    fn rot_word(word: [u8; 4]) -> [u8; 4] {
        [word[1], word[2], word[3], word[0]]
    }

    fn sub_word(word: [u8; 4]) -> [u8; 4] {
        [
            SBox[word[0] as usize],
            SBox[word[1] as usize],
            SBox[word[2] as usize],
            SBox[word[3] as usize],
        ]
    }
    fn rot_word32(data: u32) -> u32 {
        bytes_to_word(&Self::rot_word(word_to_bytes(data)))
    }

    fn sub_word32(data: u32) -> u32 {
        bytes_to_word(&Self::sub_word(word_to_bytes(data)))
    }

    fn bytes_pack_to_word(data: [u8; 16]) -> [u32; 4] {
        [
            bytes_to_word(&data[0..4]),
            bytes_to_word(&data[4..8]),
            bytes_to_word(&data[8..12]),
            bytes_to_word(&data[12..16]),
        ]
    }

    fn words_pack_to_bytes(data: [u32; 4]) -> [u8; 16] {
        todo!()
    }

    fn sub_words(t: &mut [u8; 16]) {
        t.iter_mut().for_each(|x| *x = SBox[*x as usize]);
    }

    fn rsub_words(t: &mut [u8; 16]) {
        t.iter_mut().for_each(|x| *x = RSBox[*x as usize]);
    }

    fn shift_rows(t: &mut [u8; 16]) {
        let mut r = *t;
        // 0 4 8  12
        // 1 5 9  13
        // 2 6 10 14
        // 3 7 11 15

        // Row 0 is unchanged.
        r[1] = t[5];
        r[5] = t[9];
        r[9] = t[13];
        r[13] = t[1];

        r[2] = t[10];
        r[6] = t[14];
        r[10] = t[2];
        r[14] = t[6];

        r[3] = t[15];
        r[7] = t[3];
        r[11] = t[7];
        r[15] = t[11];
        *t = r;
    }

    fn inv_shift_rows(t: &mut [u8; 16]) {
        let mut r = *t;
        // 0 4 8  12
        // 1 5 9  13
        // 2 6 10 14
        // 3 7 11 15

        // Row 0 is unchanged.
        r[5] = t[1];
        r[9] = t[5];
        r[13] = t[9];
        r[1] = t[13];

        r[10] = t[2];
        r[14] = t[6];
        r[2] = t[10];
        r[6] = t[14];

        r[15] = t[3];
        r[3] = t[7];
        r[7] = t[11];
        r[11] = t[15];
        *t = r;
    }

    fn mix_columns(t: &mut [u8; 16]) {
        //4 cols.
        let mut b = [0u8; 16];
        for i in 0..4 {
            // Do compute on each col.
            let a = [t[4 * i + 0], t[4 * i + 1], t[4 * i + 2], t[4 * i + 3]];
            b[4 * i + 0] = Galois::mul_vec([2, 3, 1, 1], a);
            b[4 * i + 1] = Galois::mul_vec([1, 2, 3, 1], a);
            b[4 * i + 2] = Galois::mul_vec([1, 1, 2, 3], a);
            b[4 * i + 3] = Galois::mul_vec([3, 1, 1, 2], a);
        }
        // Copy back.
        *t = b;
    }

    fn inv_mix_columns(t: &mut [u8; 16]) {
        //4 cols.
        let mut b = [0u8; 16];
        for i in 0..4 {
            // Do compute on each col.
            let a = [t[4 * i + 0], t[4 * i + 1], t[4 * i + 2], t[4 * i + 3]];
            b[4 * i + 0] = Galois::mul_vec([0x0e, 0x0b, 0x0d, 0x09], a);
            b[4 * i + 1] = Galois::mul_vec([0x09, 0x0e, 0x0b, 0x0d], a);
            b[4 * i + 2] = Galois::mul_vec([0x0d, 0x09, 0x0e, 0x0b], a);
            b[4 * i + 3] = Galois::mul_vec([0x0b, 0x0d, 0x09, 0x0e], a);
        }
        // Copy back.
        *t = b;
    }

    fn xor_words(t: &mut [u8; 16], rhs: &[u8; 16]) {
        for i in 0..16 {
            t[i] = t[i] ^ rhs[i]
        }
    }
}

#[test]
fn test_aes128_key_schedule() {
    //Test sample is from FIPS 197.
    const EXPECT: &[&str] = &[
        "000102030405060708090a0b0c0d0e0f",
        "d6aa74fdd2af72fadaa678f1d6ab76fe",
        "b692cf0b643dbdf1be9bc5006830b3fe",
        "b6ff744ed2c2c9bf6c590cbf0469bf41",
        "47f7f7bc95353e03f96c32bcfd058dfd",
        "3caaa3e8a99f9deb50f3af57adf622aa",
        "5e390f7df7a69296a7553dc10aa31f6b",
        "14f9701ae35fe28c440adf4d4ea9c026",
        "47438735a41c65b9e016baf4aebf7ad2",
        "549932d1f08557681093ed9cbe2c974e",
        "13111d7fe3944a17f307a78b4d2b30c5",
    ];
    let key: [u8; 16] = <[u8; 16]>::from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
    let round_keys = Aes::aes128_key_schedule(key);
    for i in 0..11 {
        println!("round {}: {}", i, round_keys[i].encode_hex::<String>());
        assert!(<[u8; 16]>::from_hex(EXPECT[i]).unwrap() == round_keys[i]);
    }
}

/// See FIPS 197, page 36.
#[test]
fn test_aes128_encrypt() {
    let msg = <[u8; 16]>::from_hex("00112233445566778899aabbccddeeff").unwrap();
    let key = <[u8; 16]>::from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
    let ks = Aes::aes128_key_schedule(key);
    let cryptmsg = Aes::encrypt::<9, 11>(&msg, ks);
    let crypt = cryptmsg.encode_hex::<String>();
    assert_eq!(
        cryptmsg,
        <[u8; 16]>::from_hex("69c4e0d86a7b0430d8cdb78070b4c55a").unwrap()
    );
    println!("{}", crypt);
    let decrypt_msg = Aes::decrypt::<9, 11>(&cryptmsg, ks);
    assert_eq!(decrypt_msg, msg);
    println!("{}", decrypt_msg.encode_hex::<String>());
}
