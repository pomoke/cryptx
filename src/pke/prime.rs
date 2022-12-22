// Generate prime.

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::mp::LargeInt;

/// Generate safe prime.
/// 2 primes is needed for one rsa key.
#[inline]
pub fn is_prime<const N: usize>(n: LargeInt<N>) -> bool {
    // n-1 = u * 2^t
    if n % 2 == LargeInt::<N>::zero() {
        return false;
    }
    let mut t = n - 1;
    let mut k = 0;
    while (t.0[0] & 1) == 0 {
        t = t / 2;
        k += 1;
    }

    let mut rng = ChaCha20Rng::from_entropy();
    let mut a_base = LargeInt([0; N]);
    for i in 0..(N / 2) {
        a_base.0[i] = rng.next_u32();
    }
    a_base = a_base % n;

    for i in 0..64 {
        let mut a = a_base;
        a_base = a_base + 2;

        a = a % n;
        a.0[0] |= 0x3;
        a = a.pow_mod(t, n);
        let mut next = a;
        assert_ne!(a, LargeInt::<N>::zero());

        for _ in 1..=k {
            next = a * a % n;
            if next == LargeInt::<N>::one() && a != LargeInt::<N>::one() && a != n - 1 {
                return false;
            }
            a = next;
        }
        if a % n != LargeInt::<N>::one() {
            return false;
        }
    }
    return true;

    // 64 rounds.
}

pub fn generate_prime<const N: usize>(bytes: i32) -> LargeInt<N> {
    let mut rng = ChaCha20Rng::from_entropy();
    let mut ret: LargeInt<N> = LargeInt::zero();
    // Fill ret with random number.
    for i in 0..(bytes as usize / 4) {
        ret.0[i] = rng.next_u32();
    }
    // Fill most significant bit and make a odd number.
    ret.0[bytes as usize / 4 - 1] |= 0x80000000;
    ret.0[0] |= 1;
    let mut i = 0u64;
    loop {
        ret = ret + 2;
        i += 1;
        // prime, safe prime, sophie germain.
        if is_prime(ret) && is_prime((ret - 1) >> 1) {
            break;
        }
    }
    println!("found after {} iters", i);
    ret
}

/// This test should run in release mode.
#[test]
fn test_is_prime() {
    //assert!(!is_prime(LargeInt([40, 0])));
    assert!(is_prime(LargeInt([13, 0])));
    assert!(!is_prime(LargeInt([1, 1, 0, 0])));
    assert!(is_prime(LargeInt([15, 1, 0, 0])));
    let mut p25519 = LargeInt([0u32; 16]);
    p25519.0[0] = 0xffffffed;
    p25519.0[1] = 0xffffffff;
    p25519.0[2] = 0xffffffff;
    p25519.0[3] = 0xffffffff;
    p25519.0[4] = 0xffffffff;
    p25519.0[5] = 0xffffffff;
    p25519.0[6] = 0xffffffff;
    p25519.0[7] = 0x7fffffff;
    let two = LargeInt::<16>::from_u32(41);
    println!("{:?}", two.pow_mod(p25519 - 1, p25519));
    println!(
        "{:?}",
        LargeInt([2, 0, 0, 0]).pow_mod(LargeInt([15, 1, 0, 0]), LargeInt([15, 1, 0, 0]))
    );
    //assert!(is_prime(p25519));
}

#[test]
fn test_prime_generate() {
    generate_prime::<128>(256);
}
