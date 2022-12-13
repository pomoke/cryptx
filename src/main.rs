pub mod aes;
pub mod comm;
pub mod common;
pub mod galois;
pub mod mp;
pub mod pke;
pub mod sha256;
pub mod stream;
pub mod util;
pub mod wire;

use pke::ec25519::{EdwardsPoint, EdwardsPointCompute, G};

fn main() {
    println!("Hello, world!");
    println!("testing ed25519 a*P...");
    let mut multiplier = [0u8; 32];
    multiplier[30] = 1;
    multiplier[30] = 1;
    for _ in 0..10000 {
        let a = multiplier * G;
    }
}
