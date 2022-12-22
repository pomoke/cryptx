pub mod aes;
pub mod common;
pub mod galois;
pub mod mp;
pub mod pke;
pub mod rsa;
pub mod sha256;
pub mod util;
use clap::Parser;
use hex::FromHex;
use std::{env, fs, path::Path};

/// TCP safe tranport wrapper.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Alternative config file location, default to ~/.config/sst/config.toml
    #[arg(short, long)]
    config: Option<String>,
}

fn main() {
    // Is config folder exists?
    println!("hello!");
}
