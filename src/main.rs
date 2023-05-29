pub mod aes;
pub mod comm;
pub mod common;
pub mod galois;
pub mod mp;
pub mod pke;
pub mod sha256;
pub mod stream;
pub mod ui;
pub mod util;
pub mod wire;
use clap::Parser;
use hex::FromHex;
use iced::{Application, Settings};
use serde::{Deserialize, Serialize};
use std::{env, fs, path::Path};
use ui::UI;

/// TCP safe tranport wrapper.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Alternative config file location, default to ~/.config/sst/config.toml
    #[arg(short, long)]
    config: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub privkey: String,
    pub signkey: String,
}

fn main() {
    // Is config folder exists?
    let args = Args::parse();
    let home_path = env::var("HOME").unwrap_or("/".to_owned());
    let full_path = Path::new(&home_path);
    #[cfg(target_os = "windows")]
    let full_path = full_path.join("sst/");
    #[cfg(not(target_os = "windows"))]
    let full_path = full_path.join(".config/sst/");
    if !full_path.is_dir() && args.config.is_none() {
        // Create folder.
        fs::create_dir_all(full_path.clone()).unwrap();
    }
    let full_path = full_path.join("config.toml");
    let full_path = args.config.map(|x| x.into()).unwrap_or(full_path);
    let config = fs::read(full_path).unwrap();
    let config: Config = toml::from_slice(&config).unwrap();
    let privkey = <[u8; 32]>::from_hex(&config.privkey).unwrap();
    let signkey = <[u8; 32]>::from_hex(&config.signkey).unwrap();

    // start gui.
    UI::run(Settings {
        flags: (privkey, signkey),
        ..Default::default()
    })
    .unwrap();
}
