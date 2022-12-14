// message - Definitions of message type.
// Messages must be `Serialize` and `Deserialize`.
// To compute MACs within struct, set mac fields to [0u8;32], and do it in postcard data.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signature {
    pub signature: Vec<u8>,
    pub signed_by: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Certificate {
    pub exchange_pubkey: [u8; 32], // for exchange
    pub sign_pubkey: [u8; 32],     // for signature
    pub owner: String,
    pub valid_thru: u64,
    pub note: u64,
    pub signed_by: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WireMessage {
    Link { msg: LinkMsg },
    // Decrypt data to `struct Message`.
    Encrypted { msg: Vec<u8> },
    // To signal fatal state after handshake, a valid MAC is required.
    Fatal { code: u32, mac: [u8; 32] },
}

#[non_exhaustive]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum LinkMsg {
    FHMQVHandshake {
        identity: [u8; 32],      // MQV public key
        ephemeral_key: [u8; 32], // session key.
        /// Put cert chain from your identity to root approved cert.
        /// If certs is not in order, then auth will not pass.
        certification: Option<Vec<Certificate>>,
        mac: [u8; 32], // This MAC is used to check validity.
    },
    Shutdown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Message {
    ReKey,
    Data(Packet),
    Fatal { code: u32, mac: [u8; 32] },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Packet {
    pub stream_type: StreamType,
    /// stream tag when multiplex is used.
    pub stream: u16,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum StreamType {
    TCP,
    UDP,
    IP,
    Ethernet,
    RAW,
}
