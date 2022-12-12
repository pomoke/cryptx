use hex::{decode, FromHex};

use crate::{sha256::SHA256, common::CryptoHash};

// Message Authentication Code.
// HMAC based.
pub struct HMAC;

/// Not a standard HMAC but it should work.
impl HMAC {
    pub fn compute(key: &[u8;16],nonce: &[u8;16],payload: &[u8]) -> [u8;32] {
        let mut sk = vec![];
        sk.extend_from_slice(&key[..]);
        sk.extend_from_slice(&nonce[..]);
        let sk = SHA256::hash(&sk);
        let mut data = vec![];
        data.extend_from_slice(&sk);
        data.extend_from_slice(payload);

        SHA256::hash(&data)
    }
    
    pub fn verify(key: &[u8;16],nonce: &[u8;16],payload: &[u8], hmac: &[u8;32]) -> bool {
        let mut sk = vec![];
        sk.extend_from_slice(&key[..]);
        sk.extend_from_slice(&nonce[..]);
        let sk = SHA256::hash(&sk);
        let mut data = vec![];
        data.extend_from_slice(&sk[..]);
        data.extend_from_slice(&payload[..]);
        let hmac_computed = SHA256::hash(&data);

        hmac_computed == *hmac
    }
}

#[test]
fn test_hmac() {
    let key = <[u8;16]>::from_hex("3d44864498530aa5dc8af6add48de2c6").unwrap();
    let nonce = <[u8;16]>::from_hex("2010de5282f01c542a3325be3fb358e8").unwrap();
    let payload = "114514".as_bytes();
    let mac = HMAC::compute(&key,&nonce,payload);
    assert!(HMAC::verify(&key, &nonce, payload, &mac));
}