use crate::sha256::SHA256;

// EdDSA - Signature on Twisted Edward curve.
// This implentation uses legacy parameters, and is not compatible with modern parameters based impls.
use super::{
    arith_n::ModNItem,
    ec25519::{ECCError, EdwardsPoint, G},
};
use hex::FromHex;
/// This is not an ed25519, but ElGamal over edward25519.
pub struct Sr25519;

impl Sr25519 {
    pub fn sign(key: [u8; 32], data: &[u8]) -> ([u8; 32], [u8; 32]) {
        let p = key * G;
        let mut secret_source = vec![];
        secret_source.extend_from_slice(&data);
        secret_source.extend_from_slice(&key[..]);
        let k = SHA256::do_hash(&secret_source);
        let r = k * G;
        let key: ModNItem = key.into();
        let mut h = vec![];
        h.extend_from_slice(&data[..]);
        h.extend_from_slice(&r.encode_point()[..]);
        h.extend_from_slice(&p.encode_point()[..]);
        let k: ModNItem = k.into();
        let h = SHA256::do_hash(&h);
        let h: ModNItem = h.into();
        let s = k + h * key;

        (r.into(), s.to_bytes())
    }

    pub fn verify(
        pubkey: [u8; 32],
        data: &[u8],
        r: [u8; 32],
        s: [u8; 32],
    ) -> Result<bool, ECCError> {
        let pubkey = EdwardsPoint::recover_point(pubkey).ok_or(ECCError::InvalidPoint)?;
        let r = EdwardsPoint::recover_point(r).ok_or(ECCError::InvalidPoint)?;
        let left = s * G;
        let mut h = vec![];
        h.extend_from_slice(&data[..]);
        h.extend_from_slice(&r.encode_point()[..]);
        h.extend_from_slice(&pubkey.encode_point()[..]);
        let h = SHA256::do_hash(&h);
        let right = r + h * pubkey;
        Ok(left.pack() == right.pack())
    }
}

#[test]
fn test_schnorr_sig() {
    let data = "whatsoever".as_bytes();
    let privkey =
        <[u8; 32]>::from_hex("cce23408fda42b852fdd4bae99ed990dbe398182c1d743b3d630958af47dfd96")
            .unwrap();
    let pubkey = EdwardsPoint::get_pubkey(privkey);
    let sig = Sr25519::sign(privkey, data);
    assert!(Sr25519::verify(pubkey, data, sig.0, sig.1).unwrap());
    let data = "whatsoever_again".as_bytes();
    assert!(!Sr25519::verify(pubkey, data, sig.0, sig.1).unwrap());
}
