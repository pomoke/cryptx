// AES-CTR based.
use crate::{
    aes::{self, Aes},
    common::CryptError,
};

use super::mac::HMAC;
use hex::FromHex;
/// AES-CTR encryption, HMAC based MAC, MtE mode.
/// 16 bytes: counter
///     8 : serial
///     4 : size
///     4 : local counter
/// ....... : encrypted data
/// 16 bytes: HMAC
#[derive(Clone, Debug)]
pub struct AesCtrHmac {
    aes_key: [u8; 16],
    mac_key: [u8; 16],
    /// One serial number can only be used once.
    /// If a older packet is seen, then discard it.
    serial: u64,
    recv_serial: u64,
    counter: u32,
    key_schedule: [[u8; 16]; 11],
}

pub trait StreamEnc<T: Clone> {
    fn encrypt(&mut self, data: Vec<u8>) -> Vec<u8>;
    fn decrypt(data: Vec<u8>) -> Vec<u8>;
    fn send_state(&self) -> T;
}

impl AesCtrHmac {
    pub fn new(aes_key: &[u8; 16], mac_key: &[u8; 16], serial: u64) -> Self {
        Self {
            aes_key: *aes_key,
            mac_key: *mac_key,
            serial: 1,
            recv_serial: 0,
            counter: 0,
            key_schedule: Aes::aes128_key_schedule(*aes_key),
        }
    }
    pub fn encrypt_stream(&mut self, data: &[u8]) -> Vec<u8> {
        // Make header.
        let mut data = data.to_owned();
        let mut payload: Vec<u8> = vec![];
        let data_len = data.len();
        self.serial += 1;
        self.counter += 100;
        let header = gen_counter(self.serial, data_len as u32, self.counter);

        let cryptmsg = Aes::encrypt::<9, 11>(&header, &self.key_schedule);
        payload.extend_from_slice(&cryptmsg[..]);

        // Pad and slice data.
        let append_zero_count = if data.len() % 16 != 0 {
            16 - (data.len() % 16)
        } else {
            0
        };
        let append_zeros: Vec<u8> = vec![0];
        let mut append_zeros = append_zeros.repeat(append_zero_count);
        data.append(&mut append_zeros);

        for i in 0..(data.len() / 16) {
            // Generate CTR value.
            let counter = gen_counter(self.serial, data_len as u32, self.counter);
            let cur_data = &mut data[(i * 16)..(i * 16) + 16];
            // counter xor data
            let cleartext = xor(cur_data, &counter);
            // encrypt
            let encrypted = Aes::encrypt::<9, 11>(&cleartext, &self.key_schedule);
            payload.extend_from_slice(&encrypted[..]);
            self.counter += 1;
        }
        // Compute HMAC on encrypted payloads.
        let hmac = HMAC::compute(&self.mac_key, &header, &payload);
        payload.extend_from_slice(&hmac[..]);
        payload
    }

    /// Raw decrypt. This does not check for replay attack.
    pub fn decrypt_raw(&self, msg: &[u8]) -> Result<Vec<u8>, CryptError> {
        // Decrypt header.
        let header_orig: [u8; 16] = msg[0..16].try_into().unwrap();
        let header = Aes::decrypt::<9, 11>(&header_orig, &self.key_schedule);
        // Check HMAC.
        let msg_len = msg.len();
        let mac: [u8; 32] = msg[(msg_len - 32)..].try_into().unwrap();
        let hmac_ok = HMAC::verify(&self.mac_key, &header, &msg[..(msg_len - 32)], &mac);

        let mut ret: Vec<u8> = vec![];
        if !hmac_ok {
            return Err(CryptError::HMACFailed);
        }

        let msg = &msg[16..(msg_len - 32)];
        let serial = u64::from_le_bytes(header[0..8].try_into().unwrap());
        let msg_len = u32::from_le_bytes(header[8..12].try_into().unwrap());
        let mut counter = u32::from_le_bytes(header[12..16].try_into().unwrap());

        //Decrypt message.
        for i in 0..(msg.len() / 16) {
            let block = Aes::decrypt::<9, 11>(
                &msg[(i * 16)..(i * 16 + 16)].try_into().unwrap(),
                &self.key_schedule,
            );
            let ctr = gen_counter(serial, msg_len, counter);
            let block = xor(&block[..], &ctr[..]);
            counter += 1;
            ret.extend_from_slice(&block[..]);
        }

        ret.resize(msg_len as usize, 0);
        Ok(ret)
    }

    /// Decrypt, and check for replay attack
    pub fn decrypt_stream(&mut self, msg: &[u8]) -> Result<Vec<u8>, CryptError> {
        // Decrypt header.
        let header_orig: [u8; 16] = msg[0..16].try_into().unwrap();
        let header = Aes::decrypt::<9, 11>(&header_orig, &self.key_schedule);
        // Check HMAC.
        let msg_len = msg.len();
        let mac: [u8; 32] = msg[(msg_len - 32)..].try_into().unwrap();
        let hmac_ok = HMAC::verify(&self.mac_key, &header, &msg[..(msg_len - 32)], &mac);

        let mut ret: Vec<u8> = vec![];
        if !hmac_ok {
            return Err(CryptError::HMACFailed);
        }

        let msg = &msg[16..(msg_len - 32)];
        let serial = u64::from_le_bytes(header[0..8].try_into().unwrap());
        let msg_len = u32::from_le_bytes(header[8..12].try_into().unwrap());
        let mut counter = u32::from_le_bytes(header[12..16].try_into().unwrap());
        // Check for replay attack.
        if serial <= self.recv_serial {
            return Err(CryptError::ReplayAttack);
        }
        self.recv_serial = serial;

        //Decrypt message.
        for i in 0..(msg.len() / 16) {
            let block = Aes::decrypt::<9, 11>(
                &msg[(i * 16)..(i * 16 + 16)].try_into().unwrap(),
                &self.key_schedule,
            );
            let ctr = gen_counter(serial, msg_len, counter);
            let block = xor(&block[..], &ctr[..]);
            counter += 1;
            ret.extend_from_slice(&block[..]);
        }

        ret.resize(msg_len as usize, 0);
        Ok(ret)
    }
}

fn gen_counter(serial: u64, size: u32, counter: u32) -> [u8; 16] {
    let mut ret = [0u8; 16];
    let serial: [u8; 8] = serial.to_le_bytes();
    let size: [u8; 4] = size.to_le_bytes();
    let counter: [u8; 4] = counter.to_le_bytes();
    for i in 0..8 {
        ret[i] = serial[i];
    }

    for i in 0..4 {
        ret[8 + i] = size[i];
        ret[12 + i] = counter[i];
    }

    ret
}

fn xor(a: &[u8], b: &[u8]) -> [u8; 16] {
    let mut ret = [0u8; 16];
    for i in 0..16 {
        ret[i] = a[i] ^ b[i];
    }
    ret
}

#[test]
fn test_stream() {
    let aes_key = <[u8; 16]>::from_hex("277c6a6de132a226fefb1c469df53446").unwrap();
    let mac_key = <[u8; 16]>::from_hex("240dc26508f0c9fc65f83138782ad919").unwrap();
    let serial = 1;
    let mut state = AesCtrHmac::new(&aes_key, &mac_key, serial);
    let data = "abcdefghijklmnopqrstuvwxyz01234567890!@#$%^&*()".as_bytes();
    let encrypted = state.encrypt_stream(data);
    let ans = state.decrypt_stream(&encrypted).unwrap();
    let ans2 = state.decrypt_stream(&encrypted).unwrap_err();
    let ans: String = String::from_utf8(ans).unwrap();
    assert_eq!(ans, String::from_utf8(data.to_owned()).unwrap());
    println!("{}", ans);
}
