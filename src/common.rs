use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum CryptError {
    #[error("failed to decrypt - wrong key.")]
    WrongKey,
    #[error("invalid key")]
    InvalidKey,
    #[error("invalid cipher text.")]
    InvalidCipherText,
    #[error("invalid mode")]
    InvalidMode,
    #[error("invalid parameter")]
    InvalidParameter,
    #[error("invalid state")]
    InvalidState,
    #[error("invalid operation")]
    InvalidOperation,
}

pub trait Crypt<T> {
    fn encrypt(data: &[u8],key: T) -> Result<Vec<u8>,CryptError>;
    fn decrypt(ciphertext: &[u8],key: T) -> Result<Vec<u8>,CryptError>;
}

pub trait StatefulCrypt<T> {
    fn encrypt(data: &[u8]) -> Result<Vec<u8>,CryptError>;
    fn decrypt(ciphertext: &[u8]) -> Result<Vec<u8>,CryptError>;
    fn set_key(key: T) -> Result<(),CryptError> {
        Err(CryptError::InvalidOperation)
    }
}

pub trait CryptoHash<const N:usize> {
    fn hash(data: &[u8]) -> Result<[u8;N],CryptError>;
}