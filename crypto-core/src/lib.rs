use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use zeroize::Zeroize;

const FILE_KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 24;

#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    Randomness,
    Encryption,
    Decryption,
}

pub struct FileKey([u8; FILE_KEY_SIZE]);

impl FileKey {
    pub fn generate() -> Result<Self, CryptoError> {
        let mut bytes = [0u8; FILE_KEY_SIZE];
        getrandom::getrandom(&mut bytes).map_err(|_| CryptoError::Randomness)?;
        Ok(Self(bytes))
    }

    pub fn from_bytes(bytes: [u8; FILE_KEY_SIZE]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; FILE_KEY_SIZE] {
        &self.0
    }
}

impl Drop for FileKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub struct EncryptedChunk {
    pub nonce: [u8; NONCE_SIZE],
    pub ciphertext: Vec<u8>,
}

pub fn encrypt_chunk(
    key: &FileKey,
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<EncryptedChunk, CryptoError> {
    let mut nonce = [0u8; NONCE_SIZE];
    getrandom::getrandom(&mut nonce).map_err(|_| CryptoError::Randomness)?;

    let cipher_key = Key::from(*key.as_bytes());
    let cipher = XChaCha20Poly1305::new(&cipher_key);
    let cipher_nonce = XNonce::from(nonce);
    let ciphertext = cipher
        .encrypt(
            &cipher_nonce,
            Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .map_err(|_| CryptoError::Encryption)?;

    Ok(EncryptedChunk { nonce, ciphertext })
}

pub fn decrypt_chunk(
    key: &FileKey,
    chunk: &EncryptedChunk,
    associated_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher_key = Key::from(*key.as_bytes());
    let cipher = XChaCha20Poly1305::new(&cipher_key);
    let cipher_nonce = XNonce::from(chunk.nonce);
    cipher
        .decrypt(
            &cipher_nonce,
            Payload {
                msg: &chunk.ciphertext,
                aad: associated_data,
            },
        )
        .map_err(|_| CryptoError::Decryption)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypts_and_decrypts_a_chunk() {
        let key = FileKey::generate().unwrap();
        let plaintext = b"secret chunk";
        let aad = b"file-id:chunk-0";

        let encrypted = encrypt_chunk(&key, plaintext, aad).unwrap();
        let decrypted = decrypt_chunk(&key, &encrypted, aad).unwrap();

        assert_eq!(decrypted, plaintext);
        assert_ne!(encrypted.nonce, [0u8; NONCE_SIZE]);
    }

    #[test]
    fn rejects_modified_associated_data() {
        let key = FileKey::generate().unwrap();
        let encrypted = encrypt_chunk(&key, b"secret chunk", b"original-aad").unwrap();

        let result = decrypt_chunk(&key, &encrypted, b"modified-aad");

        assert_eq!(result, Err(CryptoError::Decryption));
    }
}
