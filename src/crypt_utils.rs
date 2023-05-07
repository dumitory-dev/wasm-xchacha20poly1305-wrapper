// Copyright (c) 2023 dumitory-dev. All rights reserved.
// This work is licensed under the terms of the MIT license.
// For a copy, see <https://opensource.org/licenses/MIT>.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::XChaCha20Poly1305;

use crate::constants::{KEY_SIZE, NONCE_SIZE, POLY1305_AUTH_TAG_SIZE};
use crate::errors::CryptoError;

/// Encrypts the given plaintext using the given key.
/// Returns the ciphertext.
/// # Errors
/// Returns an error if encrypt fails.
pub fn perform_encryption(plaintext: &[u8], key: &[u8; KEY_SIZE]) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let raw_nonce = generate_random_nonce()?;
    let nonce = chacha20poly1305::XNonce::from_slice(&raw_nonce);

    let mut ciphertext = Vec::with_capacity(plaintext.len() + POLY1305_AUTH_TAG_SIZE + NONCE_SIZE);
    ciphertext.extend_from_slice(nonce.as_ref());

    cipher
        .encrypt(nonce, plaintext)
        .map_err(CryptoError::Encryption)
        .map(|mut result_buffer| {
            ciphertext.append(&mut result_buffer);
            ciphertext
        })
}

/// Decrypts the given ciphertext using the given key.
/// Returns the plaintext.
/// # Errors
/// Returns an error if decrypt fails.
pub fn perform_decryption(ciphertext: &[u8], key: &[u8; KEY_SIZE]) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = chacha20poly1305::XNonce::from_slice(&ciphertext[..NONCE_SIZE]);

    cipher
        .decrypt(nonce, &ciphertext[NONCE_SIZE..])
        .map_err(CryptoError::Decryption)
}

/// Validates the given key size.
/// # Errors
/// Returns an error if key size is invalid.
pub fn validate_key_size(key: &[u8]) -> Result<(), CryptoError> {
    if key.len() != KEY_SIZE {
        return Err(CryptoError::InvalidKeySize { size: KEY_SIZE });
    }
    Ok(())
}

/// Validates the given data is not empty.
/// # Errors
/// Returns an error if data is empty.
pub fn validate_non_empty_data(data: &[u8]) -> Result<(), CryptoError> {
    if data.is_empty() {
        return Err(CryptoError::EmptyData);
    }
    Ok(())
}

fn generate_random_nonce() -> Result<[u8; NONCE_SIZE], CryptoError> {
    let mut raw_nonce = [0u8; NONCE_SIZE];
    getrandom::getrandom(&mut raw_nonce).map_err(CryptoError::NonceGeneration)?;
    Ok(raw_nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_perform_encryption() {
        let plaintext = b"Hello, world!";
        let key = [0u8; KEY_SIZE];
        let ciphertext = perform_encryption(plaintext, &key).unwrap();
        assert_ne!(plaintext, ciphertext.as_slice());
    }

    #[test]
    fn test_perform_decryption() {
        // Test with valid key
        let plaintext = b"Hello, world!";
        let key = [0u8; KEY_SIZE];
        let ciphertext = perform_encryption(plaintext, &key).unwrap();
        let decrypted = perform_decryption(&ciphertext, &key).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());

        // Test with invalid key
        let invalid_key = [1u8; KEY_SIZE];
        let decrypted = perform_decryption(&ciphertext, &invalid_key);
        assert!(decrypted.is_err());
    }

    #[test]
    fn test_validate_key_size() {
        let true_key = [0u8; KEY_SIZE];
        let small_key = [0u8; KEY_SIZE - 1];
        let big_key = [0u8; KEY_SIZE + 1];

        assert!(validate_key_size(&true_key).is_ok());
        assert!(validate_key_size(&small_key[..KEY_SIZE - 1]).is_err());
        assert!(validate_key_size(&big_key[..KEY_SIZE + 1]).is_err());
    }

    #[test]
    fn test_validate_non_empty_data() {
        assert!(validate_non_empty_data(b"Hello, world!").is_ok());
        assert!(validate_non_empty_data(b"").is_err());
    }
}
