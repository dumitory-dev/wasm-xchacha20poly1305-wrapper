// Copyright (c) 2023 dumitory-dev. All rights reserved.
// This work is licensed under the terms of the MIT license.
// For a copy, see <https://opensource.org/licenses/MIT>.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::XChaCha20Poly1305;

use crate::constants::{KEY_SIZE, NONCE_SIZE, POLY1305_AUTH_TAG_SIZE};
use crate::errors::CryptoError;

pub fn perform_encryption(plaintext: &[u8], key: &[u8; KEY_SIZE]) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let raw_nonce = generate_random_nonce()?;
    let nonce = chacha20poly1305::XNonce::from_slice(&raw_nonce);

    let mut ciphertext = Vec::with_capacity(plaintext.len() + POLY1305_AUTH_TAG_SIZE + NONCE_SIZE);
    ciphertext.extend(nonce);

    cipher
        .encrypt(nonce, plaintext)
        .map_err(CryptoError::Encryption)
        .map(|result_buffer| {
            ciphertext.extend(&result_buffer);
            ciphertext
        })
}

pub fn perform_decryption(ciphertext: &[u8], key: &[u8; KEY_SIZE]) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = chacha20poly1305::XNonce::from_slice(&ciphertext[..NONCE_SIZE]);

    cipher
        .decrypt(nonce, &ciphertext[NONCE_SIZE..])
        .map_err(CryptoError::Decryption)
}

fn generate_random_nonce() -> Result<[u8; NONCE_SIZE], CryptoError> {
    let mut raw_nonce = [0u8; NONCE_SIZE];
    getrandom::getrandom(&mut raw_nonce).map_err(CryptoError::NonceGeneration)?;
    Ok(raw_nonce)
}

pub fn validate_key_size(key: &[u8]) -> Result<(), CryptoError> {
    if key.len() != KEY_SIZE {
        return Err(CryptoError::InvalidKeySize { size: KEY_SIZE });
    }
    Ok(())
}

pub fn validate_non_empty_data(data: &[u8]) -> Result<(), CryptoError> {
    if data.is_empty() {
        return Err(CryptoError::EmptyData);
    }
    Ok(())
}
