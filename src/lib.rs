mod utils;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use std::convert::TryInto;
use thiserror::Error;
use wasm_bindgen::prelude::*;

// Global constants
// Based on RFC8439
// https://tools.ietf.org/html/rfc8439
const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 24;
const POLY1305_AUTH_TAG_SIZE: usize = 16;

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Key must be {size} bytes")]
    InvalidKeySize { size: usize },
    #[error("Data must not be empty")]
    EmptyData,
    #[error("Error generating nonce: {0}")]
    NonceGeneration(#[from] getrandom::Error),
    #[error("Error encrypting plaintext: {0}")]
    Encryption(#[source] chacha20poly1305::aead::Error),
    #[error("Error decrypting ciphertext: {0}")]
    Decryption(#[source] chacha20poly1305::aead::Error),
}

impl From<CryptoError> for JsValue {
    fn from(error: CryptoError) -> Self {
        JsValue::from_str(&error.to_string())
    }
}

#[wasm_bindgen]
pub fn encrypt(plaintext: Vec<u8>, key: Vec<u8>) -> Result<js_sys::Uint8Array, JsValue> {
    // Checks
    check_data(plaintext.as_ref())?;
    check_key_size(key.as_ref())?;

    let key_data: &[u8; 32] = key.as_slice().try_into().unwrap();

    // Encrypt the plaintext
    let ciphertext = _encrypt(plaintext.as_ref(), key_data)?;

    // Return the ciphertext
    Ok(js_sys::Uint8Array::from(&ciphertext[..]))
}

#[wasm_bindgen]
pub fn decrypt(ciphertext: Vec<u8>, key: Vec<u8>) -> Result<js_sys::Uint8Array, JsValue> {
    // Checks
    check_data(ciphertext.as_ref())?;
    check_key_size(key.as_ref())?;

    // wasm doesn't support &[u8; 32] so we have to convert it
    let key_data: &[u8; 32] = key.as_slice().try_into().unwrap();

    // Decrypt the ciphertext
    let plaintext = _decrypt(ciphertext.as_ref(), key_data)?;

    // Return the plaintext
    Ok(js_sys::Uint8Array::from(&plaintext[..]))
}

fn check_key_size(key: &[u8]) -> Result<(), CryptoError> {
    if key.len() != KEY_SIZE {
        return Err(CryptoError::InvalidKeySize { size: KEY_SIZE });
    }
    Ok(())
}

fn check_data(data: &[u8]) -> Result<(), CryptoError> {
    if data.len() == 0 {
        return Err(CryptoError::EmptyData);
    }
    Ok(())
}

fn generate_random_nonce() -> Result<[u8; NONCE_SIZE], CryptoError> {
    let mut raw_nonce = [0u8; NONCE_SIZE];
    if let Err(e) = getrandom::getrandom(&mut raw_nonce) {
        return Err(CryptoError::NonceGeneration(e));
    }
    Ok(raw_nonce)
}

fn _encrypt(plaintext: &[u8], key: &[u8; KEY_SIZE]) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut ciphertext = Vec::with_capacity(plaintext.len() + POLY1305_AUTH_TAG_SIZE + NONCE_SIZE);
    // Generate a random nonce
    let raw_nonce = generate_random_nonce()?;
    let nonce = chacha20poly1305::XNonce::from_slice(&raw_nonce);

    // Save the nonce to the ciphertext
    ciphertext.extend(nonce);

    // Encrypt the plaintext
    match cipher.encrypt(nonce, plaintext) {
        Ok(result_buffer) => {
            // Move the encrypted data into the ciphertext
            ciphertext.extend(&result_buffer);
        }
        Err(e) => return Err(CryptoError::Encryption(e)),
    };

    Ok(ciphertext)
}

fn _decrypt(ciphertext: &[u8], key: &[u8; KEY_SIZE]) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    // Get the nonce from the ciphertext
    let nonce = chacha20poly1305::XNonce::from_slice(&ciphertext[..NONCE_SIZE]);

    // Decrypt the ciphertext
    let result_buffer = match cipher.decrypt(nonce, &ciphertext[NONCE_SIZE..]) {
        Ok(result_buffer) => {
            // Move the decrypted data into the plaintext
            result_buffer
        }
        Err(e) => return Err(CryptoError::Decryption(e)),
    };

    Ok(result_buffer)
}
