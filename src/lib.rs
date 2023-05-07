// Copyright (c) 2023 dumitory-dev. All rights reserved.
// This work is licensed under the terms of the MIT license.
// For a copy, see <https://opensource.org/licenses/MIT>.

pub mod constants;
pub mod crypt_utils;
pub mod errors;
use crypt_utils::{
    perform_decryption, perform_encryption, validate_key_size, validate_non_empty_data,
};
use std::convert::TryInto;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

// export log function from js
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

/// This function encrypts the given plaintext using the XChaCha20Poly1305 algorithm and returns the resulting ciphertext as a js_sys::Uint8Array.
/// # Arguments
///
/// * `plaintext` - The plaintext to encrypt. Must not be empty.
/// * `key` - The key to use for encryption. Must be 32 bytes long.
///
/// # Returns
///
/// The ciphertext.
///
/// # Errors
///
/// Returns an error if the plaintext is empty or the key is not 32 bytes long.
#[wasm_bindgen]
pub fn encrypt(plaintext: &[u8], key: &[u8]) -> Result<js_sys::Uint8Array, JsValue> {
    // Checks
    validate_key_size(key)?;
    validate_non_empty_data(plaintext)?;

    let key_data: &[u8; 32] = key.try_into().unwrap();

    // Encrypt the plaintext
    let encrypted_data = perform_encryption(plaintext, key_data)?;

    // Return the ciphertext
    Ok(js_sys::Uint8Array::from(&encrypted_data[..]))
}

/// This function decrypts the given ciphertext using the XChaCha20Poly1305 algorithm and returns the resulting plaintext as a js_sys::Uint8Array.
/// # Arguments
///
/// * `ciphertext` - The ciphertext to decrypt. Must not be empty.
/// * `key` - The key to use for decryption. Must be 32 bytes long.
///
/// # Returns
///
/// The plaintext.
///
/// # Errors
///
/// Returns an error if the ciphertext is empty or the key is not 32 bytes long.
#[wasm_bindgen]
pub fn decrypt(ciphertext: &[u8], key: &[u8]) -> Result<js_sys::Uint8Array, JsValue> {
    // Checks
    validate_key_size(key)?;
    validate_non_empty_data(ciphertext)?;

    // wasm doesn't support &[u8; 32] so we have to convert it
    let key_data: &[u8; 32] = key.try_into().unwrap();

    // Decrypt the ciphertext
    let decrypted_data = perform_decryption(ciphertext, key_data)?;

    // Return the plaintext
    Ok(js_sys::Uint8Array::from(&decrypted_data[..]))
}

/// This asynchronous function encrypts the given plaintext using the XChaCha20Poly1305 algorithm
/// and returns a js_sys::Promise that resolves with the resulting ciphertext as a js_sys::Uint8Array.
/// # Arguments
///
/// * `plaintext` - The plaintext to encrypt. Must not be empty.
/// * `key` - The key to use for encryption. Must be 32 bytes long.
///
/// # Returns
///
/// The ciphertext.
///
/// # Errors
///
/// Returns an error if the plaintext is empty or the key is not 32 bytes long.
#[wasm_bindgen]
pub fn encrypt_async(plaintext: Vec<u8>, key: Vec<u8>) -> js_sys::Promise {
    // Wrap Rust future in a JavaScript Promise
    future_to_promise(async move {
        validate_key_size(&key)?;
        validate_non_empty_data(&plaintext)?;
        let encrypted_data = perform_encryption(&plaintext, key.as_slice().try_into().unwrap())?;
        let uint8array = js_sys::Uint8Array::from(&encrypted_data[..]);
        Ok(uint8array.into())
    })
}

/// This asynchronous function decrypts the given ciphertext using the XChaCha20Poly1305 algorithm
/// and returns a js_sys::Promise that resolves with the resulting plaintext as a js_sys::Uint8Array
/// # Arguments
///
/// * `ciphertext` - The ciphertext to decrypt. Must not be empty.
/// * `key` - The key to use for decryption. Must be 32 bytes long.
///
/// # Returns
///
/// The plaintext.
///
/// # Errors
///
/// Returns an error if the ciphertext is empty or the key is not 32 bytes long.
#[wasm_bindgen]
pub fn decrypt_async(plaintext: Vec<u8>, key: Vec<u8>) -> js_sys::Promise {
    // Wrap Rust future in a JavaScript Promise
    future_to_promise(async move {
        validate_key_size(&key)?;
        validate_non_empty_data(&plaintext)?;
        let decrypted_data = perform_decryption(&plaintext, key.as_slice().try_into().unwrap())?;
        let uint8array = js_sys::Uint8Array::from(&decrypted_data[..]);
        Ok(uint8array.into())
    })
}
