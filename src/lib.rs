// Copyright (c) 2023 dumitory-dev. All rights reserved.
// This work is licensed under the terms of the MIT license.
// For a copy, see <https://opensource.org/licenses/MIT>.

mod constants;
mod crypt_utils;
mod errors;

use crypt_utils::{
    perform_decryption, perform_encryption, validate_key_size, validate_non_empty_data,
};
use std::convert::TryInto;
use wasm_bindgen::prelude::*;

// export log function from js
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

/// # Panics
/// key.as_slice().try_into().unwrap() can panic if the key is not 32 bytes long.
/// but we already checked that in validate_key_size so it's safe to unwrap here.
#[wasm_bindgen]
pub fn encrypt(plaintext: &[u8], key: &[u8]) -> Result<js_sys::Uint8Array, JsValue> {
    // Checks
    validate_key_size(key)?;
    validate_non_empty_data(plaintext)?;

    let key_data: &[u8; 32] = key.try_into().unwrap();

    // Encrypt the plaintext
    let ciphertext = perform_encryption(plaintext, key_data)?;

    // Return the ciphertext
    Ok(js_sys::Uint8Array::from(&ciphertext[..]))
}

/// # Panics
/// key.as_slice().try_into().unwrap() can panic if the key is not 32 bytes long.
/// but we already checked that in validate_key_size so it's safe to unwrap here.
#[wasm_bindgen]
pub fn decrypt(ciphertext: &[u8], key: &[u8]) -> Result<js_sys::Uint8Array, JsValue> {
    // Checks
    validate_key_size(key)?;
    validate_non_empty_data(ciphertext)?;

    // wasm doesn't support &[u8; 32] so we have to convert it
    let key_data: &[u8; 32] = key.try_into().unwrap();

    // Decrypt the ciphertext
    let plaintext = perform_decryption(ciphertext, key_data)?;

    // Return the plaintext
    Ok(js_sys::Uint8Array::from(&plaintext[..]))
}
