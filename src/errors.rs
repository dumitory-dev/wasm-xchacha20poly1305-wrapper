// Copyright (c) 2023 dumitory-dev. All rights reserved.
// This work is licensed under the terms of the MIT license.
// For a copy, see <https://opensource.org/licenses/MIT>.

use thiserror::Error;
use wasm_bindgen::prelude::*;

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
