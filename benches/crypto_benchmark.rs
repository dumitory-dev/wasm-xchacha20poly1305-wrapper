// Copyright (c) 2023 dumitory-dev. All rights reserved.
// This work is licensed under the terms of the MIT license.
// For a copy, see <https://opensource.org/licenses/MIT>.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use xchacha20_poly1305_wasm::constants::KEY_SIZE;
use xchacha20_poly1305_wasm::crypt_utils::{perform_decryption, perform_encryption};

fn encryption_benchmark(c: &mut Criterion) {
    let plaintext = b"Hello, world!";
    let key = [0u8; KEY_SIZE];

    c.bench_function("encryption", |b| {
        b.iter(|| perform_encryption(black_box(plaintext), black_box(&key)))
    });
}

fn decryption_benchmark(c: &mut Criterion) {
    let plaintext = b"Hello, world!";
    let key = [0u8; KEY_SIZE];
    let ciphertext = perform_encryption(plaintext, &key).unwrap();

    c.bench_function("decryption", |b| {
        b.iter(|| perform_decryption(black_box(&ciphertext), black_box(&key)))
    });
}

fn big_decryption_benchmark(c: &mut Criterion) {
    // 1MB
    let plaintext = [0u8; 1024 * 1024];
    let key = [0u8; KEY_SIZE];
    let ciphertext = perform_encryption(plaintext.as_ref(), &key).unwrap();

    c.bench_function("big decryption", |b| {
        b.iter(|| perform_decryption(black_box(&ciphertext), black_box(&key)))
    });
}

fn big_encryption_benchmark(c: &mut Criterion) {
    // 1MB
    let plaintext = [0u8; 1024 * 1024];
    let key = [0u8; KEY_SIZE];

    c.bench_function("big encryption", |b| {
        b.iter(|| perform_encryption(black_box(plaintext.as_ref()), black_box(&key)))
    });
}

criterion_group!(
    benches,
    encryption_benchmark,
    decryption_benchmark,
    big_decryption_benchmark,
    big_encryption_benchmark
);
criterion_main!(benches);
