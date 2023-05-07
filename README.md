# wasm-xchacha20poly1305-wrapper

`wasm-xchacha20poly1305-wrapper` is a WebAssembly wrapper for the XChaCha20Poly1305 encryption algorithm. This library enables developers to use the powerful encryption capabilities of the Chacha20Poly1305 cryptographic algorithm in web applications.

## Features

- WebAssembly wrapper for XChacha20Poly1305 encryption algorithm
- Functions directly callable from JavaScript
- Input validation for data and keys
- Designed for web applications that require strong encryption and decryption

## Getting Started

### Prerequisites

Ensure the following tools are installed on your system:

- Rust (latest stable version)
- wasm-pack

### Installation

1. Clone the repository:
```
git clone https://github.com/dumitory-dev/wasm-xchacha20poly1305-wrapper.git
```

2. Build the WebAssembly package:
```
cd wasm-xchacha20poly1305-wrapper
wasm-pack build --target web
```

3. The compiled WebAssembly module will be available in the `pkg` directory.

## Usage

Include the generated JavaScript and WebAssembly files in your web application:

```html
<script type="module">
import { encrypt, decrypt, encrypt_async, decrypt_async } from './pkg/wasm_xchacha20poly1305_wrapper.js';

async function run() {
 const plaintext = new Uint8Array([72, 101, 108, 108, 111, 44, 32, 87, 111, 114, 108, 100]); // Hello, World
 const key = new Uint8Array(32); // Use a properly generated 256-bit key for real-world applications

 // Synchronous encryption
 const ciphertext = encrypt(plaintext, key);
 console.log('Ciphertext:', ciphertext);

 // Synchronous decryption
 const decrypted = decrypt(ciphertext, key);
 console.log('Decrypted:', decrypted);

 // Asynchronous encryption
 const asyncCiphertext = await encrypt_async(plaintext, key);
 console.log('Async Ciphertext:', asyncCiphertext);

 // Asynchronous decryption
 const asyncDecrypted = await decrypt_async(asyncCiphertext, key);
 console.log('Async Decrypted:', asyncDecrypted);
}

run();
</script>

```
## Running Tests

To run the tests for the library, execute the following command in the project's root directory:
```
cargo test
```
This command will run all the unit tests defined in the Rust source code.

## Running Benchmarks

To run benchmarks for the library, you need to install the criterion crate:

```
cargo install cargo-criterion
```
After installing cargo-criterion, you can run the benchmarks with the following command:

```
cargo criterion
```

This command will run all the benchmark tests and generate an HTML report in the target/criterion/report directory.

## License

This project is licensed under the terms of the MIT license. 
For a copy, see https://opensource.org/licenses/MIT.
