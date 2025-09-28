# YSC2 Cryptographic Suite

[![Crates.io](https://img.shields.io/crates/v/ysc2?style=for-the-badge)](https://crates.io/crates/ysc2)
[![Docs.rs](https://img.shields.io/docsrs/ysc2?style=for-the-badge)](https://docs.rs/ysc2)

**YSC2** is a versatile cryptographic suite built around a high-performance permutation designed with FHE (Fully Homomorphic Encryption) friendliness in mind.

This workspace consists of the following crates:

- **`ysc2`**: The main crate, which utilizes the core permutation to provide various cryptographic functionalities, including a stream cipher, hash function (YSC2X), and AEAD.
- **`auxcrypt`**: An auxiliary stream cipher scheme with a distinct internal structure. It can be used alongside YSC2 to provide an additional layer of security.

## 🚀 Features

- **Multi-Purpose**: Implements a stream cipher, hash, MAC, XOF, and AEAD based on a single permutation.
- **High Performance**: Offers a `soft` backend for stable operation on all platforms and a `simd` backend that leverages modern CPU features for maximum performance.
- **FHE-Friendly Design**: The YSC2 permutation is constructed using only AND, XOR, and bitwise rotation operations, avoiding S-Boxes and modular addition to minimize computational complexity in FHE environments.
- **Robust Security**: Provides 128-bit and 256-bit post-quantum security levels.
- **Flexible Architecture**: Easily extensible with new security parameters through the `Ysc2Variant` trait.

---

## 🏗️ Workspace Structure

This project uses a Cargo workspace to manage each cryptographic scheme in a modular fashion.

- `ysc2/`: The main YSC2 crate
  - `src/stream.rs`: Stream cipher mode of operation
  - `src/sponge.rs`: Sponge construction for Hash, MAC, and XOF (YSC2X)
  - `src/aead.rs`: Authenticated Encryption (AEAD) mode (YSC2X)
  - `src/backends/`: `soft` and `simd` permutation implementations
- `auxcrypt/`: The auxiliary AuxCrypt crate
  - `src/stream.rs`: Stream cipher mode of operation
  - `src/backends/`: `soft` and `simd` permutation implementations

## 🛠️ Usage

Add the `ysc2` crate to your `Cargo.toml` and enable the features you need.

```toml
[dependencies]
ysc2 = { version = "0.1", features = ["ysc2x"] }
```

### Stream Cipher

```rust
use ysc2::Ysc2_512StreamCipher;
use ysc2::cipher::{KeyIvInit, StreamCipher};

let key = [0x42; 64].into();
let nonce = [0x24; 64].into();
let mut buffer = vec![1, 2, 3, 4, 5];

// Encrypt
let mut cipher = Ysc2_512StreamCipher::new(&key, &nonce);
cipher.apply_keystream(&mut buffer);

// Decrypt
let mut cipher = Ysc2_512StreamCipher::new(&key, &nonce);
cipher.apply_keystream(&mut buffer);

assert_eq!(buffer, &[1, 2, 3, 4, 5]);
```

### Hash Function (YSC2X)

When the `ysc2x` feature is enabled, you can use various sponge functions based on the YSC2 permutation.

#### Fixed-Output Hash
```rust
use ysc2::Ysc2_512Hash;
use ysc2::digest::{Digest, Update};

let mut hasher = Ysc2_512Hash::default();
hasher.update(b"hello world");
let hash_result = hasher.finalize(); // 64-byte output

println!("Hash value: {:x}", hash_result);
```

#### Extendable-Output Function (XOF)
XOFs can produce an output of any desired length, making them suitable for various applications like Key Derivation (KDFs).
```rust
use ysc2::Ysc2_512Hasher;
use ysc2::digest::{ExtendableOutput, Update, XofReader};

let mut hasher = Ysc2_512Hasher::default();
hasher.update(b"important data");

let mut output = vec![0u8; 100]; // Request 100 bytes of output
let mut xof_reader = hasher.finalize_xof();
xof_reader.read(&mut output);

// println!("100-byte XOF output: {:x}", output);
```

#### Message Authentication Code (MAC)
Verifies the integrity and authenticity of a message using a secret key.
```rust
use ysc2::Ysc2_512Mac;
use ysc2::digest::{KeyInit, Mac};

let key = [0xAB; 64];
let mut mac = Ysc2_512Mac::new_from_slice(&key).expect("MAC key initialization failed");
mac.update(b"message to authenticate");

// Verify the MAC
let result = mac.finalize();
let code_bytes = result.into_bytes();

let mut mac = Ysc2_512Mac::new_from_slice(&key).expect("MAC key initialization failed");
mac.update(b"message to authenticate");
mac.verify_slice(&code_bytes).expect("MAC verification successful");
```

### Authenticated Encryption (AEAD)

```rust
use ysc2::Ysc2_512Aead;
use ysc2::aead_api::{Aead, AeadInPlace, KeyInit};
use ysc2::aead_api::generic_array::GenericArray;
// Use a PRNG for reproducible key generation in examples and tests.
use rand_core::SeedableRng;
use rand_chacha::ChaCha8Rng;

let mut rng = ChaCha8Rng::from_seed([42; 32]);
let key = Ysc2_512Aead::generate_key(&mut rng);
let cipher = Ysc2_512Aead::new(&key);
let nonce = GenericArray::from([0u8; 64]); // 64-byte Nonce
let mut buffer = b"plaintext message".to_vec();

// Encrypt in-place
let tag = cipher.encrypt_in_place_detached(&nonce, b"associated data", &mut buffer)
    .expect("AEAD encryption failed");

// Decrypt in-place
cipher.decrypt_in_place_detached(&nonce, b"associated data", &mut buffer, &tag)
    .expect("AEAD decryption failed");

assert_eq!(&buffer, b"plaintext message");
```

## 📜 License

This project is distributed under the BSD-2-Clause license. See the `LICENSE` file for details.