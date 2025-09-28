# YSC2 암호화 스위트

<!--
[![Crates.io](https://img.shields.io/crates/v/ysc2?style=for-the-badge)](https://crates.io/crates/ysc2)
[![Docs.rs](https://img.shields.io/docsrs/ysc2?style=for-the-badge)](https://docs.rs/ysc2)
-->
**YSC2**는 FHE(완전 동형 암호) 환경 친화성을 목표로 설계된 고성능 순열(permutation)을 기반으로 하는 다목적 암호화 스위트(cryptographic suite)입니다.

이 워크스페이스는 다음과 같은 크레이트들로 구성됩니다:

- **`ysc2`**: 핵심 순열을 사용하여 스트림 암호, 해시 함수(YSC2X), AEAD 등 다양한 암호학적 기능을 제공하는 메인 크레이트입니다.
- **`auxcrypt`**: YSC2와는 다른 독자적인 구조를 가진 보조 스트림 암호 스킴입니다. YSC2와 함께 사용하여 추가적인 보안 계층을 제공할 수 있습니다.

## 🚀 특징

- **다양한 기능 제공**: 스트림 암호, 해시, MAC, XOF, AEAD를 단일 순열 기반으로 구현.
- **고성능**: 모든 플랫폼에서 안정적으로 동작하는 `soft` 백엔드와, 최신 CPU의 SIMD 기능을 활용하여 성능을 극대화하는 `simd` 백엔드 제공.
- **FHE 친화적 설계**: YSC2 순열은 S-Box나 모듈러 덧셈 없이 AND, XOR, 비트 회전(Rotate) 연산만으로 구성되어 FHE 환경에서의 연산 복잡도를 최소화합니다.
- **강력한 보안**: 128비트 및 256비트 양자 내성 보안 수준을 제공합니다.
- **유연한 아키텍처**: `Ysc2Variant` 트레잇을 통해 다양한 보안 파라미터를 쉽게 추가하고 확장할 수 있습니다.

---

## 🏗️ 워크스페이스 구조


본 프로젝트는 Cargo 워크스페이스를 사용하여 각 암호 스킴을 모듈식으로 관리합니다.

- `ysc2/`: 메인 YSC2 크레이트
  - `src/stream.rs`: 스트림 암호 모드
  - `src/sponge.rs`: 해시, MAC, XOF를 위한 스펀지(Sponge) 구조
  - `src/aead.rs`: 인증 암호(AEAD) 모드
  - `src/backends/`: `soft` 및 `simd` 순열 구현
- `auxcrypt/`: 보조 AuxCrypt 크레이트
  - `src/stream.rs`: 스트림 암호 모드
  - `src/backends/`: `soft` 및 `simd` 순열 구현

## 🛠️ 사용법

`ysc2` 크레이트를 `Cargo.toml`에 추가하여 사용할 수 있습니다. 필요한 기능에 따라 `features`를 활성화하세요.

```toml
[dependencies]
ysc2 = { version = "0.1", features = ["ysc2x"] }
```

### 스트림 암호 (Stream Cipher)

```rust
use ysc2::Ysc2_512StreamCipher;
use ysc2::cipher::{KeyIvInit, StreamCipher};

let key = [0x42; 64].into();
let nonce = [0x24; 64].into();
let mut buffer = [1, 2, 3, 4, 5];

// 암호화
let mut cipher = Ysc2_512StreamCipher::new(&key, &nonce);
cipher.apply_keystream(&mut buffer);

// 복호화
let mut cipher = Ysc2_512StreamCipher::new(&key, &nonce);
cipher.apply_keystream(&mut buffer);

assert_eq!(buffer, [1, 2, 3, 4, 5]);
```

### 해시 함수 (YSC2X)

`ysc2x` 기능이 활성화되면, YSC2 순열을 기반으로 한 다양한 스펀지 함수를 사용할 수 있습니다.

#### 고정 길이 해시 (Fixed-Output Hash)
```rust
use ysc2::Ysc2_512Hash;
use ysc2::digest::{Digest, Update};

let mut hasher = Ysc2_512Hash::default();
hasher.update(b"hello world");
let hash_result = hasher.finalize(); // 64바이트 출력

println!("해시 값: {:x}", hash_result);
```

#### 가변 길이 해시/XOF (Extendable-Output Function)
XOF는 원하는 길이의 해시 값을 생성할 수 있어, 키 유도(KDF) 등 다양한 용도로 활용됩니다.
```rust
use ysc2::Ysc2_512Hasher;
use ysc2::digest::{ExtendableOutput, Update};

let mut hasher = Ysc2_512Hasher::default();
hasher.update(b"important data");

let mut output = vec![0u8; 100]; // 100바이트 길이의 출력 요청
let mut xof_reader = hasher.finalize_xof();
xof_reader.read(&mut output);

println!("100바이트 XOF 출력: {:x}", output);
```

#### 메시지 인증 코드 (MAC)
키를 사용하여 메시지의 무결성과 신뢰성을 검증합니다.
```rust
use ysc2::Ysc2_512Mac;
use ysc2::digest::{KeyInit, Mac};

let key = [0xAB; 64];
let mut mac = Ysc2_512Mac::new_from_slice(&key).expect("MAC 키 초기화 실패");
mac.update(b"message to authenticate");

// MAC 검증
let result = mac.finalize();
let code_bytes = result.into_bytes();

let mut mac = Ysc2_512Mac::new_from_slice(&key).expect("MAC 키 초기화 실패");
mac.update(b"message to authenticate");
mac.verify_slice(&code_bytes).expect("MAC 검증 성공");
```

### 인증 암호 (AEAD)

```rust
use ysc2::Ysc2_512Aead;
use ysc2::aead_api::{Aead, KeyInit, OsRng};
use ysc2::aead_api::generic_array::GenericArray;

let key = Ysc2_512Aead::generate_key(&mut OsRng);
let cipher = Ysc2_512Aead::new(&key);
let nonce = GenericArray::from([0u8; 64]); // 64바이트 Nonce

let ciphertext = cipher.encrypt(&nonce, b"plaintext message".as_ref())
    .expect("AEAD 암호화 실패");

let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref())
    .expect("AEAD 복호화 실패");

assert_eq!(&plaintext, b"plaintext message");
```

## 📜 라이선스

이 프로젝트는 BSD-2-Clause 라이선스 하에 배포됩니다. 자세한 내용은 `LICENSE` 파일을 참고하세요.
```
```markdown:YSC2 Workspace README (English):README.md
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
  - `src/sponge.rs`: Sponge construction for Hash, MAC, and XOF
  - `src/aead.rs`: Authenticated Encryption (AEAD) mode
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
let mut buffer = [1, 2, 3, 4, 5];

// Encrypt
let mut cipher = Ysc2_512StreamCipher::new(&key, &nonce);
cipher.apply_keystream(&mut buffer);

// Decrypt
let mut cipher = Ysc2_512StreamCipher::new(&key, &nonce);
cipher.apply_keystream(&mut buffer);

assert_eq!(buffer, [1, 2, 3, 4, 5]);
```

### Hash Function (YSC2X)

```rust
use ysc2::Ysc2_512Hash;
use ysc2::digest::{Digest, Update};

let mut hasher = Ysc2_512Hash::default();
hasher.update(b"hello world");
let hash_result = hasher.finalize();

println!("Hash: {:x}", hash_result);
```

### Authenticated Encryption (AEAD)

```rust
use ysc2::Ysc2_512Aead;
use ysc2::aead_api::{Aead, KeyInit, OsRng};
use ysc2::aead_api::generic_array::GenericArray;

let key = Ysc2_512Aead::generate_key(&mut OsRng);
let cipher = Ysc2_512Aead::new(&key);
let nonce = GenericArray::from([0u8; 64]); // 64-byte Nonce

let ciphertext = cipher.encrypt(&nonce, b"plaintext message".as_ref())
    .expect("AEAD encryption failed");

let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref())
    .expect("AEAD decryption failed");

assert_eq!(&plaintext, b"plaintext message");
```

## 📜 License

This project is distributed under the BSD-2-Clause license. See the `LICENSE` file for details.
```
```markdown:YSC2 Crate README (Korean):ysc2/README.md
# YSC2

[![Crates.io](https://img.shields.io/crates/v/ysc2?style=for-the-badge)](https://crates.io/crates/ysc2)
[![Docs.rs](https://img.shields.io/docsrs/ysc2?style=for-the-badge)](https://docs.rs/ysc2)

**YSC2**는 FHE(완전 동형 암호) 환경 친화성을 목표로 설계된 고성능 순열(permutation)을 기반으로 하는 다목적 암호화 크레이트입니다.

이 크레이트는 단일 핵심 순열을 재사용하여 다음과 같은 다양한 암호학적 기능을 제공합니다:

- **스트림 암호 (Stream Cipher)**
- **해시 함수 (Hash Function)**
- **메시지 인증 코드 (MAC)**
- **가변 길이 출력 함수 (XOF)**
- **인증 암호 (AEAD)**

## 🛠️ 기능 플래그 (Features)

YSC2는 기능 플래그를 통해 필요한 기능만 선택적으로 컴파일하여 바이너리 크기를 최적화할 수 있습니다.

- `ysc2x`: 해시, MAC, XOF, AEAD 등 스펀지 기반의 모든 추가 기능을 활성화합니다.
- `simd`: `portable_simd`를 사용하는 고성능 백엔드를 활성화합니다. (Nightly 툴체인 필요)
- `auxcrypt`: 보조 암호 스킴인 `auxcrypt`와의 통합 기능을 활성화합니다. (현재는 기능 정의만 되어 있음)

## 📖 상세 설계

YSC2의 핵심 설계, 순열 함수, 백엔드 구현에 대한 자세한 내용은 워크스페이스 루트의 [README.md](../README.md) 파일을 참고하십시오.
```
```markdown:YSC2 Crate README (English):ysc2/README.md
# YSC2

[![Crates.io](https://img.shields.io/crates/v/ysc2?style=for-the-badge)](https://crates.io/crates/ysc2)
[![Docs.rs](https://img.shields.io/docsrs/ysc2?style=for-the-badge)](https://docs.rs/ysc2)

**YSC2** is a versatile cryptographic crate built around a high-performance permutation designed with FHE (Fully Homomorphic Encryption) friendliness in mind.

This crate reuses a single core permutation to provide a wide range of cryptographic functionalities:

- **Stream Cipher**
- **Hash Function**
- **Message Authentication Code (MAC)**
- **Extendable-Output Function (XOF)**
- **Authenticated Encryption with Associated Data (AEAD)**

## 🛠️ Feature Flags

YSC2 uses feature flags to allow selective compilation, optimizing binary size by including only the necessary functionalities.

- `ysc2x`: Enables all additional sponge-based features, including Hash, MAC, XOF, and AEAD.
- `simd`: Enables the high-performance backend using `portable_simd`. (Requires a nightly toolchain)
- `auxcrypt`: Enables integration with the `auxcrypt` auxiliary cipher. (Currently, this is a placeholder for future integration)

## 📖 Design Details

For detailed information on the core design, permutation function, and backend implementations of YSC2, please refer to the [README.md](../README.md) file in the workspace root.
```
```markdown:AuxCrypt Crate README (Korean):auxcrypt/README.md
# AuxCrypt

**AuxCrypt**는 YSC2 암호화 스위트를 위한 보조 스트림 암호 스킴입니다.

이 암호는 YSC2와는 완전히 다른 내부 구조를 가지고 있으며, 4차원 하이퍼큐브로 해석된 내부 상태에 Lai-Massey 구조를 반복적으로 적용하는 독특한 설계를 특징으로 합니다.

## 🚀 목적

AuxCrypt의 주된 목적은 YSC2와 함께 사용될 때 추가적인 보안 계층을 제공하는 것입니다. 예를 들어, AuxCrypt가 생성한 키스트림을 YSC2 스펀지 구조의 추가 입력(auxiliary input)으로 사용하여 도메인 분리나 키 유도 과정을 더욱 강화할 수 있습니다.

## 📖 상세 설계

- **내부 상태**: 1024비트 (16 x 64비트 워드)
- **비선형 함수**: `f(x) = (¬x) ⊕ (x <<< R_A) ⊕ (x <<< R_B)` (비트 NOT, XOR, 회전)
- **구조**: 4차원 Lai-Massey 구조
- **백엔드**: YSC2와 동일하게 `soft` 및 `simd` 백엔드를 지원합니다.

자세한 내용은 워크스페이스 루트의 [README.md](../README.md) 파일을 참고하십시오.
```
```markdown:AuxCrypt Crate README (English):auxcrypt/README.md
# AuxCrypt

**AuxCrypt** is an auxiliary stream cipher scheme for the YSC2 cryptographic suite.

This cipher features an internal structure completely distinct from YSC2, characterized by a unique design that repeatedly applies a Lai-Massey structure to an internal state interpreted as a 4-dimensional hypercube.

## 🚀 Purpose

The primary purpose of AuxCrypt is to provide an additional layer of security when used in conjunction with YSC2. For example, a keystream generated by AuxCrypt can be used as an auxiliary input to the YSC2 sponge construction to further strengthen domain separation or key derivation processes.

## 📖 Design Details

- **Internal State**: 1024-bit (16 x 64-bit words)
- **Non-linear Function**: `f(x) = (¬x) ⊕ (x <<< R_A) ⊕ (x <<< R_B)` (bitwise NOT, XOR, and rotation)
- **Structure**: 4-dimensional Lai-Massey
- **Backends**: Supports both `soft` and `simd` backends, same as YSC2.

For more details, please refer to the [README.md](../README.md) file in the workspace root.