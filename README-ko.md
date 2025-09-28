# YSC2 암호화 스위트

[![Crates.io](https://img.shields.io/crates/v/ysc2?style=for-the-badge)](https://crates.io/crates/ysc2)
[![Docs.rs](https://img.shields.io/docsrs/ysc2?style=for-the-badge)](https://docs.rs/ysc2)

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
  - `src/sponge.rs`: 해시, MAC, XOF를 위한 스펀지(Sponge) 구조 (YSC2X)
  - `src/aead.rs`: 인증 암호(AEAD) 모드 (YSC2X)
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
let mut buffer = vec![1, 2, 3, 4, 5];

// 암호화
let mut cipher = Ysc2_512StreamCipher::new(&key, &nonce);
cipher.apply_keystream(&mut buffer);

// 복호화
let mut cipher = Ysc2_512StreamCipher::new(&key, &nonce);
cipher.apply_keystream(&mut buffer);

assert_eq!(buffer, &[1, 2, 3, 4, 5]);
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
use ysc2::digest::{ExtendableOutput, Update, XofReader};

let mut hasher = Ysc2_512Hasher::default();
hasher.update(b"important data");

let mut output = vec![0u8; 100]; // 100바이트 길이의 출력 요청
let mut xof_reader = hasher.finalize_xof();
xof_reader.read(&mut output);

// println!("100바이트 XOF 출력: {:x}", output);
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
use ysc2::aead_api::{Aead, AeadInPlace, KeyInit};
use ysc2::aead_api::generic_array::GenericArray;
// 테스트 및 재현 가능한 키 생성을 위해 PRNG를 사용합니다.
use rand_core::SeedableRng;
use rand_chacha::ChaCha8Rng;


let mut rng = ChaCha8Rng::from_seed([42; 32]);
let key = Ysc2_512Aead::generate_key(&mut rng);
let cipher = Ysc2_512Aead::new(&key);
let nonce = GenericArray::from([0u8; 64]); // 64바이트 Nonce
let mut buffer = b"plaintext message".to_vec();

// 암호화 (in-place)
let tag = cipher.encrypt_in_place_detached(&nonce, b"associated data", &mut buffer)
    .expect("AEAD 암호화 실패");

// 복호화 (in-place)
cipher.decrypt_in_place_detached(&nonce, b"associated data", &mut buffer, &tag)
    .expect("AEAD 복호화 실패");

assert_eq!(&buffer, b"plaintext message");
```

## 📜 라이선스

이 프로젝트는 BSD-2-Clause 라이선스 하에 배포됩니다. 자세한 내용은 `LICENSE` 파일을 참고하세요.