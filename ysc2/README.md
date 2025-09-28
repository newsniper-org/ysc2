# YSC2 스트림 암호

## 개요
YSC2는 FHE(완전 동형 암호) 환경 친화성을 목표로 설계된 고성능 스트림 암호입니다. 이 암호는 확장된 Lai-Massey 구조를 기반으로 하며, S-Box나 모듈러 덧셈 없이 AND, XOR, 순환 이동(Rotate) 연산만으로 비선형성을 구현하여 FHE 환경에서의 산술 복잡도를 최소화합니다.

이 문서는 YSC2 Rust 구현의 구조, 핵심 설계, 사용법을 설명합니다.

## 프로젝트 구조
YSC2 크레이트는 여러 모듈로 구성되어 있으며, 각 모듈은 명확한 역할을 담당합니다.
* `src/lib.rs`: 크레이트의 진입점으로, 보안 수준별 암호 타입(`Ysc2_512Cipher`, `Ysc2_1024Cipher`)을 정의하고 외부에 공개합니다.
* `src/stream.rs`: 스트림 암호 모드의 핵심 로직을 정의합니다.
    * `Ysc2Variant` 트레잇: 키/Nonce 크기, 라운드 수 등 보안 수준별 파라미터를 추상화합니다.
    * `Ysc2StreamCore` 구조체: 1024비트 내부 상태와 64비트 블록 카운터를 관리합니다.
* `src/consts.rs`: 라운드 상수, 회전 상수 등 암호 설계에 사용되는 모든 상수를 정의합니다.
* `src/backends/mod.rs`: 컴파일 시점에 `cfg-if` 매크로를 사용하여 스칼라(`soft`) 백엔드와 SIMD(`simd`) 백엔드 중 하나를 선택합니다.
* `src/backends/soft.rs`: 순수 Rust 코드로 작성된 스칼라 참조 구현입니다.
* `src/backends/simd.rs`: Rust의 Portable SIMD 기능을 사용하여 구현된 고성능 벡터화 버전입니다.

## 핵심 설계
### `Ysc2Variant` 트레잇
YSC2는 `Ysc2Variant` 트레잇을 통해 다양한 보안 수준을 지원합니다. 이 트레잇은 각 암호 버전이 구현해야 하는 상수(키/Nonce 크기, 라운드 수)와 관련 타입을 정의하여, 코드 재사용성을 높이고 새로운 버전을 쉽게 추가할 수 있도록 합니다.

```rust
pub trait Ysc2Variant: Sized + Clone {
    type KeySize: cipher::generic_array::ArrayLength<u8>;
    const KEY_SIZE: usize;
    type NonceSize: cipher::generic_array::ArrayLength<u8>;
    const NONCE_SIZE: usize;
    const ROUNDS: usize;
}
```

### Ysc2StreamCore 구조체와 초기화
`Ysc2StreamCore`는 암호의 핵심 상태(`state`)와 현재 블록 위치를 나타내는 `counter`를 가집니다. `KeyIvInit` 트레잇의 `new` 함수를 통해 초기화됩니다.
    1. **상태 로드**: 1024비트(16 x 64비트) 상태 배열을 생성하고, 주어진 키와 Nonce를 명세에 따라 로드합니다.
    2. **초기 순열**: 로드된 상태에 대해 순열 함수(`permutation`)를 한 번 적용하여 키와 Nonce를 충분히 혼합합니다. 이 과정을 통해 초기 상태의 예측 불가능성을 확보합니다.
<img src="assets/figure1.svg" />

### 키스트림 생성
YSC2는 CTR(카운터) 모드와 유사한 방식으로 키스트림을 생성합니다.
1. `counter`를 1 증가시킵니다.
2. `state`의 복사본(`working_state`)을 만들고, 첫 번째 워드에 `counter` 값을 XOR합니다.
3. `working_state`에 순열 함수를 적용합니다.
4. 순열이 적용된 `working_state`를 128바이트(1024비트) 키스트림 블록으로 변환하여 출력합니다.

이 방식은 `state` 자체는 변경하지 않고 매번 카운터 값만 다르게 적용하여 키스트림을 생성하므로, 특정 블록 위치로의 `seek` 연산이 효율적입니다.
<img src="assets/figure2.svg"/>

## 순열 함수 (permutation)
순열 함수는 YSC2의 보안성을 책임지는 핵심 요소이며, 세 단계로 구성됩니다.
<img src="assets/figure3.svg"/>

1. **라운드 상수 덧셈 (AddRoundConstant)**: `state[0]`에 라운드별 상수를 XOR하여 라운드 간 대칭성을 파괴합니다.
2. **비선형 계층 (Non-linear Layer)**: 확장된 Lai-Massey 구조를 적용합니다.
    * 상태의 왼쪽 절반(8개 워드) 각각에 비선형 함수 `g(x)`를 적용합니다.
    * 그 결과를 오른쪽 절반(8개 워드)에 XOR합니다. (`R' = R ^ g(L)`)
    * 변경된 오른쪽 절반을 다시 왼쪽 절반에 XOR합니다. (`L' = L ^ R'`)
3. **선형 계층 (Linear Layer)**: 16개의 상태 워드를 미리 정의된 순서(`P`)에 따라 재배치하여 상태 내 비트들의 확산을 돕습니다.

이 과정이 `Ysc2Variant`에 정의된 `ROUNDS` 수만큼 반복됩니다.

## 백엔드 구현
YSC2는 컴파일 시점에 최적의 실행 백엔드를 선택하여 성능을 극대화합니다.

* **`soft` 백엔드**: 모든 플랫폼에서 동작하는 표준 스칼라 구현입니다.
* **`simd` 백엔드**: `ysc2_simd` 기능 플래그가 활성화되면 컴파일됩니다. `u64x4` 타입을 사용하여 4개의 64비트 워드를 동시에 처리하므로, 스칼라 구현보다 훨씬 높은 성능을 제공합니다.

## 사용법
`cipher` 크레이트의 표준 인터페이스를 따르므로 사용법이 간단합니다.

### 기본 암호화/복호화
```rust
use ysc2::{Ysc2_512StreamCipher, cipher::{KeyIvInit, StreamCipher}};

// 512비트(64바이트) 키와 Nonce 준비
let key = [0x42; 64].into();
let nonce = [0x24; 64].into();

let mut buffer = [1, 2, 3, 4, 5];

// 암호화
let mut cipher = Ysc2_512StreamCipher::new(&key, &nonce);
cipher.apply_keystream(&mut buffer);

// 복호화 (동일한 키와 Nonce 사용)
let mut cipher = Ysc2_512StreamCipher::new(&key, &nonce);
cipher.apply_keystream(&mut buffer);

assert_eq!(buffer, [1, 2, 3, 4, 5]);
```

### 빌드 방법
* **표준 빌드 (스칼라)**:
    ```bash
    cargo build --release
    ```
* **SIMD 최적화 빌드**:
    ```bash
    RUSTFLAGS='--cfg feature="ysc2_simd"' cargo +nightly build --release --features ysc2_simd
    ```
    __주의: SIMD 백엔드는 Nightly 툴체인과 `portable_simd` 기능 활성화가 필요합니다.__


## 라이선스
BSD-2-Clause 라이선스 하에 배포됩니다.