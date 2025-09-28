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
- `simd`: `portable_simd`를 사용하는 고성능 백엔드를 활성화합니다.
- `auxcrypt`: 보조 암호 스킴인 `auxcrypt`와의 통합 기능을 활성화합니다. (현재는 기능 정의만 되어 있음)

## 📖 상세 설계

YSC2의 핵심 설계, 순열 함수, 백엔드 구현에 대한 자세한 내용은 워크스페이스 루트의 [README.md](../README.md) 파일을 참고하십시오.