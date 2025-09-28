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
- `simd`: Enables the high-performance backend using `portable_simd`.
- `auxcrypt`: Enables integration with the `auxcrypt` auxiliary cipher. (Currently, this is a placeholder for future integration)

## 📖 Design Details

For detailed information on the core design, permutation function, and backend implementations of YSC2, please refer to the [README.md](../README.md) file in the workspace root.