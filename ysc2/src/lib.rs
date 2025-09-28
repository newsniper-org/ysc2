#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]

//======================================================================
// src/lib.rs
// 크레이트의 진입점. 공개 API를 선언하고 모듈을 구성합니다.
//======================================================================


// --- Module declarations ---
pub mod stream;
use crate::stream::Ysc2StreamCore;

#[cfg(feature = "ysc2x")]
pub mod sponge;

pub mod variant;
use crate::variant::{Ysc2_1024, Ysc2_512};

pub mod consts;
mod backends;

#[cfg(feature = "ysc2x")]
pub mod aead;

// --- Convenience Type Aliases for Users ---
pub type Ysc2_512StreamCipher = cipher::StreamCipherCoreWrapper<Ysc2StreamCore<Ysc2_512>>;
pub type Ysc2_1024StreamCipher = cipher::StreamCipherCoreWrapper<Ysc2StreamCore<Ysc2_1024>>;

// --- Test Module ---
#[cfg(test)]
mod tests;

pub use cipher;
pub use digest;
pub use aead as aead_api;

// -- Sponge Function Aliases (YSC2-X) --
#[cfg(feature = "ysc2x")]
pub type Ysc2_512Hasher = sponge::Hasher<Ysc2_512>;
#[cfg(feature = "ysc2x")]
pub type Ysc2_1024Hasher = sponge::Hasher<Ysc2_1024>;
#[cfg(feature = "ysc2x")]
pub type Ysc2_512Hash = sponge::Hash<Ysc2_512>;
#[cfg(feature = "ysc2x")]
pub type Ysc2_1024Hash = sponge::Hash<Ysc2_1024>;
#[cfg(feature = "ysc2x")]
pub type Ysc2_512Mac = sponge::Mac<Ysc2_512>;
#[cfg(feature = "ysc2x")]
pub type Ysc2_1024Mac = sponge::Mac<Ysc2_1024>;
#[cfg(feature = "ysc2x")]
pub type Ysc2_512XofReader = sponge::Reader<Ysc2_512>;
#[cfg(feature = "ysc2x")]
pub type Ysc2_1024XofReader = sponge::Reader<Ysc2_1024>;

// -- AEAD Aliases --
#[cfg(feature = "ysc2x")]
pub type Ysc2_512Aead = aead::Ysc2Aead<Ysc2_512>;
#[cfg(feature = "ysc2x")]
pub type Ysc2_1024Aead = aead::Ysc2Aead<Ysc2_1024>;