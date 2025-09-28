//======================================================================
// auxcrypt/src/lib.rs
// Crate entry point for the AuxCrypt auxiliary scheme.
//======================================================================

#![cfg_attr(docsrs, feature(doc_cfg))]


#![cfg(feature = "auxcrypt_simd")]
#![feature(portable_simd)]

// --- Module Declarations ---

mod backends;
mod consts;
pub mod variant;
pub mod stream;

// --- Test Module ---
#[cfg(test)]
mod tests;

// --- Re-exports ---

pub use cipher;

// --- Top-level Type Aliases ---

use variant::{AuxCrypt512, AuxCrypt1024};

/// AuxCrypt stream cipher with a 512-bit security level.
pub type AuxCrypt512Stream = stream::AuxCryptStream<AuxCrypt512>;

/// AuxCrypt stream cipher with a 1024-bit security level.
pub type AuxCrypt1024Stream = stream::AuxCryptStream<AuxCrypt1024>;