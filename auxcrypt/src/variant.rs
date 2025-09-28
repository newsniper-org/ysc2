//======================================================================
// auxcrypt/src/variant.rs
// Defines security parameter variants for AuxCrypt.
//======================================================================

use cipher::consts::{U128, U64};

/// A trait that defines the parameters for a specific AuxCrypt variant.
pub trait AuxCryptVariant: Sized + Clone + Send + Sync + 'static {
    /// Key size in bytes.
    type KeySize: cipher::ArrayLength<u8>;
    const KEY_SIZE: usize;

    /// Nonce size in bytes.
    type NonceSize: cipher::ArrayLength<u8>;
    const NONCE_SIZE: usize;

    /// Number of permutation rounds.
    const ROUNDS: usize;
}

/// AuxCrypt variant with a 512-bit key.
#[derive(Clone)]
pub struct AuxCrypt512;
impl AuxCryptVariant for AuxCrypt512 {
    type KeySize = U64;
    const KEY_SIZE: usize = 64;
    type NonceSize = U64;
    const NONCE_SIZE: usize = 64;
    const ROUNDS: usize = 14;
}

/// AuxCrypt variant with a 1024-bit key.
#[derive(Clone)]
pub struct AuxCrypt1024;
impl AuxCryptVariant for AuxCrypt1024 {
    type KeySize = U128;
    const KEY_SIZE: usize = 128;
    type NonceSize = U64;
    const NONCE_SIZE: usize = 64;
    const ROUNDS: usize = 20;
}