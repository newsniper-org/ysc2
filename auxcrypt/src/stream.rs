//======================================================================
// auxcrypt/src/stream.rs
// Implements the stream cipher mode of operation for AuxCrypt.
//======================================================================

use crate::backends;
use crate::consts::STATE_WORDS;
use crate::variant::AuxCryptVariant;
use cipher::{
    consts::U128, BlockSizeUser, Iv, IvSizeUser, Key, KeyIvInit, KeySizeUser,
    StreamCipherCore, StreamCipherCoreWrapper, StreamCipherSeekCore,
};
use core::marker::PhantomData;

/// The core engine for the AuxCrypt stream cipher.
pub struct AuxCryptCore<V: AuxCryptVariant> {
    /// The 1024-bit internal state (16 x 64-bit words).
    pub(crate) state: [u64; STATE_WORDS],
    /// The 64-bit block counter.
    pub(crate) counter: u64,
    /// PhantomData to associate the core with a specific `AuxCryptVariant`.
    _variant: PhantomData<V>,
}

impl<V: AuxCryptVariant> KeySizeUser for AuxCryptCore<V> {
    type KeySize = V::KeySize;
}

impl<V: AuxCryptVariant> IvSizeUser for AuxCryptCore<V> {
    type IvSize = V::NonceSize;
}

impl<V: AuxCryptVariant> BlockSizeUser for AuxCryptCore<V> {
    type BlockSize = U128; // 1024-bit (128-byte) blocks
}

impl<V: AuxCryptVariant> KeyIvInit for AuxCryptCore<V> {
    fn new(key: &Key<Self>, iv: &Iv<Self>) -> Self {
        let mut state = [0u64; STATE_WORDS];
        
        // Load key into the first part of the state.
        for (i, chunk) in key.chunks_exact(8).enumerate() {
            state[i] = u64::from_le_bytes(chunk.try_into().unwrap());
        }
        
        // Load IV into the second part of the state.
        let offset = V::KEY_SIZE / 8;
        for (i, chunk) in iv.chunks_exact(8).enumerate() {
            state[offset + i] = u64::from_le_bytes(chunk.try_into().unwrap());
        }

        // Run an initial permutation to mix key and IV.
        backends::permutation::<V>(&mut state);
        
        Self {
            state,
            counter: 0,
            _variant: PhantomData,
        }
    }
}

impl<V: AuxCryptVariant> StreamCipherCore for AuxCryptCore<V> {
    fn remaining_blocks(&self) -> Option<usize> { None }

    fn process_with_backend(&mut self, f: impl cipher::StreamClosure<BlockSize = Self::BlockSize>) {
        cfg_if::cfg_if! {
            if #[cfg(feature = "auxcrypt_simd")] {
                f.call(&mut backends::simd::Backend(self));
            } else {
                f.call(&mut backends::soft::Backend(self));
            }
        }
    }
}

impl<V: AuxCryptVariant> StreamCipherSeekCore for AuxCryptCore<V> {
    type Counter = u64;
    fn get_block_pos(&self) -> Self::Counter { self.counter }
    fn set_block_pos(&mut self, pos: Self::Counter) { self.counter = pos; }
}

/// The high-level stream cipher type for AuxCrypt.
pub type AuxCryptStream<V> = StreamCipherCoreWrapper<AuxCryptCore<V>>;