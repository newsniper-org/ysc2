//======================================================================
// src/core.rs
// YSC2 순열의 핵심 로직을 추상화하는 트레잇 정의
//======================================================================

use cfg_if::cfg_if;
use cipher::{
    BlockSizeUser, Iv, IvSizeUser, Key, KeyIvInit, KeySizeUser, StreamCipherCore, StreamCipherSeekCore
};
use core::marker::PhantomData;
use crate::backends;


/// YSC2 순열을 위한 핵심 트레잇입니다.
/// 보안 수준별로 다른 파라미터(라운드 수, 키/Nonce 크기)를 정의합니다.
pub trait Ysc2Variant : Sized {
    /// Key size type and const.
    type KeySize: cipher::ArrayLength<u8>;
    const KEY_SIZE: usize;
    /// Nonce size type and const.
    type NonceSize: cipher::ArrayLength<u8>;
    const NONCE_SIZE: usize;
    
    const ROUNDS: usize;
}

pub struct Ysc2Core<V: Ysc2Variant> {
    /// The 1024-bit internal state (16 x 64-bit words).
    pub(crate) state: [u64; 16],
    /// The 64-bit block counter.
    pub(crate) counter: u64,
    /// PhantomData to associate the core with a specific `Ysc2Variant`.
    pub(crate) _variant: PhantomData<V>,
}

impl<V: Ysc2Variant> KeySizeUser for Ysc2Core<V> {
    type KeySize = V::KeySize;
}

impl<V: Ysc2Variant> IvSizeUser for Ysc2Core<V> {
    type IvSize = V::NonceSize;
}

impl<V: Ysc2Variant> BlockSizeUser for Ysc2Core<V> {
    type BlockSize = cipher::consts::U128; // 1024-bit blocks
}

impl<V: Ysc2Variant> KeyIvInit for Ysc2Core<V> {
    /// Creates a new `Ysc2Core` instance, initializing its state with the
    /// given key and nonce according to the specification.
    fn new(key: &Key<Self>, iv: &Iv<Self>) -> Self {
        let mut state = [0u64; 16];
        
        // 키와 Nonce를 초기 상태에 로드합니다.
        if V::KEY_SIZE == 128 { // 1024비트 키
            for (i, chunk) in key.chunks_exact(8).enumerate() {
                state[i] = u64::from_le_bytes(chunk.try_into().unwrap());
            }
            for (i, chunk) in iv.chunks_exact(8).enumerate() {
                // Nonce는 상태의 후반부와 XOR합니다.
                state[i + 8] ^= u64::from_le_bytes(chunk.try_into().unwrap());
            }
        } else { // 512비트 키
            for (i, chunk) in key.chunks_exact(8).enumerate() {
                state[i] = u64::from_le_bytes(chunk.try_into().unwrap());
            }
            for (i, chunk) in iv.chunks_exact(8).enumerate() {
                state[i + 8] = u64::from_le_bytes(chunk.try_into().unwrap());
            }
        }

        // 2. Run the permutation for INIT_ROUNDS.
        cfg_if! {
            if #[cfg(feature = "ysc2_simd")] {
                backends::simd::permutation::<V>(&mut state);
            } else {
                backends::soft::permutation::<V>(&mut state);
            }
        }
        Self {
            state,
            counter: 0,
            _variant: PhantomData,
        }
    }
}

impl<V: Ysc2Variant> StreamCipherCore for Ysc2Core<V> {
    fn remaining_blocks(&self) -> Option<usize> {
        None
    }
    
    /// Processes data by applying the keystream, delegating the core permutation
    /// to the backend selected at compile time.
    fn process_with_backend(&mut self, f: impl cipher::StreamClosure<BlockSize = Self::BlockSize>) {
        cfg_if::cfg_if! {
            if #[cfg(feature = "ysc2_simd")] {
                f.call(&mut backends::simd::Backend(self));
            } else {
                f.call(&mut backends::soft::Backend(self));
            }
        }
    }
}

impl<V: Ysc2Variant> StreamCipherSeekCore for Ysc2Core<V> {
    type Counter = u64;

    /// Gets the current block position (counter).
    fn get_block_pos(&self) -> Self::Counter {
        self.counter
    }

    /// Sets the block position (counter).
    fn set_block_pos(&mut self, pos: Self::Counter) {
        self.counter = pos;
    }
}