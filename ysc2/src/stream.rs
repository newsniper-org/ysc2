//======================================================================
// src/stream.rs
// YSC2 순열의 핵심 로직을 추상화하는 트레잇 정의
//======================================================================

use cipher::{
    BlockSizeUser, Iv, IvSizeUser, Key, KeyIvInit, KeySizeUser, StreamCipherCore, StreamCipherSeekCore
};
use core::marker::PhantomData;
use crate::backends;

use crate::variant::Ysc2Variant;


pub struct Ysc2StreamCore<V: Ysc2Variant> {
    /// The 1024-bit internal state (16 x 64-bit words).
    pub(crate) state: [u64; 16],
    /// The 64-bit block counter.
    pub(crate) counter: u64,
    /// PhantomData to associate the core with a specific `Ysc2Variant`.
    pub(crate) _variant: PhantomData<V>,
}

impl<V: Ysc2Variant> KeySizeUser for Ysc2StreamCore<V> {
    type KeySize = V::KeySize;
}

impl<V: Ysc2Variant> IvSizeUser for Ysc2StreamCore<V> {
    type IvSize = V::NonceSize;
}

impl<V: Ysc2Variant> BlockSizeUser for Ysc2StreamCore<V> {
    type BlockSize = cipher::consts::U128; // 1024-bit blocks
}

impl<V: Ysc2Variant> KeyIvInit for Ysc2StreamCore<V> {
    /// Creates a new `Ysc2StreamCore` instance, initializing its state with the
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
        backends::permutation::<V>(&mut state);
        Self {
            state,
            counter: 0,
            _variant: PhantomData,
        }
    }
}

impl<V: Ysc2Variant> StreamCipherCore for Ysc2StreamCore<V> {
    fn remaining_blocks(&self) -> Option<usize> {
        None
    }
    
    /// Processes data by applying the keystream, delegating the core permutation
    /// to the backend selected at compile time.
    fn process_with_backend(&mut self, f: impl cipher::StreamClosure<BlockSize = Self::BlockSize>) {
        f.call(&mut backends::Backend(self));
    }
}

impl<V: Ysc2Variant> StreamCipherSeekCore for Ysc2StreamCore<V> {
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