use crate::{stream::Ysc2StreamCore};
use crate::variant::Ysc2Variant;
use crate::consts::*;
use cipher::{Block, BlockSizeUser, ParBlocksSizeUser, StreamBackend};

/// The software (scalar) backend for YSC2.
pub struct Backend<'a, V: Ysc2Variant>(pub(crate) &'a mut Ysc2StreamCore<V>);

impl<'a, V: Ysc2Variant> BlockSizeUser for Backend<'a, V> {
    type BlockSize = cipher::consts::U128;
}

// Re-add ParBlocksSizeUser for compatibility with cipher v0.4.4
impl<'a, V: Ysc2Variant> ParBlocksSizeUser for Backend<'a, V> {
    type ParBlocksSize = cipher::consts::U128;
}

impl<'a, V: Ysc2Variant> StreamBackend for Backend<'a, V> {
    #[inline]
    fn gen_ks_block(&mut self, output: &mut Block<Self>) {
        self.0.counter = self.0.counter.wrapping_add(1);

        let mut working_state = self.0.state;
        working_state[0] ^= self.0.counter;

        permutation::<V>(&mut working_state);

        for (i, chunk) in output.chunks_exact_mut(8).enumerate() {
            chunk.copy_from_slice(&working_state[i].to_le_bytes());
        }
    }
}



/// 비선형 함수 g(x) = x ^ ((x <<< A) & (x <<< B))
#[inline(always)]
fn g(x: u64) -> u64 {
    x ^ (x.rotate_left(ROT_A) & x.rotate_left(ROT_B))
}

/// The state permutation function based on the (2x2) Lai-Massey structure.
#[inline(always)]
pub(crate) fn permutation<V: Ysc2Variant>(state: &mut [u64; 16]) {
    for r in 0..V::ROUNDS {
        // 1. 라운드 상수 더하기 (AddRoundConstant)
        state[0] ^= RC[r];

        // 2. 비선형 계층 (Non-linear Layer) - Lai-Massey 유사 구조
        let mut temp = [0u64; 8];
        for i in 0..8 {
            temp[i] = g(state[i]);
        }
        for i in 0..8 {
            state[i + 8] ^= temp[i]; // R' = R ^ g(L)
        }
        for i in 0..8 {
            state[i] ^= state[i + 8]; // L' = L ^ R'
        }

        // 3. 선형 계층 (Linear Layer) - 워드 단위 순열
        let mut new_state = [0u64; 16];
        for i in 0..16 {
            new_state[i] = state[P[i]];
        }
        *state = new_state;
    }
}