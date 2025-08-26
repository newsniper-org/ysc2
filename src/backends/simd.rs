
use crate::{arx, core::Ysc2Core, Ysc2Variant};
use cipher::{Block, BlockSizeUser, ParBlocksSizeUser, StreamBackend};
use core::simd::prelude::*;

/// 비선형 함수 g(x)의 벡터 버전
#[inline(always)]
fn g_vec(x: Simd<u64, 4>) -> Simd<u64, 4> {
    // 각 u64 레인에 대해 비트 단위 회전을 수행합니다.
    let rot_a = (x << Simd::splat(ROT_A as u64)) | (x >> Simd::splat(64 - ROT_A));
    let rot_b = (x << Simd::splat(ROT_B as u64)) | (x >> Simd::splat(64 - ROT_B));
    x ^ (rot_a & rot_b)
}

/// The portable SIMD backend for YSC2.
pub struct Backend<'a, V: Ysc2Variant>(pub(crate) &'a mut Ysc2Core<V>);

impl<'a, V: Ysc2Variant> BlockSizeUser for Backend<'a, V> {
    type BlockSize = cipher::consts::U128;
}

// Re-add ParBlocksSizeUser for compatibility with cipher v0.4.4
impl<'a, V: Ysc2Variant> ParBlocksSizeUser for Backend<'a, V> {
    type ParBlocksSize = cipher::consts::U128;
}

impl<'a, V: Ysc2Variant> StreamBackend for Backend<'a, V> {
    #[inline]
    fn gen_ks_block(&mut self, block: &mut Block<Self>) {
        self.0.counter = self.0.counter.wrapping_add(1);

        let mut working_state = self.0.state;
        working_state[0] ^= self.0.counter;

        permutation::<V>(&mut working_state);

        for (i, chunk) in output.chunks_exact_mut(8).enumerate() {
            chunk.copy_from_slice(&self.0.state[i].to_le_bytes());
        }
    }
}

/// The state permutation function using portable SIMD.
#[inline(always)]
fn permutation_simd(state: &mut [u64; 16]) {
    // 상태를 u64x4 벡터 4개로 변환
    let mut s: [Simd<u64, 4>; 4] = [
        Simd::from_slice(&state[0..4]),
        Simd::from_slice(&state[4..8]),
        Simd::from_slice(&state[8..12]),
        Simd::from_slice(&state[12..16]),
    ];

    for r in 0..ROUNDS {
        // 1. 라운드 상수 더하기
        s[0][0] ^= RC[r];

        // 2. 비선형 계층
        let temp0 = g_vec(s[0]);
        let temp1 = g_vec(s[1]);
        s[2] ^= temp0; // R' = R ^ g(L)
        s[3] ^= temp1;
        s[0] ^= s[2]; // L' = L ^ R'
        s[1] ^= s[3];

        // 3. 선형 계층
        let mut temp_state = [0u64; 16];
        s[0].write_to_slice(&mut temp_state[0..4]);
        s[1].write_to_slice(&mut temp_state[4..8]);
        s[2].write_to_slice(&mut temp_state[8..12]);
        s[3].write_to_slice(&mut temp_state[12..16]);
        
        let mut new_state_array = [0u64; 16];
        for i in 0..16 {
            new_state_array[i] = temp_state[P[i]];
        }

        s[0] = Simd::from_slice(&new_state_array[0..4]);
        s[1] = Simd::from_slice(&new_state_array[4..8]);
        s[2] = Simd::from_slice(&new_state_array[8..12]);
        s[3] = Simd::from_slice(&new_state_array[12..16]);
    }

    // 최종 상태를 다시 원래 배열에 저장
    s[0].write_to_slice(&mut state[0..4]);
    s[1].write_to_slice(&mut state[4..8]);
    s[2].write_to_slice(&mut state[8..12]);
    s[3].write_to_slice(&mut state[12..16]);
}
