//======================================================================
// auxcrypt/src/backends/simd.rs
// Portable SIMD implementation of the AuxCrypt permutation.
//======================================================================

use crate::consts::*;
use crate::stream::AuxCryptCore;
use crate::variant::AuxCryptVariant;
use cipher::{Block, BlockSizeUser, ParBlocksSizeUser, StreamBackend};
use std::simd::*;

/// The portable SIMD backend for AuxCrypt.
pub struct Backend<'a, V: AuxCryptVariant>(pub(crate) &'a mut AuxCryptCore<V>);

impl<'a, V: AuxCryptVariant> BlockSizeUser for Backend<'a, V> {
    type BlockSize = cipher::consts::U128;
}

impl<'a, V: AuxCryptVariant> ParBlocksSizeUser for Backend<'a, V> {
    type ParBlocksSize = cipher::consts::U128;
}

impl<'a, V: AuxCryptVariant> StreamBackend for Backend<'a, V> {
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

/// The vectorized non-linear function f(x).
#[inline(always)]
fn f_vec(x: u64x4) -> u64x4 {
    let rot_a = x.rotate_elements_left::<{ ROT_A as usize }>();
    let rot_b = x.rotate_elements_left::<{ ROT_B as usize }>();
    (!x) ^ rot_a ^ rot_b
}

/// A single vectorized Lai-Massey round on two vectors.
#[inline(always)]
fn lai_massey_round_vec(a: &mut u64x4, b: &mut u64x4) {
    let diff = f_vec(*a ^ *b);
    *a ^= diff;
    *b ^= diff;
}

/// The core state permutation function for AuxCrypt (SIMD version).
#[inline(always)]
pub(crate) fn permutation<V: AuxCryptVariant>(state: &mut [u64; STATE_WORDS]) {
    // Load state into SIMD vectors
    let mut s0 = u64x4::from_slice(&state[0..4]);
    let mut s1 = u64x4::from_slice(&state[4..8]);
    let mut s2 = u64x4::from_slice(&state[8..12]);
    let mut s3 = u64x4::from_slice(&state[12..16]);

    for r in 0..V::ROUNDS {
        // 1. Add Round Constant
        s0[0] ^= RC[r];

        // 2. Non-linear Layer (4D Lai-Massey)
        // This is a simplified SIMD implementation focusing on vector-width operations.
        // A more complex implementation could use shuffles for perfect dimensional mapping.
        lai_massey_round_vec(&mut s0, &mut s1);
        lai_massey_round_vec(&mut s2, &mut s3);
        lai_massey_round_vec(&mut s0, &mut s2);
        lai_massey_round_vec(&mut s1, &mut s3);

        // 3. Linear Layer (Word Permutation)
        let mut temp_state = [0u64; STATE_WORDS];
        s0.copy_to_slice(&mut temp_state[0..4]);
        s1.copy_to_slice(&mut temp_state[4..8]);
        s2.copy_to_slice(&mut temp_state[8..12]);
        s3.copy_to_slice(&mut temp_state[12..16]);
        
        let mut new_state_array = [0u64; STATE_WORDS];
        for i in 0..STATE_WORDS {
            new_state_array[i] = temp_state[P[i]];
        }

        s0 = u64x4::from_slice(&new_state_array[0..4]);
        s1 = u64x4::from_slice(&new_state_array[4..8]);
        s2 = u64x4::from_slice(&new_state_array[8..12]);
        s3 = u64x4::from_slice(&new_state_array[12..16]);
    }

    // Store SIMD vectors back to state
    s0.copy_to_slice(&mut state[0..4]);
    s1.copy_to_slice(&mut state[4..8]);
    s2.copy_to_slice(&mut state[8..12]);
    s3.copy_to_slice(&mut state[12..16]);
}