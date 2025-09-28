//======================================================================
// auxcrypt/src/backends/soft.rs
// Software (scalar) implementation of the AuxCrypt permutation.
//======================================================================

use crate::consts::*;
use crate::stream::AuxCryptCore;
use crate::variant::AuxCryptVariant;
use cipher::{Block, BlockSizeUser, ParBlocksSizeUser, StreamBackend};

/// The software (scalar) backend for AuxCrypt.
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

/// The non-linear function f(x) = (¬x) ⊕ (x <<< R_A) ⊕ (x <<< R_B).
#[inline(always)]
fn f(x: u64) -> u64 {
    (!x) ^ x.rotate_left(ROT_A) ^ x.rotate_left(ROT_B)
}

/// A single Lai-Massey round on a pair of words.
#[inline(always)]
fn lai_massey_round(state: &mut [u64; STATE_WORDS], aidx: usize, bidx: usize) {
    let diff = f(state[aidx] ^ state[bidx]);
    state[aidx] ^= diff;
    state[bidx] ^= diff;
}

/// The core state permutation function for AuxCrypt.
#[inline(always)]
pub(crate) fn permutation<V: AuxCryptVariant>(state: &mut [u64; STATE_WORDS]) {
    for r in 0..V::ROUNDS {
        // 1. Add Round Constant
        state[0] ^= RC[r];

        // 2. Non-linear Layer (4D Lai-Massey)
        // Apply rounds across 4 dimensions of the 2x2x2x2 state hypercube.
        for i in 0..8 { lai_massey_round(state, 2 * i, 2 * i + 1); } // Dim 1 (X)
        for i in 0..4 {
            lai_massey_round(state, 4 * i, 4 * i + 2); // Dim 2 (Y)
            lai_massey_round(state, 4 * i + 1, 4 * i + 3);
        }
        for i in 0..2 {
            for j in 0..4 { lai_massey_round(state, 8 * i + j, 8 * i + j + 4); } // Dim 3 (Z)
        }
        for i in 0..8 { lai_massey_round(state, i, i + 8); } // Dim 4 (W)

        // 3. Linear Layer (Word Permutation)
        let mut new_state = [0u64; STATE_WORDS];
        for i in 0..STATE_WORDS {
            new_state[i] = state[P[i]];
        }
        *state = new_state;
    }
}