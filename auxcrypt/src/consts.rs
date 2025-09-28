//======================================================================
// auxcrypt/src/consts.rs
// Defines constants used in the AuxCrypt permutation.
//======================================================================

/// Number of 64-bit words in the state.
pub const STATE_WORDS: usize = 16;

/// Rotation constants for the non-linear function `f`.
pub const ROT_A: u32 = 19;
pub const ROT_B: u32 = 41;

/// Round constants (RC) - simple iota values.
pub const RC: [u64; 20] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
];

/// Permutation table for the linear layer.
pub const P: [usize; 16] = [
    0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11,
];