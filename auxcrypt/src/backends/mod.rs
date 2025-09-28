//======================================================================
// auxcrypt/src/backends/mod.rs
// Selects the appropriate permutation backend at compile time.
//======================================================================

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(feature = "auxcrypt_simd")] {
        pub(crate) mod simd;
        pub(crate) use self::simd::permutation;
    } else {
        pub(crate) mod soft;
        pub(crate) use self::soft::permutation;
    }
}