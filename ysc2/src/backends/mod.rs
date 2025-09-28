use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(feature = "ysc2_simd")] {
        mod simd;
        pub(crate) use simd::*;
    } else {
        mod soft;
        pub(crate) use soft::*;
    }
}