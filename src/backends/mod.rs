use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(feature = "ysc2_simd")] {
        pub(crate) mod simd;
    } else {
        pub(crate) mod soft;
    }
}