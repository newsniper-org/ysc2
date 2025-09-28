// --- Security Parameter Abstraction ---
/// YSC2 순열을 위한 핵심 트레잇입니다.
/// 보안 수준별로 다른 파라미터(라운드 수, 키/Nonce 크기)를 정의합니다.
pub trait Ysc2Variant : Sized + Clone {
    /// Key size type and const.
    type KeySize: cipher::ArrayLength<u8>;
    const KEY_SIZE: usize;
    /// Nonce size type and const.
    type NonceSize: cipher::ArrayLength<u8>;
    const NONCE_SIZE: usize;
    
    const ROUNDS: usize;

    const KEYED_DOMAIN: &'static str;

    const AEAD_DOMAIN: &'static str;

    const AEAD_NONCE_DOMAIN: &'static str = "NONCE";
    const AEAD_AD_DOMAIN: &'static str = "AD";
    const AEAD_CT_DOMAIN: &'static str = "CT";
}


/// YSC2 variant with a 512-bit key and 512-bit nonce.
#[derive(Clone)]
pub struct Ysc2_512;
impl Ysc2Variant for Ysc2_512 {
    type KeySize = cipher::consts::U64;
    type NonceSize = cipher::consts::U64;
    const ROUNDS: usize = 12;
    
    const KEY_SIZE: usize = 64;
    
    const NONCE_SIZE: usize = 64;

    const KEYED_DOMAIN: &'static str = "YSC2-X-MAC-512";
    const AEAD_DOMAIN: &'static str = "YSC2-512-AEAD-V1";
}

/// YSC2 variant with a 1024-bit key and 512-bit nonce.
#[derive(Clone)]
pub struct Ysc2_1024;
impl Ysc2Variant for Ysc2_1024 {
    type KeySize = cipher::consts::U128;
    type NonceSize = cipher::consts::U64;
    const ROUNDS: usize = 12;
    
    const KEY_SIZE: usize = 128;
    
    const NONCE_SIZE: usize = 64;
    const KEYED_DOMAIN: &'static str = "YSC2-X-MAC-1024";
    const AEAD_DOMAIN: &'static str = "YSC2-1024-AEAD-V1";
}