//======================================================================
// src/lib.rs
// 크레이트의 진입점. 공개 API를 선언하고 모듈을 구성합니다.
//======================================================================
#![no_std]
pub use cipher; // Re-export cipher crate for downstream users


// --- Module declarations ---
mod core;
use crate::core::{Ysc2Core, Ysc2Variant};

mod consts;
mod backends;


// --- Security Parameter Abstraction ---



/// YSC2 variant with a 512-bit key and 512-bit nonce.
#[derive(Clone)]
pub struct Ysc2_512;
impl Ysc2Variant for Ysc2_512 {
    type KeySize = cipher::consts::U64;
    type NonceSize = cipher::consts::U64;
    const ROUNDS: usize = 12;
    
    const KEY_SIZE: usize = 64;
    
    const NONCE_SIZE: usize = 64;
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
}

// --- Convenience Type Aliases for Users ---
pub type Ysc2_512Cipher = cipher::StreamCipherCoreWrapper<Ysc2Core<Ysc2_512>>;
pub type Ysc2_1024Cipher = cipher::StreamCipherCoreWrapper<Ysc2Core<Ysc2_1024>>;

// --- Tests ---
#[cfg(test)]
mod tests {
    use super::{Ysc2_1024Cipher, Ysc2_512Cipher};
    use cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};

    const PLAINTEXT: &[u8] = b"This is a test message for the YSC2 stream cipher implementation.";

    #[test]
    fn ysc2_512_encrypt_decrypt() {
        let key = [0x01; 64].into();
        let nonce = [0x02; 64].into();
        let mut buffer = PLAINTEXT.to_vec();

        // Encrypt
        let mut cipher = Ysc2_512Cipher::new(&key, &nonce);
        cipher.apply_keystream(&mut buffer);

        assert_ne!(
            buffer, PLAINTEXT,
            "Ciphertext should not be the same as plaintext"
        );

        // Decrypt
        let mut cipher = Ysc2_512Cipher::new(&key, &nonce);
        cipher.apply_keystream(&mut buffer);

        assert_eq!(
            buffer, PLAINTEXT,
            "Decrypted text should match the original plaintext"
        );
    }

    #[test]
    fn ysc2_1024_seek_and_consistency() {
        let key = [0x03; 128].into();
        let nonce = [0x04; 64].into();
        let mut buffer1 = [0u8; 128];
        let mut buffer2 = [0u8; 128];

        // Generate 2 blocks of keystream
        let mut cipher1 = Ysc2_1024Cipher::new(&key, &nonce);
        cipher1.apply_keystream(&mut buffer1);

        // Generate the second block separately after seeking
        let mut cipher2 = Ysc2_1024Cipher::new(&key, &nonce);
        cipher2.seek(64); // Seek to the beginning of the second block
        cipher2.apply_keystream(&mut buffer2[64..]);

        assert_eq!(
            buffer1[64..],
            buffer2[64..],
            "Keystream from sought position should match"
        );
    }

    #[test]
    #[cfg(feature = "ysc2_simd")]
    fn ysc2_simd_vs_soft_consistency() {
        use crate::core::Ysc2Core;
        use crate::{Ysc2_512, backends};

        let key = [0xAB; 64].into();
        let nonce = [0xCD; 64].into();
        
        // Generate keystream using the soft backend
        let mut soft_cipher = Ysc2_512_Cipher::new(&key, &nonce);
        let mut soft_keystream = vec![0u8; 256];
        soft_cipher.apply_keystream(&mut soft_keystream);

        // Generate keystream using the SIMD backend
        // We need to build a core instance and call the backend directly for this test
        let mut simd_core = Ysc2Core::<Ysc2_512>::new(&key, &nonce);
        let mut simd_backend = backends::simd::Backend(&mut simd_core);
        let mut simd_keystream = vec![0u8; 256];
        for chunk in simd_keystream.chunks_mut(64) {
            cipher::StreamCipherBackend::gen_ks_block(&mut simd_backend, chunk.into());
        }

        assert_eq!(soft_keystream, simd_keystream, "SIMD and Soft backends must produce identical keystreams");
    }
}