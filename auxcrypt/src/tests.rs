//======================================================================
// AuxCrypt Crate Test Suite
//======================================================================
#![cfg(test)]

use crate::{AuxCrypt1024Stream, AuxCrypt512Stream};
use cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};

const PLAINTEXT: &[u8] = b"Test message for the AuxCrypt auxiliary stream cipher.";

#[test]
fn auxcrypt_512_stream_roundtrip() {
    let key = [0x11; 64].into();
    let nonce = [0x22; 64].into();
    let mut buffer = PLAINTEXT.to_vec();

    // Encrypt
    let mut cipher = AuxCrypt512Stream::new(&key, &nonce);
    cipher.apply_keystream(&mut buffer);
    assert_ne!(buffer, PLAINTEXT, "Ciphertext should not match plaintext");

    // Decrypt
    let mut cipher = AuxCrypt512Stream::new(&key, &nonce);
    cipher.apply_keystream(&mut buffer);
    assert_eq!(buffer, PLAINTEXT, "Decrypted text should match original");
}

#[test]
fn auxcrypt_1024_stream_seek_consistency() {
    let key = [0x33; 128].into();
    let nonce = [0x44; 64].into();
    let mut buffer1 = vec![0u8; 256];
    let mut buffer2 = vec![0u8; 256];

    // Generate 2 blocks of keystream at once
    let mut cipher1 = AuxCrypt1024Stream::new(&key, &nonce);
    cipher1.apply_keystream(&mut buffer1);

    // Generate the second block separately after seeking
    let mut cipher2 = AuxCrypt1024Stream::new(&key, &nonce);
    cipher2.seek(128); // Seek to the beginning of the second 128-byte block
    cipher2.apply_keystream(&mut buffer2[128..]);

    assert_eq!(buffer1[128..], buffer2[128..], "Keystream from sought position should match");
}

#[test]
#[cfg(feature = "auxcrypt_simd")]
fn auxcrypt_simd_vs_soft_consistency() {
    use crate::stream::AuxCryptCore;
    use crate::variant::AuxCrypt512;

    let key = [0xAB; 64].into();
    let nonce = [0xCD; 64].into();
    let mut buffer = vec![0u8; 512];

    // Generate keystream using the default (soft) backend via high-level API
    let mut soft_cipher = AuxCrypt512Stream::new(&key, &nonce);
    let mut soft_keystream = buffer.clone();
    soft_cipher.apply_keystream(&mut soft_keystream);

    // Generate keystream using the SIMD backend directly for this test
    // This requires building a core instance and calling the backend.
    let mut simd_core = AuxCryptCore::<AuxCrypt512>::new(&key, &nonce);
    let mut simd_backend = crate::backends::simd::Backend(&mut simd_core);
    let mut simd_keystream = buffer.clone();
    
    // We need to call gen_ks_block manually for each block
    for chunk in simd_keystream.chunks_mut(128) {
        let block = cipher::generic_array::GenericArray::from_mut_slice(chunk);
        cipher::StreamBackend::gen_ks_block(&mut simd_backend, block);
    }
    
    assert_eq!(soft_keystream, simd_keystream, "SIMD and Soft backends must produce identical keystreams");
}