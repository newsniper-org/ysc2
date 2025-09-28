//======================================================================
// YSC2 Crate Test Suite
//======================================================================
#![cfg(test)]

extern crate alloc;
use alloc::vec;

#[cfg(feature = "ysc2x")]
use aead::AeadInPlace;

#[cfg(feature = "ysc2x")]
use crate::{
    Ysc2_1024Aead, Ysc2_1024Mac, Ysc2_512Aead,
    Ysc2_512Hash, Ysc2_512Hasher
};
use crate::{
    Ysc2_1024StreamCipher, Ysc2_512StreamCipher,
};
#[cfg(feature = "ysc2x")]
use aead::{Aead, KeyInit};
use cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
#[cfg(feature = "ysc2x")]
use digest::{ExtendableOutput, KeyInit as MacKeyInit, Mac as _, Update, XofReader};

// --- WASM Compatibility Fix ---
// Replace OsRng with a deterministic PRNG for reproducible tests.
#[cfg(feature = "ysc2x")]
use rand_core::{RngCore, SeedableRng};
#[cfg(feature = "ysc2x")]
use rand_chacha::ChaCha8Rng;


const PLAINTEXT: &[u8] = b"This is a reasonably long test message for the YSC2 cipher suite.";
#[cfg(feature = "ysc2x")]
const ASSOCIATED_DATA: &[u8] = b"Metadata that needs to be authenticated but not encrypted.";


//======================================================================
// Stream Cipher Tests
//======================================================================

#[test]
fn ysc2_512_stream_roundtrip() {
    let key = [0x01u8; 64].into();
    let nonce = [0x02u8; 64].into();
    let mut buffer = PLAINTEXT.to_vec();

    // Encrypt
    let mut cipher = Ysc2_512StreamCipher::new(&key, &nonce);
    cipher.apply_keystream(&mut buffer);
    assert_ne!(buffer, PLAINTEXT, "Ciphertext should not match plaintext");

    // Decrypt
    let mut cipher = Ysc2_512StreamCipher::new(&key, &nonce);
    cipher.apply_keystream(&mut buffer);
    assert_eq!(buffer, PLAINTEXT, "Decrypted text should match original");
}

#[test]
fn ysc2_1024_stream_seek_consistency() {
    let key = [0x03u8; 128].into();
    let nonce = [0x04u8; 64].into();
    let mut buffer1 = vec![0u8; 128];
    let mut buffer2 = vec![0u8; 128];

    // Generate 2 blocks of keystream at once
    let mut cipher1 = Ysc2_1024StreamCipher::new(&key, &nonce);
    cipher1.apply_keystream(&mut buffer1);

    // Generate the second block separately after seeking
    let mut cipher2 = Ysc2_1024StreamCipher::new(&key, &nonce);
    cipher2.seek(64); // Seek to the beginning of the second 64-byte part
    cipher2.apply_keystream(&mut buffer2[64..]);

    assert_eq!(buffer1[64..], buffer2[64..], "Keystream from sought position should match");
}

//======================================================================
// Sponge (YSC2-X) Tests
//======================================================================
#[cfg(feature = "ysc2x")]
#[test]
fn ysc2_512_hash_and_xof() {
    use digest::Digest;

    let mut hasher = Ysc2_512Hasher::default();
    hasher.update(b"hello");
    let mut reader = hasher.finalize_xof();
    
    let mut out1 = [0u8; 32];
    reader.read(&mut out1);

    // Continue reading from the same reader
    let mut out2 = [0u8; 32];
    reader.read(&mut out2);

    assert_ne!(out1, out2, "XOF should produce different outputs on subsequent reads");

    // Test fixed-size Hash
    let mut fixed_hasher = Ysc2_512Hash::default();
    <Ysc2_512Hash as Digest>::update(&mut fixed_hasher, b"hello");
    let fixed_out = <Ysc2_512Hash as Digest>::finalize(fixed_hasher);
    
    assert_eq!(&out1[..], &fixed_out[..32], "Fixed hash should match the first part of XOF output");
}
#[cfg(feature = "ysc2x")]
#[test]
fn ysc2_1024_mac_verification() {
    use digest::Mac;

    let key = [0xAA; 128];
    let mut mac = <Ysc2_1024Mac as Mac>::new_from_slice(&key).expect("MAC key init failed");
    <Ysc2_1024Mac as Mac>::update(&mut mac, b"message to authenticate");
    let result = mac.finalize();
    let code_bytes = result.into_bytes();

    // Correct verification
    let mut mac = <Ysc2_1024Mac as Mac>::new_from_slice(&key).expect("MAC key init failed");
   <Ysc2_1024Mac as Mac>::update(&mut mac, b"message to authenticate");
    assert!(mac.verify_slice(&code_bytes).is_ok(), "MAC verification should succeed with correct key and message");

    // Incorrect key
    let wrong_key = [0xBB; 128];
    let mut mac = <Ysc2_1024Mac as Mac>::new_from_slice(&wrong_key).expect("MAC key init failed");
    <Ysc2_1024Mac as Mac>::update(&mut mac, b"message to authenticate");
    assert!(mac.verify_slice(&code_bytes).is_err(), "MAC verification should fail with incorrect key");

    // Incorrect message
    let mut mac = <Ysc2_1024Mac as Mac>::new_from_slice(&key).expect("MAC key init failed");
    <Ysc2_1024Mac as Mac>::update(&mut mac, b"different message");
    assert!(mac.verify_slice(&code_bytes).is_err(), "MAC verification should fail with incorrect message");
}


//======================================================================
// AEAD Tests
//======================================================================
#[cfg(feature = "ysc2x")]
#[test]
fn ysc2_512_aead_roundtrip() {
    let mut rng = ChaCha8Rng::from_seed([42; 32]);
    let key = Ysc2_512Aead::generate_key(&mut rng);
    let cipher = Ysc2_512Aead::new(&key);
    let nonce = [0x42; 64].into(); // Nonce size is 64 bytes

    let mut buffer = PLAINTEXT.to_vec();

    // Encrypt
    let tag = cipher.encrypt_in_place_detached(&nonce, ASSOCIATED_DATA, &mut buffer)
        .expect("AEAD encryption failed");
    
    assert_ne!(buffer, PLAINTEXT, "AEAD ciphertext should not match plaintext");

    // Decrypt with correct tag
    let cipher = Ysc2_512Aead::new(&key);
    cipher.decrypt_in_place_detached(&nonce, ASSOCIATED_DATA, &mut buffer, &tag)
        .expect("AEAD decryption should succeed with correct tag");
    
    assert_eq!(buffer, PLAINTEXT, "AEAD decrypted text should match original");
}
#[cfg(feature = "ysc2x")]
#[test]
fn ysc2_1024_aead_authentication_failure() {
    let mut rng = ChaCha8Rng::from_seed([24; 32]);
    let key = Ysc2_1024Aead::generate_key(&mut rng);
    let cipher = Ysc2_1024Aead::new(&key);
    let nonce = [0x24; 64].into();

    let mut buffer = PLAINTEXT.to_vec();

    // Encrypt to get a valid tag
    let tag = cipher.encrypt_in_place_detached(&nonce, ASSOCIATED_DATA, &mut buffer)
        .expect("AEAD encryption failed");

    // --- Case 1: Tampered ciphertext ---
    let mut tampered_buffer = buffer.clone();
    tampered_buffer[0] ^= 0xFF; // Flip the first byte
    let err = cipher.decrypt_in_place_detached(&nonce, ASSOCIATED_DATA, &mut tampered_buffer, &tag)
        .expect_err("Decryption should fail for tampered ciphertext");
    assert_eq!(err, aead::Error, "Error should be authentication error");

    // --- Case 2: Tampered associated data ---
    let tampered_ad = b"tampered metadata";
    let err = cipher.decrypt_in_place_detached(&nonce, tampered_ad, &mut buffer, &tag)
        .expect_err("Decryption should fail for tampered AD");
    assert_eq!(err, aead::Error, "Error should be authentication error");
        
    // --- Case 3: Invalid tag ---
    let mut invalid_tag_bytes = tag.clone();
    invalid_tag_bytes[0] ^= 0xFF; // Flip the first byte of the tag
    let invalid_tag = invalid_tag_bytes.into();
    let err = cipher.decrypt_in_place_detached(&nonce, ASSOCIATED_DATA, &mut buffer, &invalid_tag)
        .expect_err("Decryption should fail for invalid tag");
    assert_eq!(err, aead::Error, "Error should be authentication error");
}