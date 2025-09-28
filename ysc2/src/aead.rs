//======================================================================
// src/aead.rs
// YSC2-X AEAD Mode Implementation.
//
// This implementation uses a standard "Duplex" sponge construction to ensure
// symmetric state updates during encryption and decryption, which is crucial
// for correct tag generation and verification.
//======================================================================

use crate::backends;
use crate::consts::{RATE_BYTES, STATE_WORDS};
use crate::variant::Ysc2Variant;
use core::marker::PhantomData;
use aead::{
    consts::{U0, U16},
    generic_array::GenericArray,
    AeadCore, AeadInPlace, Key, KeyInit, KeySizeUser, Nonce, Tag,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// YSC2-X AEAD Cipher.
#[derive(Clone, ZeroizeOnDrop)]
pub struct Ysc2Aead<V: Ysc2Variant> {
    initial_state: [u64; STATE_WORDS],
    _variant: PhantomData<V>,
}

impl<V: Ysc2Variant> KeySizeUser for Ysc2Aead<V> {
    type KeySize = V::KeySize;
}

impl<V: Ysc2Variant> KeyInit for Ysc2Aead<V> {
    fn new(key: &Key<Self>) -> Self {
        let mut state = [0u64; STATE_WORDS];
        let key_bytes = key.as_slice();

        // 1. Load key into state.
        for (i, chunk) in key_bytes.chunks_exact(8).enumerate() {
            state[i] = u64::from_le_bytes(chunk.try_into().unwrap());
        }

        // 2. Absorb the AEAD domain separator.
        absorb_padded_data::<V>(&mut state, V::AEAD_DOMAIN.as_bytes());

        Self { initial_state: state, _variant: PhantomData }
    }
}

impl<V: Ysc2Variant> AeadCore for Ysc2Aead<V> {
    type NonceSize = V::NonceSize;
    type TagSize = U16; // 128-bit (16-byte) tag.
    type CiphertextOverhead = U0;
}

impl<V: Ysc2Variant> AeadInPlace for Ysc2Aead<V> {
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> aead::Result<Tag<Self>> {
        let mut state = self.initial_state;

        absorb_padded_data::<V>(&mut state, nonce);
        absorb_padded_data::<V>(&mut state, associated_data);

        // Process plaintext: Squeeze, encrypt, then absorb ciphertext.
        for chunk in buffer.chunks_mut(RATE_BYTES) {
            backends::permutation::<V>(&mut state);
            
            let mut keystream_block = [0u8; RATE_BYTES];
            for (i, ks_chunk) in keystream_block.chunks_exact_mut(8).enumerate() {
                ks_chunk.copy_from_slice(&state[i].to_le_bytes());
            }

            // Encrypt in-place
            for (i, byte) in chunk.iter_mut().enumerate() {
                *byte ^= keystream_block[i];
            }
            
            // Absorb the resulting ciphertext.
            absorb_padded_data::<V>(&mut state, chunk);
        }

        // Finalize and generate the tag.
        backends::permutation::<V>(&mut state);
        let mut tag = [0u8; 16];
        tag[..8].copy_from_slice(&state[0].to_le_bytes());
        tag[8..].copy_from_slice(&state[1].to_le_bytes());

        Ok(GenericArray::clone_from_slice(&tag))
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag<Self>,
    ) -> aead::Result<()> {
        let mut state = self.initial_state;

        absorb_padded_data::<V>(&mut state, nonce);
        absorb_padded_data::<V>(&mut state, associated_data);
        
        // Process ciphertext: Absorb ciphertext, then squeeze, then decrypt.
        for chunk in buffer.chunks_mut(RATE_BYTES) {
            backends::permutation::<V>(&mut state);
            
            let mut keystream_block = [0u8; RATE_BYTES];
            for (i, ks_chunk) in keystream_block.chunks_exact_mut(8).enumerate() {
                ks_chunk.copy_from_slice(&state[i].to_le_bytes());
            }

            // Absorb the ciphertext before decryption.
            absorb_padded_data::<V>(&mut state, chunk);

            // Decrypt in-place
            for (i, byte) in chunk.iter_mut().enumerate() {
                *byte ^= keystream_block[i];
            }
        }

        // Finalize and generate the tag for verification.
        backends::permutation::<V>(&mut state);
        let mut calculated_tag = [0u8; 16];
        calculated_tag[..8].copy_from_slice(&state[0].to_le_bytes());
        calculated_tag[8..].copy_from_slice(&state[1].to_le_bytes());

        // Constant-time tag comparison.
        if ct_compare(&calculated_tag, tag.as_slice()) {
            Ok(())
        } else {
            // On failure, zero out the decrypted (but unauthenticated) buffer.
            buffer.iter_mut().for_each(|b| *b = 0);
            Err(aead::Error)
        }
    }
}

/// Helper function to absorb data with padding.
/// This function handles the padding logic correctly, even for empty or block-sized data.
fn absorb_padded_data<V: Ysc2Variant>(state: &mut [u64; STATE_WORDS], data: &[u8]) {
    let mut chunks = data.chunks(RATE_BYTES);
    
    for chunk in chunks.by_ref() {
        let mut block = [0u8; RATE_BYTES];
        block[..chunk.len()].copy_from_slice(chunk);
        
        for (i, word_chunk) in block.chunks_exact(8).enumerate() {
            state[i] ^= u64::from_le_bytes(word_chunk.try_into().unwrap());
        }

        // If this chunk is the last and not full, apply padding.
        if chunk.len() < RATE_BYTES {
            let mut padded_block = [0u8; RATE_BYTES];
            padded_block[chunk.len()] = 0x01; // Simple padding
            for i in 0..8 {
                state[i] ^= u64::from_le_bytes(padded_block[i*8..(i+1)*8].try_into().unwrap());
            }
        }
    }

    // If data length is a multiple of RATE_BYTES or is empty,
    // an additional block with padding must be absorbed.
    if data.is_empty() || data.len() % RATE_BYTES == 0 {
        let mut padding_block = [0u8; RATE_BYTES];
        padding_block[0] = 0x01;
        for i in 0..8 {
            state[i] ^= u64::from_le_bytes(padding_block[i*8..(i+1)*8].try_into().unwrap());
        }
    }
    backends::permutation::<V>(state);
}

/// Constant-time comparison function.
fn ct_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0, |acc, (x, y)| acc | (x ^ y)) == 0
}
