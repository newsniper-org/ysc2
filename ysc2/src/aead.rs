//======================================================================
// src/aead.rs
// YSC2-X AEAD Mode Implementation.
//======================================================================

use crate::backends;
use crate::consts::{RATE_BYTES, STATE_WORDS};
use crate::variant::Ysc2Variant;
use core::marker::PhantomData;
use aead::{
    consts::{U0, U16}, // 16바이트(128비트) Tag 크기 정의
    generic_array::GenericArray,
    AeadCore, AeadInPlace, Key, KeyInit, KeySizeUser, Nonce, Tag
};
use zeroize::ZeroizeOnDrop;

/// YSC2-X를 사용한 AEAD 암호.
#[derive(Clone, ZeroizeOnDrop)]
pub struct Ysc2Aead<V: Ysc2Variant> {
    state: [u64; STATE_WORDS],
    _variant: PhantomData<V>,
}

impl<V: Ysc2Variant> KeySizeUser for Ysc2Aead<V> {
    type KeySize = V::KeySize;
}

impl<V: Ysc2Variant> KeyInit for Ysc2Aead<V> {
    fn new(key: &Key<Self>) -> Self {
        let mut state = [0u64; STATE_WORDS];
        let key_bytes = key.as_slice();

        // 1. 상태 초기화 (키 로드)
        for (i, chunk) in key_bytes.chunks_exact(8).enumerate() {
            state[i] = u64::from_le_bytes(chunk.try_into().unwrap());
        }

        // 2. 키 도메인 분리 상수 흡수
        let domain_separator = V::AEAD_DOMAIN.as_bytes();
        let mut block = [0u8; RATE_BYTES];
        block[..domain_separator.len()].copy_from_slice(domain_separator);
        block[domain_separator.len()] = 0x80; // 패딩
        
        for (i, chunk) in block.chunks_exact(8).enumerate() {
            state[i] ^= u64::from_le_bytes(chunk.try_into().unwrap());
        }
        
        backends::permutation::<V>(&mut state);
        
        Self { state, _variant: PhantomData }
    }
}

impl<V: Ysc2Variant> AeadCore for Ysc2Aead<V> {
    type NonceSize = V::NonceSize;
    type TagSize = U16; // Tag 크기를 16바이트(128비트)로 지정
    type CiphertextOverhead = U0;
}

impl<V: Ysc2Variant> AeadInPlace for Ysc2Aead<V> {
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> aead::Result<Tag<Self>> {
        let mut state = self.state;

        // 1. Nonce 흡수
        absorb::<V>(&mut state, nonce, V::AEAD_NONCE_DOMAIN.as_bytes());

        // 2. Associated Data 흡수
        absorb::<V>(&mut state, associated_data, V::AEAD_AD_DOMAIN.as_bytes());
        
        // 3. 평문 암호화 및 흡수 (Encrypt-then-MAC 방식과 유사)
        let tag = crypt_and_absorb::<V>(&mut state, buffer, V::AEAD_CT_DOMAIN.as_bytes(), true);

        Ok(GenericArray::clone_from_slice(&tag))
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag<Self>,
    ) -> aead::Result<()> {
        let mut state = self.state;
        
        // 1. Nonce 흡수
        absorb::<V>(&mut state, nonce, V::AEAD_NONCE_DOMAIN.as_bytes());

        // 2. Associated Data 흡수
        absorb::<V>(&mut state, associated_data, V::AEAD_AD_DOMAIN.as_bytes());
        
        // 3. 암호문 복호화 및 흡수
        let calculated_tag = crypt_and_absorb::<V>(&mut state, buffer, V::AEAD_CT_DOMAIN.as_bytes(), false);

        // 4. Tag 비교 (상수 시간 비교)
        if ct_compare(&calculated_tag, tag.as_slice()) {
            Ok(())
        } else {
            Err(aead::Error)
        }
    }
}

/// 데이터를 흡수하는 내부 함수
fn absorb<V: Ysc2Variant>(state: &mut [u64; STATE_WORDS], data: &[u8], domain: &[u8]) {
    // 도메인 분리 상수 먼저 처리
    let mut block = [0u8; RATE_BYTES];
    block[..domain.len()].copy_from_slice(domain);
    block[domain.len()] = 0x80; // 패딩
    for (i, chunk) in block.chunks_exact(8).enumerate() {
        state[i] ^= u64::from_le_bytes(chunk.try_into().unwrap());
    }
    backends::permutation::<V>(state);

    // 실제 데이터 처리
    for chunk in data.chunks(RATE_BYTES) {
        let mut block = [0u8; RATE_BYTES];
        block[..chunk.len()].copy_from_slice(chunk);
        block[chunk.len()] = 0x80; // 각 청크마다 패딩
        
        for (i, word_chunk) in block.chunks_exact(8).enumerate() {
            state[i] ^= u64::from_le_bytes(word_chunk.try_into().unwrap());
        }
        backends::permutation::<V>(state);
    }
}

/// 데이터를 암호화/복호화하고 상태에 흡수하는 내부 함수
fn crypt_and_absorb<V: Ysc2Variant>(state: &mut [u64; STATE_WORDS], buffer: &mut [u8], domain: &[u8], is_encrypting: bool) -> [u8; 16] {
    // 도메인 분리 상수 처리
    let mut domain_block = [0u8; RATE_BYTES];
    domain_block[..domain.len()].copy_from_slice(domain);
    domain_block[domain.len()] = 0x80; // 패딩
    for (i, chunk) in domain_block.chunks_exact(8).enumerate() {
        state[i] ^= u64::from_le_bytes(chunk.try_into().unwrap());
    }
    backends::permutation::<V>(state);

    // 데이터 처리
    for chunk in buffer.chunks_mut(RATE_BYTES) {
        let mut keystream_block = [0u8; RATE_BYTES];
        for (i, ks_chunk) in keystream_block.chunks_exact_mut(8).enumerate() {
            ks_chunk.copy_from_slice(&state[i].to_le_bytes());
        }
        
        let data_to_absorb = if is_encrypting { chunk.to_vec() } else { keystream_block[..chunk.len()].to_vec() };
        
        for (i, byte) in chunk.iter_mut().enumerate() {
            *byte ^= keystream_block[i];
        }

        let mut block_to_absorb = [0u8; RATE_BYTES];
        let absorb_source = if is_encrypting { chunk } else { data_to_absorb.as_slice() };
        block_to_absorb[..absorb_source.len()].copy_from_slice(absorb_source);
        block_to_absorb[absorb_source.len()] = 0x80;

        for (i, word_chunk) in block_to_absorb.chunks_exact(8).enumerate() {
            state[i] ^= u64::from_le_bytes(word_chunk.try_into().unwrap());
        }
        backends::permutation::<V>(state);
    }

    // Tag 생성
    let mut tag = [0u8; 16];
    tag[..8].copy_from_slice(&state[0].to_le_bytes());
    tag[8..].copy_from_slice(&state[1].to_le_bytes());
    tag
}

/// 상수 시간 비교 함수
fn ct_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0, |acc, (x, y)| acc | (x ^ y)) == 0
}