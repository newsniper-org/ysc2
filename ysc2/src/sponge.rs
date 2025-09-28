//======================================================================
// src/sponge.rs
// YSC2-X: Ysc2xCore에 핵심 로직을 구현하고, CoreWrapper를 통해
// 사용자 친화적인 Hasher, Hash, Mac 타입을 제공합니다.
//======================================================================

use cipher::KeySizeUser;
use crate::backends;
use crate::consts::{RATE_BYTES, STATE_WORDS};
use crate::variant::Ysc2Variant;
use core::marker::PhantomData;
use digest::{
    block_buffer::Eager,
    core_api::{
        Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper,
        ExtendableOutputCore, FixedOutputCore, OutputSizeUser, UpdateCore, XofReaderCore,
    },
    KeyInit, Output,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

//======================================================================
// Ysc2xCore - 모든 저수준 핵심 로직 담당
//======================================================================

/// YSC2-X 스펀지 구조의 저수준 핵심 엔진.
/// 사용자는 이 타입을 직접 사용하지 않고 CoreWrapper를 통해 상호작용합니다.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Ysc2xCore<V: Ysc2Variant> {
    state: [u64; STATE_WORDS],
    _variant: PhantomData<V>,
}

impl<V: Ysc2Variant> Ysc2xCore<V> {
    fn absorb_block(&mut self, block: &Block<Self>) {
        for (i, chunk) in block.chunks_exact(8).enumerate() {
            self.state[i] ^= u64::from_le_bytes(chunk.try_into().unwrap());
        }
        backends::permutation::<V>(&mut self.state);
    }

    fn new<const N: usize>(inputs: [&[u8]; N]) -> Self {
        let flattend = inputs.concat();
        let mut core = Self::default();
        let (raw_blocks, rem) = flattend.as_chunks::<64>();
        let buffer = raw_blocks.iter().map(|raw_block| {
            return Block::<Self>::clone_from_slice(raw_block);
        }).collect::<Vec<Block<Self>>>();
        core.update_blocks(&buffer);
        // finalize_xof_core를 호출하지는 않으므로, 수동으로 마지막 블록을 처리합니다.
        if !rem.is_empty() {
             let mut padded_block = Block::<Self>::default();
             padded_block[..rem.len()].copy_from_slice(rem);
             padded_block[rem.len()] = 0x80;
             core.absorb_block(&padded_block);
        }
        core
    }
}

impl<V: Ysc2Variant> Default for Ysc2xCore<V> {
    fn default() -> Self {
        Self {
            state: [0; STATE_WORDS],
            _variant: PhantomData,
        }
    }
}

impl<V: Ysc2Variant> BlockSizeUser for Ysc2xCore<V> {
    type BlockSize = digest::consts::U64;
}

impl<V: Ysc2Variant> BufferKindUser for Ysc2xCore<V> {
    type BufferKind = Eager;
}

impl<V: Ysc2Variant> UpdateCore for Ysc2xCore<V> {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        for block in blocks {
            self.absorb_block(block);
        }
    }
}

impl <V: Ysc2Variant> BlockSizeUser for Reader<V> {
    type BlockSize = digest::consts::U64;
}

impl<V: Ysc2Variant> ExtendableOutputCore for Ysc2xCore<V> {
    type ReaderCore = Reader<V>;

    #[inline]
    fn finalize_xof_core(&mut self, buffer: &mut Buffer<Self>) -> Self::ReaderCore {
        let final_block = buffer.get_data();
        let mut padded_block = Block::<Self>::default();
        padded_block[..final_block.len()].copy_from_slice(final_block);
        padded_block[final_block.len()] = 0x80; // Simple 10*1 padding

        self.absorb_block(&padded_block);

        Reader {
            state: self.state,
            _variant: PhantomData,
        }
    }
}

// Keyed 모드를 위한 KeyInit 구현
impl<V: Ysc2Variant> KeyInit for Ysc2xCore<V> {
    
    fn new(key: &digest::Key<Self>) -> Self {
        let raw = [V::KEYED_DOMAIN.as_bytes(), key];
        Self::new(raw)
    }
}

impl<V: Ysc2Variant> KeySizeUser for Ysc2xCore<V> {
    type KeySize = V::KeySize;
}


//======================================================================
// Reader - 출력 생성(Squeezing) 담당
//======================================================================

/// YSC2-X를 위한 XOF 리더. Hasher를 finalize하여 생성됩니다.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Reader<V: Ysc2Variant> {
    state: [u64; STATE_WORDS],
    _variant: PhantomData<V>,
}

impl<V: Ysc2Variant> XofReaderCore for Reader<V> {
    #[inline]
    fn read_block(&mut self) -> Block<Self> {
        // 1. 상태에 순열 함수를 적용하여 다음 키스트림 블록을 준비합니다.
        backends::permutation::<V>(&mut self.state);

        // 2. 출력으로 내보낼 블록을 생성합니다.
        let mut block = Block::<Self>::default();

        // 3. 순열이 적용된 상태의 rate 부분(앞 64바이트)을 블록에 복사합니다.
        for (i, chunk) in block.chunks_exact_mut(8).enumerate() {
            // STATE_WORDS 중 RATE_BYTES/8 만큼만 복사합니다.
            if i < RATE_BYTES / 8 {
                chunk.copy_from_slice(&self.state[i].to_le_bytes());
            }
        }
        block
    }
}

//======================================================================
// 고수준 API를 위한 타입 별칭 및 래퍼
//======================================================================

/// `Ysc2xCore`를 감싸서 `Update`와 `ExtendableOutput` 트레잇을 제공하는
/// 범용 해셔 타입입니다.
pub type Hasher<V> = CoreWrapper<Ysc2xCore<V>>;

/// `Ysc2xCore`를 감싸서 고정된 크기의 `Digest` 트레잇을 제공하는
/// 해시 함수 타입입니다. (출력 크기: 64바이트)
pub type Hash<V> = CoreWrapper<FixedOutputCoreWrapper<Ysc2xCore<V>>>;

/// 고정 길이 출력을 위해 Ysc2xCore를 한번 더 감싸는 래퍼.
#[derive(Clone, Default)]
pub struct FixedOutputCoreWrapper<V: Ysc2Variant>(Ysc2xCore<V>);

impl<V: Ysc2Variant> KeySizeUser for FixedOutputCoreWrapper<V> {
    type KeySize = V::KeySize;
}

impl<V: Ysc2Variant> KeyInit for FixedOutputCoreWrapper<V> {
    fn new(key: &digest::Key<Self>) -> Self { Self(<Ysc2xCore<V> as KeyInit>::new(key)) }
}

impl<V: Ysc2Variant> BlockSizeUser for FixedOutputCoreWrapper<V> {
    type BlockSize = <Ysc2xCore<V> as BlockSizeUser>::BlockSize;
}

impl<V: Ysc2Variant> BufferKindUser for FixedOutputCoreWrapper<V> {
    type BufferKind = <Ysc2xCore<V> as BufferKindUser>::BufferKind;
}

impl<V: Ysc2Variant> UpdateCore for FixedOutputCoreWrapper<V> {
    fn update_blocks(&mut self, blocks: &[Block<Self>]) { self.0.update_blocks(blocks); }
}

impl<V: Ysc2Variant> OutputSizeUser for FixedOutputCoreWrapper<V> {
    type OutputSize = digest::consts::U64; // 64바이트 고정 출력
}

impl<V: Ysc2Variant> FixedOutputCore for FixedOutputCoreWrapper<V> {
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let mut reader = self.0.finalize_xof_core(buffer);
        *out = reader.read_block();
    }
}

