//======================================================================
// src/consts.rs
// 각종 상수 정의
//======================================================================

pub const STATE_WORDS: usize = 16;
pub const RATE_BYTES: usize = 64;

/// The internal state size in bytes.
pub const STATE_BYTES: usize = STATE_WORDS * 8;

/// 라운드 상수 (RC) - 간단한 IOTA 값 사용
pub const RC: [u64; 16] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
];

/// 비선형 함수 g(x)에 사용될 회전 상수
pub const ROT_A: u32 = 13;
pub const ROT_B: u32 = 37;

/// 선형 계층(워드 순열)에 사용될 순열 테이블
pub const P: [usize; 16] = [
    0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11,
];