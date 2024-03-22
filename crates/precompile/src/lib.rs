//! # alphanet-precompile
//!
//! Implementations of EVM precompiled contracts for AlphaNet.

use revm_primitives::Address;

/// EIP-7212 secp256r1 precompile.
pub mod secp256r1;

/// EIP-2537 BLS12-381 precompile.
pub mod bls12_381;

mod addresses;
