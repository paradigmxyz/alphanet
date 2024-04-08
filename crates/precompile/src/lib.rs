//! # AlphaNet precompiles.
//!
//! Implementations of EVM precompiled contracts for AlphaNet.
//!
//! Alphanet currently implements the following EIPs, which define precompiles:
//! - [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537): Precompile for BLS12-381 curve
//! operations. The precompile implementation is located in the [bls12_381] module.
//! - [EIP-7212](https://eips.ethereum.org/EIPS/eip-7212): Precompile for secp256r1 Curve Support.
//! The precompile implementation is located in the [secp256r1] module.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

/// The implementation of [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537): Precompile for BLS12-381 curve.
pub mod bls12_381;

/// The implementation of [EIP-7212](https://eips.ethereum.org/EIPS/eip-7212): Precompile for secp256r1 Curve Support.
pub mod secp256r1;

mod addresses;
