//! # AlphaNet precompiles.
//!
//! Implementations of EVM precompiled contracts for AlphaNet.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

pub mod bls12_381;
pub mod secp256r1;

mod addresses;
