//! # EIP-2537 BLS12-381 Precompiles
//!
//! This module implements the [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537) precompiles for
//! BLS12-381 curve operations.
//!
//! BLS12-381 is a pairing-friendly elliptic curve construction that is used in various
//! cryptographic constructions. The precompiles implement the following operations:
//! - G1 point addition, with [`BLS12_G1ADD`](crate::bls12_381::BLS12_G1ADD)
//! - Multiplication between a G1 point and a scalar, with
//! [`BLS12_G1MUL`](crate::bls12_381::BLS12_G1MUL)
//! - Multi-scalar-multiplication of G1 points, with
//! [`BLS12_G1MSM`](crate::bls12_381::BLS12_G1MSM)
//! - G2 point addition, with [`BLS12_G2ADD`](crate::bls12_381::BLS12_G2ADD)
//! - Multiplication between a G2 point and a scalar, with
//! [`BLS12_G2MUL`](crate::bls12_381::BLS12_G2MUL)
//! - Multi-scalar-multiplication of G2 points, with
//! [`BLS12_G2MSM`](crate::bls12_381::BLS12_G2MSM)
//! - The BLS12-381 pairing operation, with [`BLS12_PAIRING`](crate::bls12_381::BLS12_PAIRING)
//! - Mapping a `F_p` to a G1 point, with
//! [`BLS12_MAP_FP_TO_G1`](crate::bls12_381::BLS12_MAP_FP_TO_G1)
//! - Mapping a `F_p^2` element to a G2 point, with
//! [`BLS12_MAP_FP2_TO_G2`](crate::bls12_381::BLS12_MAP_FP2_TO_G2)
//!
//! The precompiles can be inserted in a custom EVM like this:
//! ```
//! use alphanet_precompile::bls12_381;
//! use reth::primitives::{ChainSpec, TransactionSigned, U256};
//! use reth_node_api::{ConfigureEvm, ConfigureEvmEnv};
//! use revm::{Database, Evm, EvmBuilder};
//! use revm_precompile::{PrecompileSpecId, Precompiles};
//! use revm_primitives::{Address, Bytes, CfgEnvWithHandlerCfg, TxEnv};
//! use std::sync::Arc;
//!
//! #[derive(Debug, Clone, Copy, Default)]
//! #[non_exhaustive]
//! struct AlphaNetEvmConfig;
//!
//! impl ConfigureEvm for AlphaNetEvmConfig {
//!     type DefaultExternalContext<'a> = ();
//!
//!     fn evm<'a, DB: Database + 'a>(&self, db: DB) -> Evm<'a, (), DB> {
//!         EvmBuilder::default()
//!             .with_db(db)
//!             .append_handler_register(|handler| {
//!                 let spec_id = handler.cfg.spec_id;
//!                 handler.pre_execution.load_precompiles = Arc::new(move || {
//!                     let mut precompiles =
//!                         Precompiles::new(PrecompileSpecId::from_spec_id(spec_id)).clone();
//!                     for precompile_with_address in bls12_381::precompiles() {
//!                         precompiles
//!                             .inner
//!                             .insert(precompile_with_address.0, precompile_with_address.1);
//!                     }
//!                     precompiles.into()
//!                 });
//!             })
//!             .build()
//!     }
//! }
//!
//! impl ConfigureEvmEnv for AlphaNetEvmConfig {
//!     fn fill_tx_env(tx_env: &mut TxEnv, transaction: &TransactionSigned, sender: Address) {
//!         todo!()
//!     }
//!     fn fill_cfg_env(
//!         _: &mut CfgEnvWithHandlerCfg,
//!         _: &ChainSpec,
//!         _: &reth::primitives::Header,
//!         _: U256,
//!     ) {
//!         todo!()
//!     }
//! }
//! ```

use crate::addresses::{
    BLS12_G1ADD_ADDRESS, BLS12_G1MSM_ADDRESS, BLS12_G1MUL_ADDRESS, BLS12_G2ADD_ADDRESS,
    BLS12_G2MSM_ADDRESS, BLS12_G2MUL_ADDRESS, BLS12_MAP_FP2_TO_G2_ADDRESS,
    BLS12_MAP_FP_TO_G1_ADDRESS, BLS12_PAIRING_ADDRESS,
};
use blst::{
    blst_bendian_from_fp, blst_final_exp, blst_fp, blst_fp12, blst_fp12_is_one, blst_fp12_mul,
    blst_fp2, blst_fp_from_bendian, blst_map_to_g1, blst_map_to_g2, blst_miller_loop, blst_p1,
    blst_p1_add_or_double_affine, blst_p1_affine, blst_p1_affine_in_g1, blst_p1_from_affine,
    blst_p1_mult, blst_p1_to_affine, blst_p2, blst_p2_add_or_double_affine, blst_p2_affine,
    blst_p2_affine_in_g2, blst_p2_from_affine, blst_p2_mult, blst_p2_to_affine, blst_scalar,
    blst_scalar_from_bendian, p1_affines, p2_affines,
};
use revm_precompile::{u64_to_address, Precompile, PrecompileWithAddress};
use revm_primitives::{Bytes, PrecompileError, PrecompileResult, B256};

/// Number of bits used in the BLS12-381 curve finite field elements.
const NBITS: usize = 256;
/// Base gas fee for BLS12-381 g1_add operation.
const G1ADD_BASE: u64 = 500;
/// Base gas fee for BLS12-381 g1_mul operation.
const G1MUL_BASE: u64 = 12000;
/// Base gas fee for BLS12-381 g2_add operation.
const G2ADD_BASE: u64 = 800;
/// Base gas fee for BLS12-381 g2_mul operation.
const G2MUL_BASE: u64 = 45000;
/// Multiplier gas fee for BLS12-381 pairing operation.
const PAIRING_MULTIPLIER_BASE: u64 = 43000;
/// Offset gas fee for BLS12-381 pairing operation.
const PAIRING_OFFSET_BASE: u64 = 65000;
/// Base gas fee for BLS12-381 map_fp_to_g1 operation.
const MAP_FP_TO_G1_BASE: u64 = 5500;
/// Base gas fee for BLS12-381 map_fp2_to_g2 operation.
const MAP_FP2_TO_G2_BASE: u64 = 75000;
/// Amount used to calculate the multi-scalar-multiplication discount.
const MSM_MULTIPLIER: u64 = 1000;
/// Input length of g1_add operation.
const G1ADD_INPUT_LENGTH: usize = 256;
/// Input length of g1_mul operation.
const G1MUL_INPUT_LENGTH: usize = 160;
/// Length of each of the elements in a g1 operation input.
const G1_INPUT_ITEM_LENGTH: usize = 128;
/// Input length of g2_add operation.
const G2ADD_INPUT_LENGTH: usize = 512;
/// Input length of g2_mul operation.
const G2MUL_INPUT_LENGTH: usize = 288;
/// Length of each of the elements in a g2 operation input.
const G2_INPUT_ITEM_LENGTH: usize = 256;
/// Input length of paitring operation.
const PAIRING_INPUT_LENGTH: usize = 384;
/// Output length of a g1 operation.
const G1_OUTPUT_LENGTH: usize = 128;
/// Output length of a g2 operation.
const G2_OUTPUT_LENGTH: usize = 256;
/// Finite field element input length.
const FP_LENGTH: usize = 48;
/// Finite field element padded input length.
const PADDED_FP_LENGTH: usize = 64;
/// Quadratic extension of finite field element input length.
const PADDED_FP2_LENGTH: usize = 128;
/// Input elements padding length.
const PADDING_LENGTH: usize = 16;
/// Scalar length.
const SCALAR_LENGTH: usize = 32;
/// Table of gas discounts for multi-scalar-multiplication operations.
const MSM_DISCOUNT_TABLE: [u64; 128] = [
    1200, 888, 764, 641, 594, 547, 500, 453, 438, 423, 408, 394, 379, 364, 349, 334, 330, 326, 322,
    318, 314, 310, 306, 302, 298, 294, 289, 285, 281, 277, 273, 269, 268, 266, 265, 263, 262, 260,
    259, 257, 256, 254, 253, 251, 250, 248, 247, 245, 244, 242, 241, 239, 238, 236, 235, 233, 232,
    231, 229, 228, 226, 225, 223, 222, 221, 220, 219, 219, 218, 217, 216, 216, 215, 214, 213, 213,
    212, 211, 211, 210, 209, 208, 208, 207, 206, 205, 205, 204, 203, 202, 202, 201, 200, 199, 199,
    198, 197, 196, 196, 195, 194, 193, 193, 192, 191, 191, 190, 189, 188, 188, 187, 186, 185, 185,
    184, 183, 182, 182, 181, 180, 179, 179, 178, 177, 176, 176, 175, 174,
];

/// Returns the bls12381 precompiles with their addresses.
pub fn precompiles() -> impl Iterator<Item = PrecompileWithAddress> {
    [
        BLS12_G1ADD,
        BLS12_G1MUL,
        BLS12_G1MSM,
        BLS12_G2ADD,
        BLS12_G2MUL,
        BLS12_G2MSM,
        BLS12_PAIRING,
        BLS12_MAP_FP_TO_G1,
        BLS12_MAP_FP2_TO_G2,
    ]
    .into_iter()
}

/// [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537#specification) BLS12_G1ADD precompile.
pub const BLS12_G1ADD: PrecompileWithAddress =
    PrecompileWithAddress(u64_to_address(BLS12_G1ADD_ADDRESS), Precompile::Standard(g1_add));

/// Encodes a G1 point in affine format into a byte slice with padded elements.
fn encode_g1_point(out: &mut [u8], input: *const blst_p1_affine) {
    // SAFETY: out comes from fixed length array, x and y are blst values.
    unsafe {
        fp_to_bytes(&mut out[..PADDED_FP_LENGTH], &(*input).x);
        fp_to_bytes(&mut out[PADDED_FP_LENGTH..], &(*input).y);
    }
}

/// Encodes a G2 point in affine format into a byte slice with padded elements.
fn encode_g2_point(out: &mut [u8], input: *const blst_p2_affine) {
    // SAFETY: out comes from fixed length array, input is a blst value.
    unsafe {
        fp_to_bytes(&mut out[..PADDED_FP_LENGTH], &(*input).x.fp[0]);
        fp_to_bytes(&mut out[PADDED_FP_LENGTH..2 * PADDED_FP_LENGTH], &(*input).x.fp[1]);
        fp_to_bytes(&mut out[2 * PADDED_FP_LENGTH..3 * PADDED_FP_LENGTH], &(*input).y.fp[0]);
        fp_to_bytes(&mut out[3 * PADDED_FP_LENGTH..4 * PADDED_FP_LENGTH], &(*input).y.fp[1]);
    }
}

/// Encodes a single finite field element into a byte slice with padding.
fn fp_to_bytes(out: &mut [u8], input: *const blst_fp) {
    if out.len() != PADDED_FP_LENGTH {
        return;
    }
    for item in out.iter_mut().take(PADDING_LENGTH) {
        *item = 0;
    }
    // SAFETY: out length is checked previously, input is a blst value.
    unsafe {
        blst_bendian_from_fp(out[PADDING_LENGTH..].as_mut_ptr(), input);
    }
}

/// Removes zeros with which the precompile inputs are left padded to 64 bytes.
fn remove_padding(input: &[u8]) -> Result<[u8; FP_LENGTH], PrecompileError> {
    if input.len() != PADDED_FP_LENGTH {
        return Err(PrecompileError::Other(format!(
            "Padded Input should be {PADDED_FP_LENGTH} bits, was {}",
            input.len()
        )));
    }
    if !input.iter().take(PADDING_LENGTH).all(|&x| x == 0) {
        return Err(PrecompileError::Other(format!(
            "{PADDING_LENGTH} top bytes of input are not zero",
        )));
    }

    let sliced = &input[PADDING_LENGTH..PADDED_FP_LENGTH];
    <[u8; FP_LENGTH]>::try_from(sliced).map_err(|e| PrecompileError::Other(format!("{e}")))
}

/// Extracts an Scalar from a 32 byte slice representation.
fn extract_scalar_input(input: &[u8]) -> Result<blst_scalar, PrecompileError> {
    if input.len() != SCALAR_LENGTH {
        return Err(PrecompileError::Other(format!(
            "Input should be {SCALAR_LENGTH} bits, was {}",
            input.len()
        )));
    }

    let mut out: blst_scalar = Default::default();
    // SAFETY: input length is checked previously, out is a blst value.
    unsafe {
        blst_scalar_from_bendian(&mut out, input.as_ptr());
    }

    Ok(out)
}

/// Extracts a G1 point in Affine format from a 128 byte slice representation.
fn extract_g1_input(
    out: *mut blst_p1_affine,
    input: &[u8],
) -> Result<*mut blst_p1_affine, PrecompileError> {
    if input.len() != G1_INPUT_ITEM_LENGTH {
        return Err(PrecompileError::Other(format!(
            "Input should be {G1_INPUT_ITEM_LENGTH} bits, was {}",
            input.len()
        )));
    }

    let input_p0_x = match remove_padding(&input[..PADDED_FP_LENGTH]) {
        Ok(input_p0_x) => input_p0_x,
        Err(e) => return Err(e),
    };
    let input_p0_y = match remove_padding(&input[PADDED_FP_LENGTH..G1_INPUT_ITEM_LENGTH]) {
        Ok(input_p0_y) => input_p0_y,
        Err(e) => return Err(e),
    };

    // SAFETY: input_p0_x and input_p0_y have fixed length, x and y are blst values.
    unsafe {
        blst_fp_from_bendian(&mut (*out).x, input_p0_x.as_ptr());
        blst_fp_from_bendian(&mut (*out).y, input_p0_y.as_ptr());
    }
    // SAFETY: out is a blst value.
    unsafe {
        if !blst_p1_affine_in_g1(out) {
            return Err(PrecompileError::Other("Element not in G1".to_string()));
        }
    }
    Ok(out)
}

/// Extracts a G2 point in Affine format from a 256 byte slice representation.
fn extract_g2_input(
    out: *mut blst_p2_affine,
    input: &[u8],
) -> Result<*mut blst_p2_affine, PrecompileError> {
    if input.len() != G2_INPUT_ITEM_LENGTH {
        return Err(PrecompileError::Other(format!(
            "Input should be {G2_INPUT_ITEM_LENGTH} bits, was {}",
            input.len()
        )));
    }

    let mut input_fps: [[u8; FP_LENGTH]; 4] = [[0; FP_LENGTH]; 4];
    for i in 0..4 {
        input_fps[i] =
            match remove_padding(&input[i * PADDED_FP_LENGTH..(i + 1) * PADDED_FP_LENGTH]) {
                Ok(fp_0) => fp_0,
                Err(e) => return Err(e),
            };
    }

    // SAFETY: items in fps have fixed length, out is a blst value.
    unsafe {
        blst_fp_from_bendian(&mut (*out).x.fp[0], input_fps[0].as_ptr());
        blst_fp_from_bendian(&mut (*out).x.fp[1], input_fps[1].as_ptr());
        blst_fp_from_bendian(&mut (*out).y.fp[0], input_fps[2].as_ptr());
        blst_fp_from_bendian(&mut (*out).y.fp[1], input_fps[3].as_ptr());
    }
    // SAFETY: out is a blst value.
    unsafe {
        if !blst_p2_affine_in_g2(out) {
            return Err(PrecompileError::Other("Element not in G2".to_string()));
        }
    }
    Ok(out)
}

/// G1 addition call expects `256` bytes as an input that is interpreted as byte
/// concatenation of two G1 points (`128` bytes each).
/// Output is an encoding of addition operation result - single G1 point (`128`
/// bytes).
/// See also: <https://eips.ethereum.org/EIPS/eip-2537#abi-for-g1-addition>
pub fn g1_add(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    if G1ADD_BASE > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }

    if input.len() != G1ADD_INPUT_LENGTH {
        return Err(PrecompileError::Other(format!(
            "G1ADD Input should be {G1ADD_INPUT_LENGTH} bits, was {}",
            input.len()
        )));
    }

    let mut a_aff: blst_p1_affine = Default::default();
    let a_aff = extract_g1_input(&mut a_aff, &input[..G1_INPUT_ITEM_LENGTH])?;

    let mut b_aff: blst_p1_affine = Default::default();
    let b_aff = extract_g1_input(&mut b_aff, &input[G1_INPUT_ITEM_LENGTH..])?;

    let mut b: blst_p1 = Default::default();
    // SAFETY: b and b_aff are blst values.
    unsafe {
        blst_p1_from_affine(&mut b, b_aff);
    }

    let mut p: blst_p1 = Default::default();
    // SAFETY: p, b and a_aff are blst values.
    unsafe {
        blst_p1_add_or_double_affine(&mut p, &b, a_aff);
    }

    let mut p_aff: blst_p1_affine = Default::default();
    // SAFETY: p_aff and p are blst values.
    unsafe {
        blst_p1_to_affine(&mut p_aff, &p);
    }

    let mut out = [0u8; G1_OUTPUT_LENGTH];
    encode_g1_point(&mut out, &p_aff);

    Ok((G1ADD_BASE, out.into()))
}

/// [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537#specification) BLS12_G1MUL precompile.
pub const BLS12_G1MUL: PrecompileWithAddress =
    PrecompileWithAddress(u64_to_address(BLS12_G1MUL_ADDRESS), Precompile::Standard(g1_mul));

/// G1 multiplication call expects `160` bytes as an input that is interpreted as
/// byte concatenation of encoding of G1 point (`128` bytes) and encoding of a
/// scalar value (`32` bytes).
/// Output is an encoding of multiplication operation result - single G1 point
/// (`128` bytes).
/// See also: <https://eips.ethereum.org/EIPS/eip-2537#abi-for-g1-multiplication>
pub fn g1_mul(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    if G1MUL_BASE > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }
    if input.len() != G1MUL_INPUT_LENGTH {
        return Err(PrecompileError::Other(format!(
            "G1MUL Input should be {G1MUL_INPUT_LENGTH} bits, was {}",
            input.len()
        )));
    }

    let mut p0_aff: blst_p1_affine = Default::default();
    let p0_aff = extract_g1_input(&mut p0_aff, &input[..G1_INPUT_ITEM_LENGTH])?;
    let mut p0: blst_p1 = Default::default();
    // SAFETY: p0 and p0_aff are blst values.
    unsafe {
        blst_p1_from_affine(&mut p0, p0_aff);
    }

    let input_scalar0 = extract_scalar_input(&input[G1_INPUT_ITEM_LENGTH..])?;

    let mut p: blst_p1 = Default::default();
    // SAFETY: input_scalar0.b has fixed size, p and p0 are blst values.
    unsafe {
        blst_p1_mult(&mut p, &p0, input_scalar0.b.as_ptr(), NBITS);
    }
    let mut p_aff: blst_p1_affine = Default::default();
    // SAFETY: p_aff and p are blst values.
    unsafe {
        blst_p1_to_affine(&mut p_aff, &p);
    }

    let mut out = [0u8; G1_OUTPUT_LENGTH];
    encode_g1_point(&mut out, &p_aff);

    Ok((G1MUL_BASE, out.into()))
}

/// [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537#specification) BLS12_G1MSM precompile.
pub const BLS12_G1MSM: PrecompileWithAddress =
    PrecompileWithAddress(u64_to_address(BLS12_G1MSM_ADDRESS), Precompile::Standard(g1_msm));

/// Implements the gas schedule for G1/G2 Multiscalar-multiplication assuming 30
/// MGas/second, see also: <https://eips.ethereum.org/EIPS/eip-2537#g1g2-multiexponentiation>
fn msm_required_gas(k: usize, multiplication_cost: u64) -> u64 {
    if k == 0 {
        return 0;
    }

    let discount = if k < MSM_DISCOUNT_TABLE.len() {
        MSM_DISCOUNT_TABLE[k - 1]
    } else {
        MSM_DISCOUNT_TABLE[MSM_DISCOUNT_TABLE.len() - 1]
    };

    (k as u64 * discount * multiplication_cost) / MSM_MULTIPLIER
}

/// Implements EIP-2537 G1MSM precompile.
/// G1 multi-scalar-multiplication call expects `160*k` bytes as an input that is interpreted
/// as byte concatenation of `k` slices each of them being a byte concatenation
/// of encoding of G1 point (`128` bytes) and encoding of a scalar value (`32`
/// bytes).
/// Output is an encoding of multi-scalar-multiplication operation result - single G1
/// point (`128` bytes).
/// See also: <https://eips.ethereum.org/EIPS/eip-2537#abi-for-g1-multiexponentiation>
fn g1_msm(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    let input_len = input.len();
    if input_len == 0 || input_len % G1MUL_INPUT_LENGTH != 0 {
        return Err(PrecompileError::Other(format!(
            "G1MSM input length should be multiple of {G1MUL_INPUT_LENGTH}, was {input_len}"
        )));
    }

    let k = input_len / G1MUL_INPUT_LENGTH;
    let required_gas = msm_required_gas(k, G1MUL_BASE);
    if required_gas > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }

    let mut g1_points: Vec<blst_p1> = Vec::with_capacity(k);
    let mut scalars: Vec<u8> = Vec::with_capacity(k * SCALAR_LENGTH);
    for i in 0..k {
        let mut p0_aff: blst_p1_affine = Default::default();
        let p0_aff = extract_g1_input(
            &mut p0_aff,
            &input[i * G1MUL_INPUT_LENGTH..i * G1MUL_INPUT_LENGTH + G1_INPUT_ITEM_LENGTH],
        )?;
        let mut p0: blst_p1 = Default::default();
        // SAFETY: p0 and p0_aff are blst values.
        unsafe {
            blst_p1_from_affine(&mut p0, p0_aff);
        }

        g1_points.push(p0);

        scalars.extend_from_slice(
            &extract_scalar_input(
                &input[i * G1MUL_INPUT_LENGTH + G1_INPUT_ITEM_LENGTH
                    ..i * G1MUL_INPUT_LENGTH + G1_INPUT_ITEM_LENGTH + SCALAR_LENGTH],
            )?
            .b,
        );
    }

    let points = p1_affines::from(&g1_points);
    let multiexp = points.mult(&scalars, NBITS);

    let mut multiexp_aff: blst_p1_affine = Default::default();
    // SAFETY: multiexp_aff and multiexp are blst values.
    unsafe {
        blst_p1_to_affine(&mut multiexp_aff, &multiexp);
    }

    let mut out = [0u8; G1_OUTPUT_LENGTH];
    encode_g1_point(&mut out, &multiexp_aff);

    Ok((required_gas, out.into()))
}

/// [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537#specification) BLS12_G2ADD precompile.
pub const BLS12_G2ADD: PrecompileWithAddress =
    PrecompileWithAddress(u64_to_address(BLS12_G2ADD_ADDRESS), Precompile::Standard(g2_add));

/// G2 addition call expects `512` bytes as an input that is interpreted as byte
/// concatenation of two G2 points (`256` bytes each).
///
/// Output is an encoding of addition operation result - single G2 point (`256`
/// bytes).
/// See also <https://eips.ethereum.org/EIPS/eip-2537#abi-for-g2-addition>
fn g2_add(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    if G2ADD_BASE > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }

    if input.len() != G2ADD_INPUT_LENGTH {
        return Err(PrecompileError::Other(format!(
            "G2ADD Input should be {G2ADD_INPUT_LENGTH} bits, was {}",
            input.len()
        )));
    }

    let mut a_aff: blst_p2_affine = Default::default();
    let a_aff = extract_g2_input(&mut a_aff, &input[..G2_INPUT_ITEM_LENGTH])?;

    let mut b_aff: blst_p2_affine = Default::default();
    let b_aff = extract_g2_input(&mut b_aff, &input[G2_INPUT_ITEM_LENGTH..])?;

    let mut b: blst_p2 = Default::default();
    // SAFETY: b and b_aff are blst values.
    unsafe {
        blst_p2_from_affine(&mut b, b_aff);
    }

    let mut p: blst_p2 = Default::default();
    // SAFETY: p, b and a_aff are blst values.
    unsafe {
        blst_p2_add_or_double_affine(&mut p, &b, a_aff);
    }

    let mut p_aff: blst_p2_affine = Default::default();
    // SAFETY: p_aff and p are blst values.
    unsafe {
        blst_p2_to_affine(&mut p_aff, &p);
    }

    let mut out = [0u8; G2_OUTPUT_LENGTH];
    encode_g2_point(&mut out, &p_aff);

    Ok((G2ADD_BASE, out.into()))
}

/// [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537#specification) BLS12_G2MUL precompile.
pub const BLS12_G2MUL: PrecompileWithAddress =
    PrecompileWithAddress(u64_to_address(BLS12_G2MUL_ADDRESS), Precompile::Standard(g2_mul));

/// G2 multiplication call expects `288` bytes as an input that is interpreted as
/// byte concatenation of encoding of G2 point (`256` bytes) and encoding of a
/// scalar value (`32` bytes).
/// Output is an encoding of multiplication operation result - single G2 point
/// (`256` bytes).
/// See also: <https://eips.ethereum.org/EIPS/eip-2537#abi-for-g2-multiplication>
fn g2_mul(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    if G2MUL_BASE > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }
    if input.len() != G2MUL_INPUT_LENGTH {
        return Err(PrecompileError::Other(format!(
            "G2MUL Input should be {G2MUL_INPUT_LENGTH} bits, was {}",
            input.len()
        )));
    }

    let mut p0_aff: blst_p2_affine = Default::default();
    let p0_aff = extract_g2_input(&mut p0_aff, &input[..G2_INPUT_ITEM_LENGTH])?;
    let mut p0: blst_p2 = Default::default();
    // SAFETY: p0 and p0_aff are blst values.
    unsafe {
        blst_p2_from_affine(&mut p0, p0_aff);
    }

    let input_scalar0 = extract_scalar_input(&input[G2_INPUT_ITEM_LENGTH..])?;

    let mut p: blst_p2 = Default::default();
    // SAFETY: input_scalar0.b has fixed size, p and p0 are blst values.
    unsafe {
        blst_p2_mult(&mut p, &p0, input_scalar0.b.as_ptr(), NBITS);
    }
    let mut p_aff: blst_p2_affine = Default::default();
    // SAFETY: p_aff and p are blst values.
    unsafe {
        blst_p2_to_affine(&mut p_aff, &p);
    }

    let mut out = [0u8; G2_OUTPUT_LENGTH];
    encode_g2_point(&mut out, &p_aff);

    Ok((G2MUL_BASE, out.into()))
}

/// [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537#specification) BLS12_G2MSM precompile.
pub const BLS12_G2MSM: PrecompileWithAddress =
    PrecompileWithAddress(u64_to_address(BLS12_G2MSM_ADDRESS), Precompile::Standard(g2_msm));

/// Implements EIP-2537 G2MSM precompile.
/// G2 multi-scalar-multiplication call expects `288*k` bytes as an input that is interpreted
/// as byte concatenation of `k` slices each of them being a byte concatenation
/// of encoding of G2 point (`256` bytes) and encoding of a scalar value (`32`
/// bytes).
/// Output is an encoding of multi-scalar-multiplication operation result - single G2
/// point (`256` bytes).
/// See also: <https://eips.ethereum.org/EIPS/eip-2537#abi-for-g2-multiexponentiation>
fn g2_msm(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    let input_len = input.len();
    if input_len == 0 || input_len % G2MUL_INPUT_LENGTH != 0 {
        return Err(PrecompileError::Other(format!(
            "G2MSM input length should be multiple of {G2MUL_INPUT_LENGTH}, was {input_len}"
        )));
    }

    let k = input_len / G2MUL_INPUT_LENGTH;
    let required_gas = msm_required_gas(k, G2MUL_BASE);
    if required_gas > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }

    let mut g2_points: Vec<blst_p2> = Vec::with_capacity(k);
    let mut scalars: Vec<u8> = Vec::with_capacity(k * SCALAR_LENGTH);
    for i in 0..k {
        let mut p0_aff: blst_p2_affine = Default::default();
        let p0_aff = extract_g2_input(
            &mut p0_aff,
            &input[i * G2MUL_INPUT_LENGTH..i * G2MUL_INPUT_LENGTH + G2_INPUT_ITEM_LENGTH],
        )?;
        let mut p0: blst_p2 = Default::default();
        // SAFETY: p0 and p0_aff are blst values.
        unsafe {
            blst_p2_from_affine(&mut p0, p0_aff);
        }

        g2_points.push(p0);

        scalars.extend_from_slice(
            &extract_scalar_input(
                &input[i * G2MUL_INPUT_LENGTH + G2_INPUT_ITEM_LENGTH
                    ..i * G2MUL_INPUT_LENGTH + G2_INPUT_ITEM_LENGTH + SCALAR_LENGTH],
            )?
            .b,
        );
    }

    let points = p2_affines::from(&g2_points);
    let multiexp = points.mult(&scalars, NBITS);

    let mut multiexp_aff: blst_p2_affine = Default::default();
    // SAFETY: multiexp_aff and multiexp are blst values.
    unsafe {
        blst_p2_to_affine(&mut multiexp_aff, &multiexp);
    }

    let mut out = [0u8; G2_OUTPUT_LENGTH];
    encode_g2_point(&mut out, &multiexp_aff);

    Ok((required_gas, out.into()))
}

/// [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537#specification) BLS12_PAIRING precompile.
pub const BLS12_PAIRING: PrecompileWithAddress =
    PrecompileWithAddress(u64_to_address(BLS12_PAIRING_ADDRESS), Precompile::Standard(pairing));

/// Pairing call expects 384*k (k being a positive integer) bytes as an inputs
/// that is interpreted as byte concatenation of k slices. Each slice has the
/// following structure:
///    * 128 bytes of G1 point encoding
///    * 256 bytes of G2 point encoding
/// Each point is expected to be in the subgroup of order q.
/// Output is a 32 bytes where first 31 bytes are equal to 0x00 and the last byte
/// is 0x01 if pairing result is equal to the multiplicative identity in a pairing
/// target field and 0x00 otherwise.
/// See also: <https://eips.ethereum.org/EIPS/eip-2537#abi-for-pairing>
fn pairing(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    let input_len = input.len();
    if input_len == 0 || input_len % PAIRING_INPUT_LENGTH != 0 {
        return Err(PrecompileError::Other(format!(
            "Pairing input length should be multiple of {PAIRING_INPUT_LENGTH}, was {input_len}"
        )));
    }

    let k = input_len / PAIRING_INPUT_LENGTH;
    let required_gas: u64 = PAIRING_MULTIPLIER_BASE * k as u64 + PAIRING_OFFSET_BASE;
    if required_gas > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }

    let mut ret: blst_fp12 = Default::default();
    for i in 0..k {
        let mut p1_aff: blst_p1_affine = Default::default();
        let p1_aff = extract_g1_input(
            &mut p1_aff,
            &input[i * PAIRING_INPUT_LENGTH..i * PAIRING_INPUT_LENGTH + G1_INPUT_ITEM_LENGTH],
        )? as *const blst_p1_affine;
        let mut p2_aff: blst_p2_affine = Default::default();
        let p2_aff = extract_g2_input(
            &mut p2_aff,
            &input[i * PAIRING_INPUT_LENGTH + G1_INPUT_ITEM_LENGTH
                ..i * PAIRING_INPUT_LENGTH + G1_INPUT_ITEM_LENGTH + G2_INPUT_ITEM_LENGTH],
        )? as *const blst_p2_affine;
        if i > 0 {
            // after the first slice (i>0) we use cur_ml to store the current
            // miller loop and accumulate with the previous results using a fp12
            // multiplication.
            let mut cur_ml: blst_fp12 = Default::default();
            // SAFETY: ret, cur_ml, p1_aff and p2_aff are blst values.
            unsafe {
                blst_miller_loop(&mut cur_ml, p2_aff, p1_aff);
                blst_fp12_mul(&mut ret, &ret, &cur_ml);
            }
        } else {
            // on the first slice (i==0) there is no previous results and no need
            // to accumulate.
            // SAFETY: ret, p1_aff and p2_aff are blst values.
            unsafe {
                blst_miller_loop(&mut ret, p2_aff, p1_aff);
            }
        }
    }
    // SAFETY: ret is  blst value.
    unsafe {
        blst_final_exp(&mut ret, &ret);
    }

    let mut result: u8 = 0;
    // SAFETY: ret is a blst value.
    unsafe {
        if blst_fp12_is_one(&ret) {
            result = 1;
        }
    }
    Ok((required_gas, B256::with_last_byte(result).into()))
}

/// [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537#specification) BLS12_MAP_FP_TO_G1 precompile.
pub const BLS12_MAP_FP_TO_G1: PrecompileWithAddress = PrecompileWithAddress(
    u64_to_address(BLS12_MAP_FP_TO_G1_ADDRESS),
    Precompile::Standard(map_fp_to_g1),
);

/// Field-to-curve call expects 64 bytes as an input that is interpreted as an
/// element of Fp. Output of this call is 128 bytes and is an encoded G1 point.
/// See also: <https://eips.ethereum.org/EIPS/eip-2537#abi-for-mapping-fp-element-to-g1-point>
fn map_fp_to_g1(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    if MAP_FP_TO_G1_BASE > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }

    if input.len() != PADDED_FP_LENGTH {
        return Err(PrecompileError::Other(format!(
            "MAP_FP_TO_G1 Input should be {PADDED_FP_LENGTH} bits, was {}",
            input.len()
        )));
    }

    let input_p0 = match remove_padding(input) {
        Ok(input_p0) => input_p0,
        Err(e) => return Err(e),
    };

    let mut fp: blst_fp = Default::default();

    // SAFETY: input_p0 has fixed length, fp is a blst value.
    unsafe {
        blst_fp_from_bendian(&mut fp, input_p0.as_ptr());
    }

    let mut p: blst_p1 = Default::default();
    // SAFETY: p and fp are blst values.
    unsafe {
        // third argument is unused if null.
        blst_map_to_g1(&mut p, &fp, std::ptr::null());
    }

    let mut p_aff: blst_p1_affine = Default::default();
    // SAFETY: p_aff and p are blst values.
    unsafe {
        blst_p1_to_affine(&mut p_aff, &p);
    }

    let mut out = [0u8; G1_OUTPUT_LENGTH];
    encode_g1_point(&mut out, &p_aff);

    Ok((MAP_FP_TO_G1_BASE, out.into()))
}

/// [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537#specification) BLS12_MAP_FP2_TO_G2 precompile.
pub const BLS12_MAP_FP2_TO_G2: PrecompileWithAddress = PrecompileWithAddress(
    u64_to_address(BLS12_MAP_FP2_TO_G2_ADDRESS),
    Precompile::Standard(map_fp2_to_g2),
);

/// Field-to-curve call expects 128 bytes as an input that is interpreted as a
/// an element of Fp2. Output of this call is 256 bytes and is an encoded G2
/// point.
/// See also: <https://eips.ethereum.org/EIPS/eip-2537#abi-for-mapping-fp2-element-to-g2-point>
fn map_fp2_to_g2(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    if MAP_FP2_TO_G2_BASE > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }

    if input.len() != PADDED_FP2_LENGTH {
        return Err(PrecompileError::Other(format!(
            "MAP_FP2_TO_G2 Input should be {PADDED_FP2_LENGTH} bits, was {}",
            input.len()
        )));
    }

    let input_p0_x = match remove_padding(&input[..PADDED_FP_LENGTH]) {
        Ok(input_p0_x) => input_p0_x,
        Err(e) => return Err(e),
    };
    let input_p0_y = match remove_padding(&input[PADDED_FP_LENGTH..PADDED_FP2_LENGTH]) {
        Ok(input_p0_y) => input_p0_y,
        Err(e) => return Err(e),
    };

    let mut fp2: blst_fp2 = Default::default();
    let mut fp_x: blst_fp = Default::default();
    let mut fp_y: blst_fp = Default::default();
    // SAFETY: input_p0_x has fixed length, fp_x is a blst value.
    unsafe {
        blst_fp_from_bendian(&mut fp_x, input_p0_x.as_ptr());
    }
    // SAFETY: input_p0_y has fixed length, fp_y is a blst value.
    unsafe {
        blst_fp_from_bendian(&mut fp_y, input_p0_y.as_ptr());
    }
    fp2.fp[0] = fp_x;
    fp2.fp[1] = fp_y;

    let mut p: blst_p2 = Default::default();
    // SAFETY: p and fp2 are blst values.
    unsafe {
        // third argument is unused if null.
        blst_map_to_g2(&mut p, &fp2, std::ptr::null());
    }

    let mut p_aff: blst_p2_affine = Default::default();
    // SAFETY: p_aff and p are blst values.
    unsafe {
        blst_p2_to_affine(&mut p_aff, &p);
    }

    let mut out = [0u8; G2_OUTPUT_LENGTH];
    encode_g2_point(&mut out, &p_aff);

    Ok((MAP_FP2_TO_G2_BASE, out.into()))
}

#[cfg(test)]
mod test {
    use super::*;
    use eyre::Result;
    use revm_primitives::hex::FromHex;
    use rstest::rstest;
    use serde_derive::{Deserialize, Serialize};
    use std::{fs, path::Path};

    #[derive(Serialize, Deserialize, Debug)]
    struct TestVector {
        input: String,
        expected: String,
        name: String,
        gas: u64,
        error: bool,
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct TestVectors(Vec<TestVector>);

    fn load_test_vectors<P: AsRef<Path>>(path: P) -> Result<TestVectors> {
        let file_contents = fs::read_to_string(path)?;
        Ok(serde_json::from_str(&file_contents)?)
    }

    #[rstest]
    #[case::g1_add(g1_add, "blsG1Add.json")]
    #[case::g1_mul(g1_mul, "blsG1Mul.json")]
    #[case::g1_msm(g1_msm, "blsG1MSM.json")]
    #[case::g2_add(g2_add, "blsG2Add.json")]
    #[case::g2_mul(g2_mul, "blsG2Mul.json")]
    #[case::g2_msm(g2_msm, "blsG2MSM.json")]
    #[case::pairing(pairing, "blsPairing.json")]
    #[case::map_fp_to_g1(map_fp_to_g1, "blsMapG1.json")]
    #[case::map_fp2_to_g2(map_fp2_to_g2, "blsMapG2.json")]
    fn test_bls(
        #[case] precompile: fn(input: &Bytes, gas_limit: u64) -> PrecompileResult,
        #[case] file_name: &str,
    ) {
        let test_vectors = load_test_vectors(format!("test-vectors/{file_name}"))
            .unwrap_or_else(|e| panic!("Failed to load test vectors from {file_name}: {e}"));

        for vector in test_vectors.0 {
            let test_name = format!("{file_name}/{}", vector.name);
            let input = Bytes::from_hex(vector.input.clone()).unwrap_or_else(|e| {
                panic!("could not deserialize input {} as hex in {test_name}: {e}", &vector.input)
            });
            let target_gas: u64 = 30_000_000;
            let res = precompile(&input, target_gas);
            if vector.error {
                assert!(res.is_err(), "expected error didn't happen in {test_name}");
            } else {
                let (actual_gas, actual_output) =
                    res.unwrap_or_else(|e| panic!("precompile call failed for {test_name}: {e}"));
                assert_eq!(
                    vector.gas, actual_gas,
                    "expected gas: {}, actual gas: {} in {test_name}",
                    vector.gas, actual_gas
                );
                let expected_output = Bytes::from_hex(vector.expected).unwrap();
                assert_eq!(
                    expected_output, actual_output,
                    "expected output: {expected_output}, actual output: {actual_output} in {test_name}");
            }
        }
    }

    #[rstest]
    #[case::g1_empty(0, G1MUL_BASE, 0)]
    #[case::g1_one_item(160, G1MUL_BASE, 14400)]
    #[case::g1_two_items(320, G1MUL_BASE, 21312)]
    #[case::g1_ten_items(1600, G1MUL_BASE, 50760)]
    #[case::g1_sixty_four_items(10240, G1MUL_BASE, 170496)]
    #[case::g1_one_hundred_twenty_eight_items(20480, G1MUL_BASE, 267264)]
    #[case::g1_one_hundred_twenty_nine_items(20640, G1MUL_BASE, 269352)]
    #[case::g1_two_hundred_fifty_six_items(40960, G1MUL_BASE, 534528)]
    fn test_g1_multiexp_required_gas(
        #[case] input_len: usize,
        #[case] multiplication_cost: u64,
        #[case] expected_output: u64,
    ) {
        let k = input_len / G1MUL_INPUT_LENGTH;

        let actual_output = msm_required_gas(k, multiplication_cost);

        assert_eq!(expected_output, actual_output);
    }
}
