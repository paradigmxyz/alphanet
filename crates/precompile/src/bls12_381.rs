use crate::addresses::{
    BLS12_G1ADD_ADDRESS, BLS12_G1MULTIEXP_ADDRESS, BLS12_G1MUL_ADDRESS, BLS12_G2ADD_ADDRESS,
    BLS12_G2MULTIEXP_ADDRESS, BLS12_G2MUL_ADDRESS, BLS12_MAP_FP2_TO_G2_ADDRESS,
    BLS12_MAP_FP_TO_G1_ADDRESS, BLS12_PAIRING_ADDRESS,
};
use revm_precompile::{Precompile, PrecompileWithAddress};
use revm_primitives::{Bytes, PrecompileError, PrecompileResult, B256};

/// [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537#specification) BLS12_G1ADD precompile.
pub const BLS12_G1ADD: PrecompileWithAddress =
    PrecompileWithAddress(crate::u64_to_address(BLS12_G1ADD_ADDRESS), Precompile::Standard(g1_add));

fn g1_add(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    const G1ADD_BASE: u64 = 500;
    if G1ADD_BASE > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }
    let result = g1_add_impl(input).is_some();
    Ok((G1ADD_BASE, B256::with_last_byte(result as u8).into()))
}

fn g1_add_impl(_input: &[u8]) -> Option<()> {
    None
}

/// [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537#specification) BLS12_G1MUL precompile.
pub const BLS12_G1MUL: PrecompileWithAddress =
    PrecompileWithAddress(crate::u64_to_address(BLS12_G1MUL_ADDRESS), Precompile::Standard(g1_mul));

fn g1_mul(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    const G1MUL_BASE: u64 = 12000;
    if G1MUL_BASE > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }
    let result = g1_mul_impl(input).is_some();
    Ok((G1MUL_BASE, B256::with_last_byte(result as u8).into()))
}

fn g1_mul_impl(_input: &[u8]) -> Option<()> {
    None
}

/// [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537#specification) BLS12_G1MULTIEXP precompile.
pub const BLS12_G1MULTIEXP: PrecompileWithAddress = PrecompileWithAddress(
    crate::u64_to_address(BLS12_G1MULTIEXP_ADDRESS),
    Precompile::Standard(g1_multiexp),
);

fn g1_multiexp(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    // TODO: make gas base depend on input k
    const G1MULTIEXP_BASE: u64 = 12000;
    if G1MULTIEXP_BASE > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }
    let result = g1_multiexp_impl(input).is_some();
    Ok((G1MULTIEXP_BASE, B256::with_last_byte(result as u8).into()))
}

fn g1_multiexp_impl(_input: &[u8]) -> Option<()> {
    None
}

/// [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537#specification) BLS12_G2ADD precompile.
pub const BLS12_G2ADD: PrecompileWithAddress =
    PrecompileWithAddress(crate::u64_to_address(BLS12_G2ADD_ADDRESS), Precompile::Standard(g2_add));

fn g2_add(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    const G2ADD_BASE: u64 = 800;
    if G2ADD_BASE > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }
    let result = g2_add_impl(input).is_some();
    Ok((G2ADD_BASE, B256::with_last_byte(result as u8).into()))
}

fn g2_add_impl(_input: &[u8]) -> Option<()> {
    None
}

/// [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537#specification) BLS12_G2MUL precompile.
pub const BLS12_G2MUL: PrecompileWithAddress =
    PrecompileWithAddress(crate::u64_to_address(BLS12_G2MUL_ADDRESS), Precompile::Standard(g2_mul));

fn g2_mul(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    const G2MUL_BASE: u64 = 45000;
    if G2MUL_BASE > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }
    let result = g2_mul_impl(input).is_some();
    Ok((G2MUL_BASE, B256::with_last_byte(result as u8).into()))
}

fn g2_mul_impl(_input: &[u8]) -> Option<()> {
    None
}

/// [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537#specification) BLS12_G2MULTIEXP precompile.
pub const BLS12_G2MULTIEXP: PrecompileWithAddress = PrecompileWithAddress(
    crate::u64_to_address(BLS12_G2MULTIEXP_ADDRESS),
    Precompile::Standard(g2_multiexp),
);

fn g2_multiexp(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    // TODO: make gas base depend on input k
    const G2MULTIEXP_BASE: u64 = 12000;
    if G2MULTIEXP_BASE > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }
    let result = g2_multiexp_impl(input).is_some();
    Ok((G2MULTIEXP_BASE, B256::with_last_byte(result as u8).into()))
}

fn g2_multiexp_impl(_input: &[u8]) -> Option<()> {
    None
}

/// [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537#specification) BLS12_PAIRING precompile.
pub const BLS12_PAIRING: PrecompileWithAddress = PrecompileWithAddress(
    crate::u64_to_address(BLS12_PAIRING_ADDRESS),
    Precompile::Standard(pairing),
);

fn pairing(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    // TODO: make gas base depend on input k
    const PAIRING_BASE: u64 = 12000;
    if PAIRING_BASE > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }
    let result = pairing_impl(input).is_some();
    Ok((PAIRING_BASE, B256::with_last_byte(result as u8).into()))
}

fn pairing_impl(_input: &[u8]) -> Option<()> {
    None
}

/// [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537#specification) BLS12_MAP_FP_TO_G1 precompile.
pub const BLS12_MAP_FP_TO_G1: PrecompileWithAddress = PrecompileWithAddress(
    crate::u64_to_address(BLS12_MAP_FP_TO_G1_ADDRESS),
    Precompile::Standard(map_fp_to_g1),
);

fn map_fp_to_g1(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    // TODO: make gas base depend on input k
    const MAP_FP_TO_G1_BASE: u64 = 12000;
    if MAP_FP_TO_G1_BASE > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }
    let result = map_fp_to_g1_impl(input).is_some();
    Ok((MAP_FP_TO_G1_BASE, B256::with_last_byte(result as u8).into()))
}

fn map_fp_to_g1_impl(_input: &[u8]) -> Option<()> {
    None
}

/// [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537#specification) BLS12_MAP_FP2_TO_G2 precompile.
pub const BLS12_MAP_FP2_TO_G2: PrecompileWithAddress = PrecompileWithAddress(
    crate::u64_to_address(BLS12_MAP_FP2_TO_G2_ADDRESS),
    Precompile::Standard(map_fp2_to_g2),
);

fn map_fp2_to_g2(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    // TODO: make gas base depend on input k
    const MAP_FP2_TO_G2_BASE: u64 = 12000;
    if MAP_FP2_TO_G2_BASE > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }
    let result = map_fp2_to_g2_impl(input).is_some();
    Ok((MAP_FP2_TO_G2_BASE, B256::with_last_byte(result as u8).into()))
}

fn map_fp2_to_g2_impl(_input: &[u8]) -> Option<()> {
    None
}

#[cfg(test)]
mod test {}
