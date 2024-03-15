use revm_precompile::{Precompile, PrecompileWithAddress};
use revm_primitives::{Bytes, PrecompileError, PrecompileResult, B256};

/// [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537#specification) BLS12_G1ADD precompile.
pub const BLS12_G1ADD: PrecompileWithAddress =
    PrecompileWithAddress(crate::u64_to_address(0x0b), Precompile::Standard(g1_add));

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

#[cfg(test)]
mod test {}
