use crate::addresses::{
    BLS12_G1ADD_ADDRESS, BLS12_G1MULTIEXP_ADDRESS, BLS12_G1MUL_ADDRESS, BLS12_G2ADD_ADDRESS,
    BLS12_G2MULTIEXP_ADDRESS, BLS12_G2MUL_ADDRESS, BLS12_MAP_FP2_TO_G2_ADDRESS,
    BLS12_MAP_FP_TO_G1_ADDRESS, BLS12_PAIRING_ADDRESS,
};
use bls12_381::{G1Affine, G1Projective};
use revm_precompile::{Precompile, PrecompileWithAddress};
use revm_primitives::{Bytes, PrecompileError, PrecompileResult, B256};
use std::ops::Add;

const G1ADD_BASE: u64 = 500;
const INPUT_LENGTH: usize = 256;
const OUTPUT_LENGTH: usize = 128;
const FP_LEGTH: usize = 48;
const PADDED_INPUT_LENGTH: usize = 64;
const PADDING_LEGTH: usize = 16;

/// [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537#specification) BLS12_G1ADD precompile.
pub const BLS12_G1ADD: PrecompileWithAddress =
    PrecompileWithAddress(crate::u64_to_address(BLS12_G1ADD_ADDRESS), Precompile::Standard(g1_add));

// Removes zeros with which the precompile inputs are left padded to 64 bytes.
fn remove_padding(input: &[u8]) -> Result<[u8; FP_LEGTH], PrecompileError> {
    if input.len() != PADDED_INPUT_LENGTH {
        return Err(PrecompileError::Other(format!(
            "Padded Input should be {PADDED_INPUT_LENGTH} bits, was {}",
            input.len()
        )));
    }
    let sliced = &input[PADDING_LEGTH..PADDED_INPUT_LENGTH];
    <[u8; FP_LEGTH]>::try_from(sliced).map_err(|e| PrecompileError::Other(format!("{e}")))
}

// Adds left pad with zeros to each FP element so that the output lenght matches
// 128 bytes.
fn add_padding(input: [u8; 96]) -> [u8; OUTPUT_LENGTH] {
    let mut output = [0u8; OUTPUT_LENGTH];

    output[PADDING_LEGTH..PADDED_INPUT_LENGTH].copy_from_slice(&input[..FP_LEGTH]);
    output[(PADDED_INPUT_LENGTH + PADDING_LEGTH)..].copy_from_slice(&input[FP_LEGTH..]);

    output
}

fn extract_input(input: &[u8]) -> Result<[u8; 96], PrecompileError> {
    if input.len() != INPUT_LENGTH / 2 {
        return Err(PrecompileError::Other(format!(
            "Padded Input should be {PADDED_INPUT_LENGTH} bits, was {}",
            input.len()
        )));
    }

    let input_p0_x = match remove_padding(&input[..64]) {
        Ok(input_p0_x) => input_p0_x,
        Err(e) => return Err(e),
    };
    let input_p0_y = match remove_padding(&input[64..128]) {
        Ok(input_p0_y) => input_p0_y,
        Err(e) => return Err(e),
    };
    let mut input_p0: [u8; 96] = [0; 96];
    input_p0[..48].copy_from_slice(&input_p0_x);
    input_p0[48..].copy_from_slice(&input_p0_y);

    Ok(input_p0)
}

fn g1_add(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    if G1ADD_BASE > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }

    if input.len() != INPUT_LENGTH {
        return Err(PrecompileError::Other(format!(
            "G1ADD Input should be {INPUT_LENGTH} bits, was {}",
            input.len()
        )));
    }

    let input_p0 = extract_input(&input[..128])?;
    let p0 = G1Affine::from_uncompressed(&input_p0);
    if (!p0.is_some()).into() {
        return Err(PrecompileError::Other("p0 was not a valid elliptic curve point".to_string()));
    }

    let input_p1 = extract_input(&input[128..])?;
    let p1 = G1Affine::from_uncompressed(&input_p1);
    if (!p1.is_some()).into() {
        return Err(PrecompileError::Other("p1 was not a valid elliptic curve point".to_string()));
    }

    let p1_projective: G1Projective = p1.unwrap().into();
    let out = p0.unwrap().add(p1_projective);
    let out: G1Affine = out.into();
    let out_bytes = add_padding(out.to_uncompressed());

    Ok((G1ADD_BASE, out_bytes.into()))
}

/// [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537#specification) BLS12_G1MUL precompile.
pub const BLS12_G1MUL: PrecompileWithAddress =
    PrecompileWithAddress(crate::u64_to_address(BLS12_G1MUL_ADDRESS), Precompile::Standard(g1_mul));

fn g1_mul(_input: &Bytes, gas_limit: u64) -> PrecompileResult {
    const G1MUL_BASE: u64 = 12000;
    if G1MUL_BASE > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }
    let result = 1;
    Ok((G1MUL_BASE, B256::with_last_byte(result as u8).into()))
}

/// [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537#specification) BLS12_G1MULTIEXP precompile.
pub const BLS12_G1MULTIEXP: PrecompileWithAddress = PrecompileWithAddress(
    crate::u64_to_address(BLS12_G1MULTIEXP_ADDRESS),
    Precompile::Standard(g1_multiexp),
);

fn g1_multiexp(_input: &Bytes, gas_limit: u64) -> PrecompileResult {
    // TODO: make gas base depend on input k
    const G1MULTIEXP_BASE: u64 = 12000;
    if G1MULTIEXP_BASE > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }
    let result = 1;
    Ok((G1MULTIEXP_BASE, B256::with_last_byte(result as u8).into()))
}

/// [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537#specification) BLS12_G2ADD precompile.
pub const BLS12_G2ADD: PrecompileWithAddress =
    PrecompileWithAddress(crate::u64_to_address(BLS12_G2ADD_ADDRESS), Precompile::Standard(g2_add));

fn g2_add(_input: &Bytes, gas_limit: u64) -> PrecompileResult {
    const G2ADD_BASE: u64 = 800;
    if G2ADD_BASE > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }
    let result = 1;
    Ok((G2ADD_BASE, B256::with_last_byte(result as u8).into()))
}

/// [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537#specification) BLS12_G2MUL precompile.
pub const BLS12_G2MUL: PrecompileWithAddress =
    PrecompileWithAddress(crate::u64_to_address(BLS12_G2MUL_ADDRESS), Precompile::Standard(g2_mul));

fn g2_mul(_input: &Bytes, gas_limit: u64) -> PrecompileResult {
    const G2MUL_BASE: u64 = 45000;
    if G2MUL_BASE > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }
    let result = 1;
    Ok((G2MUL_BASE, B256::with_last_byte(result as u8).into()))
}

/// [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537#specification) BLS12_G2MULTIEXP precompile.
pub const BLS12_G2MULTIEXP: PrecompileWithAddress = PrecompileWithAddress(
    crate::u64_to_address(BLS12_G2MULTIEXP_ADDRESS),
    Precompile::Standard(g2_multiexp),
);

fn g2_multiexp(_input: &Bytes, gas_limit: u64) -> PrecompileResult {
    // TODO: make gas base depend on input k
    const G2MULTIEXP_BASE: u64 = 12000;
    if G2MULTIEXP_BASE > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }
    let result = 1;
    Ok((G2MULTIEXP_BASE, B256::with_last_byte(result as u8).into()))
}

/// [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537#specification) BLS12_PAIRING precompile.
pub const BLS12_PAIRING: PrecompileWithAddress = PrecompileWithAddress(
    crate::u64_to_address(BLS12_PAIRING_ADDRESS),
    Precompile::Standard(pairing),
);

fn pairing(_input: &Bytes, gas_limit: u64) -> PrecompileResult {
    // TODO: make gas base depend on input k
    const PAIRING_BASE: u64 = 12000;
    if PAIRING_BASE > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }
    let result = 1;
    Ok((PAIRING_BASE, B256::with_last_byte(result as u8).into()))
}

/// [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537#specification) BLS12_MAP_FP_TO_G1 precompile.
pub const BLS12_MAP_FP_TO_G1: PrecompileWithAddress = PrecompileWithAddress(
    crate::u64_to_address(BLS12_MAP_FP_TO_G1_ADDRESS),
    Precompile::Standard(map_fp_to_g1),
);

fn map_fp_to_g1(_input: &Bytes, gas_limit: u64) -> PrecompileResult {
    // TODO: make gas base depend on input k
    const MAP_FP_TO_G1_BASE: u64 = 12000;
    if MAP_FP_TO_G1_BASE > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }
    let result = 1;
    Ok((MAP_FP_TO_G1_BASE, B256::with_last_byte(result as u8).into()))
}

/// [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537#specification) BLS12_MAP_FP2_TO_G2 precompile.
pub const BLS12_MAP_FP2_TO_G2: PrecompileWithAddress = PrecompileWithAddress(
    crate::u64_to_address(BLS12_MAP_FP2_TO_G2_ADDRESS),
    Precompile::Standard(map_fp2_to_g2),
);

fn map_fp2_to_g2(_input: &Bytes, gas_limit: u64) -> PrecompileResult {
    // TODO: make gas base depend on input k
    const MAP_FP2_TO_G2_BASE: u64 = 12000;
    if MAP_FP2_TO_G2_BASE > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }
    let result = 1;
    Ok((MAP_FP2_TO_G2_BASE, B256::with_last_byte(result as u8).into()))
}

#[cfg(test)]
mod test {
    use super::*;
    use revm_primitives::hex::FromHex;
    use rstest::rstest;

    #[rstest]
    // test vectors from https://github.com/ethereum/go-ethereum/blob/master/core/vm/testdata/precompiles/blsG1Add.json and https://github.com/ethereum/go-ethereum/blob/master/core/vm/testdata/precompiles/fail-blsG1Add.json
    #[case::g1_plus_g1_equals_two_times_g1("0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e10000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1", "000000000000000000000000000000000572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e00000000000000000000000000000000166a9d8cabc673a322fda673779d8e3822ba3ecb8670e461f73bb9021d5fd76a4c56d9d4cd16bd1bba86881979749d28", false, 500)]
    #[case::two_times_g1_plus_three_times_g1_equals_five_times_g1("000000000000000000000000000000000572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e00000000000000000000000000000000166a9d8cabc673a322fda673779d8e3822ba3ecb8670e461f73bb9021d5fd76a4c56d9d4cd16bd1bba86881979749d280000000000000000000000000000000009ece308f9d1f0131765212deca99697b112d61f9be9a5f1f3780a51335b3ff981747a0b2ca2179b96d2c0c9024e522400000000000000000000000000000000032b80d3a6f5b09f8a84623389c5f80ca69a0cddabc3097f9d9c27310fd43be6e745256c634af45ca3473b0590ae30d1", "0000000000000000000000000000000010e7791fb972fe014159aa33a98622da3cdc98ff707965e536d8636b5fcc5ac7a91a8c46e59a00dca575af0f18fb13dc0000000000000000000000000000000016ba437edcc6551e30c10512367494bfb6b01cc6681e8a4c3cd2501832ab5c4abc40b4578b85cbaffbf0bcd70d67c6e2", false, 500)]
    fn test_g1_add(
        #[case] input: &str,
        #[case] expected_output: &str,
        #[case] expected_error: bool,
        #[case] expected_gas: u64,
    ) {
        let input = Bytes::from_hex(input).unwrap();
        let target_gas: u64 = 30_000_000;
        let res = g1_add(&input, target_gas);
        if expected_error {
            assert!(res.is_err());
        } else {
            let (actual_gas, actual_output) = res.unwrap();
            assert_eq!(expected_gas, actual_gas);
            let expected_output = Bytes::from_hex(expected_output).unwrap();
            assert_eq!(expected_output, actual_output);
        }
    }
}
