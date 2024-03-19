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
const G1ADD_INPUT_LENGTH: usize = 256;
const INPUT_ITEM_LENGTH: usize = 128;
const OUTPUT_LENGTH: usize = 128;
const FP_LENGTH: usize = 48;
const PADDED_INPUT_LENGTH: usize = 64;
const PADDING_LENGTH: usize = 16;
const FP_CONCAT_LENGTH: usize = 96;

/// bls12381 precompiles
pub fn precompiles() -> impl Iterator<Item = PrecompileWithAddress> {
    [
        BLS12_G1ADD,
        BLS12_G1MUL,
        BLS12_G1MULTIEXP,
        BLS12_G2ADD,
        BLS12_G2MUL,
        BLS12_G2MULTIEXP,
        BLS12_PAIRING,
        BLS12_MAP_FP_TO_G1,
        BLS12_MAP_FP2_TO_G2,
    ]
    .into_iter()
}

const G1ADD_BASE: u64 = 500;
const INPUT_LENGTH: usize = 256;
const INPUT_ITEM_LENGTH: usize = 128;
const OUTPUT_LENGTH: usize = 128;
const FP_LEGTH: usize = 48;
const PADDED_INPUT_LENGTH: usize = 64;
const PADDING_LEGTH: usize = 16;
const FP_CONCAT_LENGTH: usize = 96;

/// [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537#specification) BLS12_G1ADD precompile.
const BLS12_G1ADD: PrecompileWithAddress =
    PrecompileWithAddress(crate::u64_to_address(BLS12_G1ADD_ADDRESS), Precompile::Standard(g1_add));

// Removes zeros with which the precompile inputs are left padded to 64 bytes.
fn remove_padding(input: &[u8]) -> Result<[u8; FP_LENGTH], PrecompileError> {
    if input.len() != PADDED_INPUT_LENGTH {
        return Err(PrecompileError::Other(format!(
            "Padded Input should be {PADDED_INPUT_LENGTH} bits, was {}",
            input.len()
        )));
    }
    if !input.iter().take(PADDING_LENGTH).all(|&x| x == 0) {
        return Err(PrecompileError::Other(format!(
            "{PADDING_LENGTH} top bytes of input are not zero",
        )));
    }

    let sliced = &input[PADDING_LENGTH..PADDED_INPUT_LENGTH];
    <[u8; FP_LENGTH]>::try_from(sliced).map_err(|e| PrecompileError::Other(format!("{e}")))
}

// Adds left pad with zeros to each FP element so that the output lenght matches
// 128 bytes.
fn set_padding(input: [u8; FP_CONCAT_LENGTH]) -> [u8; OUTPUT_LENGTH] {
    let mut output = [0u8; OUTPUT_LENGTH];

    output[PADDING_LENGTH..PADDED_INPUT_LENGTH].copy_from_slice(&input[..FP_LENGTH]);
    output[(PADDED_INPUT_LENGTH + PADDING_LENGTH)..].copy_from_slice(&input[FP_LENGTH..]);

    output
}

// Adds a G1 pont in projective format to another one in affine format. If any
// of the inputs is the identity, the other is returned.
fn add_g1_affine_projective(p0: G1Affine, p1_projective: G1Projective) -> G1Projective {
    if p0.is_identity().into() {
        return p1_projective;
    }
    if p1_projective.is_identity().into() {
        return p0.into();
    }
    p0.add(p1_projective)
}

// Extracts a G1 point in Affine format from a 128 byte slice representation.
fn extract_g1_input(input: &[u8]) -> Result<G1Affine, PrecompileError> {
    if input.len() != INPUT_ITEM_LENGTH {
        return Err(PrecompileError::Other(format!(
            "Input should be {INPUT_ITEM_LENGTH} bits, was {}",
            input.len()
        )));
    }

    let input_p0_x = match remove_padding(&input[..PADDED_INPUT_LENGTH]) {
        Ok(input_p0_x) => input_p0_x,
        Err(e) => return Err(e),
    };
    let input_p0_y = match remove_padding(&input[PADDED_INPUT_LENGTH..INPUT_ITEM_LENGTH]) {
        Ok(input_p0_y) => input_p0_y,
        Err(e) => return Err(e),
    };
    let mut input_p0: [u8; FP_CONCAT_LENGTH] = [0; FP_CONCAT_LENGTH];
    input_p0[..FP_LENGTH].copy_from_slice(&input_p0_x);
    input_p0[FP_LENGTH..].copy_from_slice(&input_p0_y);

    // handle the case in which all
    // the input bytes are zero, which should represent the infinity point in the
    // curve, see EIP-2537:
    //
    // <https://eips.ethereum.org/EIPS/eip-2537#point-of-infinity-encoding>
    if input_p0 == [0; FP_CONCAT_LENGTH] {
        Ok(G1Affine::identity())
    } else {
        let output = G1Affine::from_uncompressed(&input_p0);
        if (!output.is_some()).into() {
            return Err(PrecompileError::Other(
                "The given input did not represent a valid elliptic curve point".to_string(),
            ));
        }
        Ok(output.unwrap())
    }

    let input_p0_x = match remove_padding(&input[..PADDED_INPUT_LENGTH]) {
        Ok(input_p0_x) => input_p0_x,
        Err(e) => return Err(e),
    };
    let input_p0_y = match remove_padding(&input[PADDED_INPUT_LENGTH..INPUT_ITEM_LENGTH]) {
        Ok(input_p0_y) => input_p0_y,
        Err(e) => return Err(e),
    };
    let mut input_p0: [u8; FP_CONCAT_LENGTH] = [0; FP_CONCAT_LENGTH];
    input_p0[..FP_LEGTH].copy_from_slice(&input_p0_x);
    input_p0[FP_LEGTH..].copy_from_slice(&input_p0_y);

    Ok(input_p0)
}

// G1 addition call expects `256` bytes as an input that is interpreted as byte
// concatenation of two G1 points (`128` bytes each).
// Output is an encoding of addition operation result - single G1 point (`128`
// bytes).
fn g1_add(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    if G1ADD_BASE > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }

    if input.len() != G1ADD_INPUT_LENGTH {
        return Err(PrecompileError::Other(format!(
            "G1ADD Input should be {G1ADD_INPUT_LENGTH} bits, was {}",
            input.len()
        )));
    }

    let p0 = extract_g1_input(&input[..INPUT_ITEM_LENGTH])?;

    let p1 = extract_g1_input(&input[INPUT_ITEM_LENGTH..])?;
    let p1_projective: G1Projective = p1.into();

    let out = add_g1_affine_projective(p0, p1_projective);
    let out: G1Affine = out.into();

    // take into account point of infinity encoding
    // https://eips.ethereum.org/EIPS/eip-2537#point-of-infinity-encoding
    let out_bytes = if out.is_identity().into() {
        [0u8; OUTPUT_LENGTH]
    } else {
        set_padding(out.to_uncompressed())
    };

    Ok((G1ADD_BASE, out_bytes.into()))
}

/// [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537#specification) BLS12_G1MUL precompile.
const BLS12_G1MUL: PrecompileWithAddress =
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
const BLS12_G1MULTIEXP: PrecompileWithAddress = PrecompileWithAddress(
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
const BLS12_G2ADD: PrecompileWithAddress =
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
const BLS12_G2MUL: PrecompileWithAddress =
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
const BLS12_G2MULTIEXP: PrecompileWithAddress = PrecompileWithAddress(
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
const BLS12_PAIRING: PrecompileWithAddress = PrecompileWithAddress(
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
const BLS12_MAP_FP_TO_G1: PrecompileWithAddress = PrecompileWithAddress(
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
const BLS12_MAP_FP2_TO_G2: PrecompileWithAddress = PrecompileWithAddress(
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
    #[case::inf_plus_g1_equals_g1("0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1", false, 500)]
    #[case::inf_plus_inf_equals_inf("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", false, 500)]
    #[case::matter_g1_add_0("0000000000000000000000000000000012196c5a43d69224d8713389285f26b98f86ee910ab3dd668e413738282003cc5b7357af9a7af54bb713d62255e80f560000000000000000000000000000000006ba8102bfbeea4416b710c73e8cce3032c31c6269c44906f8ac4f7874ce99fb17559992486528963884ce429a992fee000000000000000000000000000000000001101098f5c39893765766af4512a0c74e1bb89bc7e6fdf14e3e7337d257cc0f94658179d83320b99f31ff94cd2bac0000000000000000000000000000000003e1a9f9f44ca2cdab4f43a1a3ee3470fdf90b2fc228eb3b709fcd72f014838ac82a6d797aeefed9a0804b22ed1ce8f7", "000000000000000000000000000000001466e1373ae4a7e7ba885c5f0c3ccfa48cdb50661646ac6b779952f466ac9fc92730dcaed9be831cd1f8c4fefffd5209000000000000000000000000000000000c1fb750d2285d4ca0378e1e8cdbf6044151867c34a711b73ae818aee6dbe9e886f53d7928cc6ed9c851e0422f609b11", false, 500)]
    #[case::matter_g1_add_1("00000000000000000000000000000000117dbe419018f67844f6a5e1b78a1e597283ad7b8ee7ac5e58846f5a5fd68d0da99ce235a91db3ec1cf340fe6b7afcdb0000000000000000000000000000000013316f23de032d25e912ae8dc9b54c8dba1be7cecdbb9d2228d7e8f652011d46be79089dd0a6080a73c82256ce5e4ed2000000000000000000000000000000000441e7f7f96198e4c23bd5eb16f1a7f045dbc8c53219ab2bcea91d3a027e2dfe659feac64905f8b9add7e4bfc91bec2b0000000000000000000000000000000005fc51bb1b40c87cd4292d4b66f8ca5ce4ef9abd2b69d4464b4879064203bda7c9fc3f896a3844ebc713f7bb20951d95", "0000000000000000000000000000000016b8ab56b45a9294466809b8e858c1ad15ad0d52cfcb62f8f5753dc94cee1de6efaaebce10701e3ec2ecaa9551024ea600000000000000000000000000000000124571eec37c0b1361023188d66ec17c1ec230d31b515e0e81e599ec19e40c8a7c8cdea9735bc3d8b4e37ca7e5dd71f6", false, 500)]
    #[case::matter_g1_add_10("0000000000000000000000000000000000641642f6801d39a09a536f506056f72a619c50d043673d6d39aa4af11d8e3ded38b9c3bbc970dbc1bd55d68f94b50d0000000000000000000000000000000009ab050de356a24aea90007c6b319614ba2f2ed67223b972767117769e3c8e31ee4056494628fb2892d3d37afb6ac9430000000000000000000000000000000016380d03b7c5cc3301ffcb2cf7c28c9bde54fc22ba2b36ec293739d8eb674678c8e6461e34c1704747817c8f8341499a000000000000000000000000000000000ec6667aa5c6a769a64c180d277a341926376c39376480dc69fcad9a8d3b540238eb39d05aaa8e3ca15fc2c3ab696047", "0000000000000000000000000000000011541d798b4b5069e2541fa5410dad03fd02784332e72658c7b0fa96c586142a967addc11a7a82bfcee33bd5d07066b900000000000000000000000000000000195b3fcb94ab7beb908208283b4e5d19c0af90fca4c76268f3c703859dea7d038aca976927f48839ebc7310869c724aa", false, 500)]
    #[case::matter_g1_add_20("0000000000000000000000000000000013c5ebfb853f0c8741f12057b6b845c4cdbf72aecbeafc8f5b5978f186eead8685f2f3f125e536c465ade1a00f212b0900000000000000000000000000000000082543b58a13354d0cce5dc3fb1d91d1de6d5927290b2ff51e4e48f40cdf2d490730843b53a92865140153888d73d4af0000000000000000000000000000000008cefd0fd289d6964a962051c2c2ad98dab178612663548370dd5f007c5264fece368468d3ca8318a381b443c68c4cc7000000000000000000000000000000000708d118d44c1cb5609667fd51df9e58cacce8b65565ef20ad1649a3e1b9453e4fb37af67c95387de008d4c2114e5b95", "0000000000000000000000000000000004b2311897264fe08972d62872d3679225d9880a16f2f3d7dd59412226e5e3f4f2aa8a69d283a2dc5b93e022293f0ee1000000000000000000000000000000000f03e18cef3f9a86e6b842272f2c7ee48d0ad23bfc7f1d5a9a796d88e5d5ac31326db5fe90de8f0690c70ae6e0155039", false, 500)]
    #[case::matter_g1_add_30("00000000000000000000000000000000159d94fb0cf6f4e3e26bdeb536d1ee9c511a29d32944da43420e86c3b5818e0f482a7a8af72880d4825a50fee6bc8cd8000000000000000000000000000000000c2ffe6be05eccd9170b6c181966bb8c1c3ed10e763613112238cabb41370e2a5bb5fef967f4f8f2af944dbef09d265e000000000000000000000000000000000c8e293f730253128399e5c39ab18c3f040b6cd9df10d794a28d2a428a9256ea1a71cf53022bd1be11f501805e0ddda40000000000000000000000000000000003e60c2291be46900930f710969f79f27e76cf710efefc243236428db2fed93719edeeb64ada0edf6346a0411f2a4cb8", "00000000000000000000000000000000191084201608f706ea1f7c51dd5b593dda87b15d2c594b52829db66ce3beab6b30899d1d285bdb9590335949ceda5f050000000000000000000000000000000000d3460622c7f1d849658a20a7ae7b05e5afae1f01e871cad52ef632cc831b0529a3066f7b81248a7728d231e51fc4ad", false, 500)]
    #[case::matter_g1_add_40("000000000000000000000000000000001837f0f18bed66841b4ff0b0411da3d5929e59b957a0872bce1c898a4ef0e13350bf4c7c8bcff4e61f24feca1acd5a370000000000000000000000000000000003d2c7fe67cada2213e842ac5ec0dec8ec205b762f2a9c05fa12fa120c80eba30676834f0560d11ce9939fe210ad6c6300000000000000000000000000000000013866438b089d39de5a3ca2a624d72c241a54cbdcf5b2a67ebdd2db8373b112a814e74662bd52e37748ffbfc21782a5000000000000000000000000000000000d55454a22d5c2ef82611ef9cb6533e2f08668577764afc5bb9b7dfe32abd5d333147774fb1001dd24889775de57d305", "000000000000000000000000000000000037b4e8846b423335711ac12f91e2419de772216509d6b9deb9c27fd1c1ee5851b3e032bf3bcac3dd8e93f3dce8a91b00000000000000000000000000000000113a1bf4be1103e858c3be282effafd5e2384f4d1073350f7073b0a415ecf9e7a3bfb55c951c0b2c25c6bab35454ecf0", false, 500)]
    #[case::matter_g1_add_47("0000000000000000000000000000000001ea88d0f329135df49893406b4f9aee0abfd74b62e7eb5576d3ddb329fc4b1649b7c228ec39c6577a069c0811c952f100000000000000000000000000000000033f481fc62ab0a249561d180da39ff641a540c9c109cde41946a0e85d18c9d60b41dbcdec370c5c9f22a9ee9de00ccd0000000000000000000000000000000014b78c66c4acecdd913ba73cc4ab573c64b404a9494d29d4a2ba02393d9b8fdaba47bb7e76d32586df3a00e03ae2896700000000000000000000000000000000025c371cd8b72592a45dc521336a891202c5f96954812b1095ba2ea6bb11aad7b6941a44d68fe9b44e4e5fd06bd541d4", "0000000000000000000000000000000015b164c854a2277658f5d08e04887d896a082c6c20895c8809ed4b349da8492d6fa0333ace6059a1f0d37e92ae9bad30000000000000000000000000000000001510d176ddba09ab60bb452188c2705ef154f449bed26abf0255897673a625637b5761355b17676748f67844a61d4e9f", false, 500)]
    #[case::matter_g1_add_57("000000000000000000000000000000000f75bc9feb74110697c9f353686910c6246e587dd71d744aab99917f1aea7165b41deb333e6bd14843f28b2232f799830000000000000000000000000000000019275491a51599736722295659dd5589f4e3f558e3d45137a66b4c8066c7514ae66ec35c862cd00bce809db528040c04000000000000000000000000000000000a138203c916cb8425663db3bbff37f239a5745be885784b8e035a4f40c47954c48873f6d5aa06d579e213282fe789fa0000000000000000000000000000000016897b8adbc3a3a0dccd809f7311ba1f84f76e218c58af243c0aa29a1bb150ed719191d1ced802d4372e717c1c97570a", "0000000000000000000000000000000004ad79769fd10081ebaaed9e2131de5d8738d9ef143b6d0fa6e106bd82cfd53bbc9fab08c422aa03d03896a0fb2460d0000000000000000000000000000000000bb79356c2d477dfbcb1b0e417df7cb79affbe151c1f03fa60b1372d7d82fd53b2160afdd88be1bf0e9dc99596366055", false, 500)]
    #[case::matter_g1_add_67("0000000000000000000000000000000001bb1e11a1ccc0b70ce46114caca7ac1aba2a607fea8c6a0e01785e17559b271a0e8b5afbfa8705ecb77420473e81c510000000000000000000000000000000018f2289ba50f703f87f0516d517e2f6309fe0dc7aca87cc534554c0e57c4bdc5cde0ca896033b7f3d96995d5cbd563d20000000000000000000000000000000002fa19b32a825608ab46b5c681c16ae23ebefd804bb06079059e3f2c7686fe1a74c9406f8581d29ff78f39221d995bfd000000000000000000000000000000000b41ea8a18c64de43301320eaf52d923a1f1d36812c92c6e8b34420eff031e05a037eed47b9fe701fd6a03eb045f2ca7", "000000000000000000000000000000000b99587f721a490b503a973591b2bb76152919269d80347aeba85d2912b864a3f67b868c34aee834ecc8cd82ac1373db0000000000000000000000000000000007767bb0ca3047eee40b83bf14d444e63d98e9fc6c4121bdf04ea7148bcfaf3819b70dcebd9a941134e5c649da8f8d80", false, 500)]
    #[case::matter_g1_add_77("000000000000000000000000000000001517dd04b165c50d2b1ef2f470c821c080f604fe1a23f2fa5481f3a63e0f56e05c89c7403d4067a5f6e59d4a338d0b5c0000000000000000000000000000000007b6b1d032aadd51052f228d7e062e336bacda83bbce657678b5f9634174f0c3c4d0374e83b520a192783a8a5f3fb211000000000000000000000000000000000a6ff5f01a97c0f3c89ac0a460861dc9040f00693bfae22d81ea9a46b6c570436f0688ed0deef5cdcc5e2142f195b5c000000000000000000000000000000000193a17880edffe5b2ebedf0dc25e479cac3b136db9b6b24009ea0a9ca526d6dd9714d10d64c999d4334baa081b9f2fbe", "000000000000000000000000000000000b728d4ae4b45fae9a9e242524e95e44f175356726da50f46236f690eec17fdd5edce5df1253383378dc8f9c1fee98ae00000000000000000000000000000000131d28a5eab968c45ddc86b82f220dcdeab7c009c7c61986ee4e55045c024e1bcbe76a4e35000b5699ccec5858ba427e", false, 500)]
    #[case::matter_g1_add_87("0000000000000000000000000000000013fe38343072af8ef1d8247c3d46b4fd190086ceddfeb767787031368da6a6a6ae849cfc26a24ead499338e37fa337e30000000000000000000000000000000009f7d7b21882455e9f1f24ea120f3eb69f739c1320c37eb2b17e0a271cb03ac6e2b0c55d3518548a005f28b5748b7f59000000000000000000000000000000000bb3a76287fb98fe668cb0a5de603c768340ee6b7f9f686a22da3a86926d8734d2c565c41f94f08fa3ef0e665f4ccb520000000000000000000000000000000016c02dbfb307c96d5b9c144672fe62f3e9cd78991844f246945ee484cbdef2a4c1b001a017cafb3acc57b35f7c08dc44", "00000000000000000000000000000000021796fd6ef624eed7049b8a5c50415cc86104b2367f2966eb3a9f5b7c4833b9470ef558457426f87756d526d94d8dfe000000000000000000000000000000000f492dca3f0a89102b503d7a7d5b197946348e195954d23b8ab9ab7704b3bccecaa2123b8386662f95cd4cfdbbb7a64d", false, 500)]
    #[case::matter_g1_add_97("00000000000000000000000000000000150b75e9e9c03ada40b607f3d648bd6c40269aba3a1a992986dc005c9fde80bb1605266add0819641a0ca702d67bceed00000000000000000000000000000000083b43df032654f2dce90c8049ae4872a39f9cd860f08512930f43898e0f1e5625a5620818788797f3ca68134bc27d220000000000000000000000000000000012dae9aee13ed6ad52fe664bf7d2d0a1f134f0951d0d7ce5184e223bde164f6860967f9aaaa44fa6654d77d026c52d2a000000000000000000000000000000000f71889d64ec2f7da7319994883eb8bd1c753e6cdd3495036b630c35f07118a1bc10568c411ecbdf468a9cdaa9b4811b", "000000000000000000000000000000000275b8efb3a3e43e2a24d0cda238154520f0a2b265f168bfc502b9cd4a07b930756961ae7e4fe3f01a5473d36ce3356200000000000000000000000000000000113403d5a968f01ba127dd8ef6c8d7b783a10d039a6b69c617032eba7122e9297f3ce2360c829ae64fdc9794695bf173", false, 500)]
    #[case::fail_empty_input("", "", true, 500)]
    #[case::fail_short_input("0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb00000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e10000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1", "", true, 500)]
    #[case::fail_large_input("0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb000000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e10000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1", "", true, 500)]
    #[case::fail_violate_top_bytes("0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000108b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e10000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1", "", true, 500)]
    #[case::fail_invalid_field_element("0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaac0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1", "", true, 500)]
    #[case::fail_point_not_on_curve("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1", "", true, 500)]
    #[case::g1_add_g1_plus_g1_equals_2_times_g1("0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e10000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1", "000000000000000000000000000000000572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e00000000000000000000000000000000166a9d8cabc673a322fda673779d8e3822ba3ecb8670e461f73bb9021d5fd76a4c56d9d4cd16bd1bba86881979749d28", false, 500)]
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
