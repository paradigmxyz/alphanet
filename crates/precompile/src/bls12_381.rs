use crate::addresses::{
    BLS12_G1ADD_ADDRESS, BLS12_G1MULTIEXP_ADDRESS, BLS12_G1MUL_ADDRESS, BLS12_G2ADD_ADDRESS,
    BLS12_G2MULTIEXP_ADDRESS, BLS12_G2MUL_ADDRESS, BLS12_MAP_FP2_TO_G2_ADDRESS,
    BLS12_MAP_FP_TO_G1_ADDRESS, BLS12_PAIRING_ADDRESS,
};
use bls12_381::{G1Affine, G1Projective};
use revm_precompile::{u64_to_address, Precompile, PrecompileWithAddress};
use revm_primitives::{Bytes, PrecompileError, PrecompileResult, B256};
use std::ops::Add;

const G1ADD_BASE: u64 = 500;
const G1MUL_BASE: u64 = 12000;
const G1ADD_INPUT_LENGTH: usize = 256;
const G1MUL_INPUT_LENGTH: usize = 160;
const INPUT_ITEM_LENGTH: usize = 128;
const OUTPUT_LENGTH: usize = 128;
const FP_LENGTH: usize = 48;
const PADDED_INPUT_LENGTH: usize = 64;
const PADDING_LENGTH: usize = 16;
const FP_CONCAT_LENGTH: usize = 96;
const SCALAR_LENGTH: usize = 32;

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

/// [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537#specification) BLS12_G1ADD precompile.
const BLS12_G1ADD: PrecompileWithAddress =
    PrecompileWithAddress(u64_to_address(BLS12_G1ADD_ADDRESS), Precompile::Standard(g1_add));

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

// Multiplies a G1 point in projective format by scalar.
fn mul_g1_projective_scalar(p0: G1Projective, scalar0: [u8; SCALAR_LENGTH]) -> G1Projective {
    let mut q = G1Projective::default();
    let mut n = p0;

    for byte in scalar0.into_iter().rev() {
        for bit_index in 0..8 {
            let bit = (byte >> bit_index) & 1;
            if bit == 0x01 {
                q = q.add(n);
            }
            n = n.double();
        }
    }
    q
}

// Extracts an Scalar from a 32 byte slice representation.
fn extract_scalar_input(input: &[u8]) -> Result<[u8; SCALAR_LENGTH], PrecompileError> {
    if input.len() != SCALAR_LENGTH {
        return Err(PrecompileError::Other(format!(
            "Input should be {SCALAR_LENGTH} bits, was {}",
            input.len()
        )));
    }

    Ok(input.try_into().unwrap())
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
}

/// G1 addition call expects `256` bytes as an input that is interpreted as byte
/// concatenation of two G1 points (`128` bytes each).
/// Output is an encoding of addition operation result - single G1 point (`128`
/// bytes). See EIP-2537:
///
/// <https://eips.ethereum.org/EIPS/eip-2537#abi-for-g1-addition>
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
    PrecompileWithAddress(u64_to_address(BLS12_G1MUL_ADDRESS), Precompile::Standard(g1_mul));

// G1 multiplication call expects `160` bytes as an input that is interpreted as
// byte concatenation of encoding of G1 point (`128` bytes) and encoding of a
// scalar value (`32` bytes).
// Output is an encoding of multiplication operation result - single G1 point
// (`128` bytes).
fn g1_mul(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    if G1MUL_BASE > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }
    if input.len() != G1MUL_INPUT_LENGTH {
        return Err(PrecompileError::Other(format!(
            "G1MUL Input should be {G1MUL_INPUT_LENGTH} bits, was {}",
            input.len()
        )));
    }

    let p0 = extract_g1_input(&input[..INPUT_ITEM_LENGTH])?;
    let p0_projective: G1Projective = p0.into();

    let input_scalar0 = extract_scalar_input(&input[INPUT_ITEM_LENGTH..])?;

    let out = mul_g1_projective_scalar(p0_projective, input_scalar0);
    let out: G1Affine = out.into();

    // take into account point of infinity encoding
    // https://eips.ethereum.org/EIPS/eip-2537#point-of-infinity-encoding
    let out_bytes = if out.is_identity().into() {
        [0u8; OUTPUT_LENGTH]
    } else {
        set_padding(out.to_uncompressed())
    };

    Ok((G1MUL_BASE, out_bytes.into()))
}

/// [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537#specification) BLS12_G1MULTIEXP precompile.
const BLS12_G1MULTIEXP: PrecompileWithAddress = PrecompileWithAddress(
    u64_to_address(BLS12_G1MULTIEXP_ADDRESS),
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
    PrecompileWithAddress(u64_to_address(BLS12_G2ADD_ADDRESS), Precompile::Standard(g2_add));

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
    PrecompileWithAddress(u64_to_address(BLS12_G2MUL_ADDRESS), Precompile::Standard(g2_mul));

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
    u64_to_address(BLS12_G2MULTIEXP_ADDRESS),
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
const BLS12_PAIRING: PrecompileWithAddress =
    PrecompileWithAddress(u64_to_address(BLS12_PAIRING_ADDRESS), Precompile::Standard(pairing));

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
    u64_to_address(BLS12_MAP_FP_TO_G1_ADDRESS),
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
    u64_to_address(BLS12_MAP_FP2_TO_G2_ADDRESS),
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
    fn test_g1_add(
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
}
