//! # EIP-2537 BLS12-381 Precompiles imported from Revm.

use revm::precompile::bls12_381::{
    g1_add::PRECOMPILE as BLS12_G1ADD, g1_msm::PRECOMPILE as BLS12_G1MSM,
    g1_mul::PRECOMPILE as BLS12_G1MUL, g2_add::PRECOMPILE as BLS12_G2ADD,
    g2_msm::PRECOMPILE as BLS12_G2MSM, g2_mul::PRECOMPILE as BLS12_G2MUL,
    map_fp2_to_g2::PRECOMPILE as BLS12_MAP_FP2_TO_G2,
    map_fp_to_g1::PRECOMPILE as BLS12_MAP_FP_TO_G1, pairing::PRECOMPILE as BLS12_PAIRING,
};

use reth::revm::precompile::PrecompileWithAddress;

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
