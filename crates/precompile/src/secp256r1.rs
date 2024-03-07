use reth::revm::precompile::{Precompile, PrecompileWithAddress};
use revm_primitives::{Bytes, PrecompileError, PrecompileResult, StandardPrecompileFn};

/// EIP-7212 secp256r1 precompile.
pub const P256VERIFY: PrecompileWithAddress = PrecompileWithAddress(
    crate::u64_to_address(11), /* 0x0b according to https://eips.ethereum.org/EIPS/eip-7212#specification */
    Precompile::Standard(p256_verify as StandardPrecompileFn),
);

fn p256_verify(i: &Bytes, target_gas: u64) -> PrecompileResult {
    use core::cmp::min;
    use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};

    const P256VERIFY_BASE: u64 = 3_450;

    if P256VERIFY_BASE > target_gas {
        return Err(PrecompileError::OutOfGas);
    }
    let mut input = [0u8; 160];
    input[..min(i.len(), 160)].copy_from_slice(&i[..min(i.len(), 160)]);

    // msg signed (msg is already the hash of the original message)
    let msg: [u8; 32] = input[..32].try_into().unwrap();
    // r, s: signature
    let sig: [u8; 64] = input[32..96].try_into().unwrap();
    // x, y: public key
    let pk: [u8; 64] = input[96..160].try_into().unwrap();
    // append 0x04 to the public key: uncompressed form
    let mut uncompressed_pk = [0u8; 65];
    uncompressed_pk[0] = 0x04;
    uncompressed_pk[1..].copy_from_slice(&pk);

    let signature: Signature = Signature::from_slice(&sig).unwrap();
    let public_key: VerifyingKey = VerifyingKey::from_sec1_bytes(&uncompressed_pk).unwrap();

    let mut result = [0u8; 32];

    // verify
    if public_key.verify_prehash(&msg, &signature).is_ok() {
        result[31] = 0x01;
        Ok((P256VERIFY_BASE, result.into()))
    } else {
        Ok((P256VERIFY_BASE, result.into()))
    }
}

#[cfg(test)]
mod test {
    use super::p256_verify;
    use revm_primitives::{hex::FromHex, Bytes};

    #[test]
    fn proper_sig_verify() {
        let input = Bytes::from_hex("4cee90eb86eaa050036147a12d49004b6b9c72bd725d39d4785011fe190f0b4da73bd4903f0ce3b639bbbf6e8e80d16931ff4bcf5993d58468e8fb19086e8cac36dbcd03009df8c59286b162af3bd7fcc0450c9aa81be5d10d312af6c66b1d604aebd3099c618202fcfe16ae7770b0c49ab5eadf74b754204a3bb6060e44eff37618b065f9832de4ca6ca971a7a1adc826d0f7c00181a5fb2ddf79ae00b4e10e").unwrap();
        let target_gas = 3_500u64;
        let (gas_used, res) = p256_verify(&input, target_gas).unwrap();
        assert_eq!(gas_used, 3_450u64);
        let mut expected_res = [0u8; 32];
        expected_res[31] = 1;
        assert_eq!(res, expected_res.to_vec());
    }
}
