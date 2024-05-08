use alloy::signers::Signer;
use alloy_network::EthereumSigner;
use alloy_signer_wallet::{coins_bip39::English, LocalWallet, MnemonicBuilder};
use reth_primitives::{B256, U256};

/// Mnemonic used to derive the test accounts
const TEST_MNEMONIC: &str = "test test test test test test test test test test test junk";

/// One of the accounts of the genesis allocations.
#[derive(Clone)]
pub(crate) struct Wallet {
    inner: LocalWallet,
}

impl Default for Wallet {
    fn default() -> Self {
        Self::new(0)
    }
}

impl Wallet {
    /// Creates a new account from one of the secret/pubkeys of the genesis allocations (test.json)
    pub(crate) fn new(index: u32) -> Self {
        let inner = MnemonicBuilder::<English>::default()
            .phrase(TEST_MNEMONIC)
            .index(index)
            .unwrap()
            .build()
            .unwrap();
        Self { inner }
    }

    pub(crate) fn random() -> Self {
        let inner = MnemonicBuilder::<English>::default().build_random().unwrap();
        Self { inner }
    }

    pub(crate) async fn sign_hash(&self, message: B256) -> (u8, U256, U256) {
        let signature = self.inner.sign_hash(&message).await.unwrap();
        (signature.v().y_parity_byte() + 27, signature.r(), signature.s())
    }
}
impl From<Wallet> for EthereumSigner {
    fn from(val: Wallet) -> Self {
        val.inner.clone().into()
    }
}
