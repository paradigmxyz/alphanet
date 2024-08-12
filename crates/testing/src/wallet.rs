use alloy_network::EthereumWallet;
use alloy_signer_local::{coins_bip39::English, MnemonicBuilder, PrivateKeySigner};

/// Mnemonic used to derive the test accounts
const TEST_MNEMONIC: &str = "test test test test test test test test test test test junk";

/// One of the accounts of the genesis allocations.
#[derive(Clone)]
pub(crate) struct Wallet {
    inner: PrivateKeySigner,
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
}
impl From<Wallet> for EthereumWallet {
    fn from(val: Wallet) -> Self {
        val.inner.clone().into()
    }
}
