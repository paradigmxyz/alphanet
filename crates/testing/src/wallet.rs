use alloy_network::EthereumSigner;
use alloy_signer_wallet::{coins_bip39::English, LocalWallet, MnemonicBuilder};

/// One of the accounts of the genesis allocations.
#[derive(Clone)]
pub(crate) struct Wallet {
    inner: LocalWallet,
}

impl Wallet {
    /// Creates a new account from one of the secret/pubkeys of the genesis allocations (test.json)
    pub(crate) fn new(phrase: &str) -> Self {
        let inner = MnemonicBuilder::<English>::default().phrase(phrase).build().unwrap();
        Self { inner }
    }
}
impl Into<EthereumSigner> for Wallet {
    fn into(self) -> EthereumSigner {
        self.inner.clone().into()
    }
}
