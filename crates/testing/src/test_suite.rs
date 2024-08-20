use crate::wallet::Wallet;
use alloy_network::EthereumWallet;

/// Helper struct to customize the chain spec during e2e tests
#[allow(dead_code)]
pub(crate) struct TestSuite {
    wallet: Wallet,
}

impl Default for TestSuite {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)]
impl TestSuite {
    /// Creates a new e2e test suite with a test account prefunded with 10_000 ETH from genesis
    /// allocations and the eth mainnet latest chainspec.
    pub(crate) fn new() -> Self {
        let wallet = Wallet::default();
        Self { wallet }
    }

    pub(crate) fn signer(&self) -> EthereumWallet {
        self.wallet.clone().into()
    }
}
