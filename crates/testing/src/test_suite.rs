use crate::wallet::Wallet;
use alloy_network::EthereumSigner;

/// Helper struct to customize the chain spec during e2e tests
pub(crate) struct TestSuite {
    wallet: Wallet,
}

impl Default for TestSuite {
    fn default() -> Self {
        Self::new()
    }
}

impl TestSuite {
    /// Creates a new e2e test suite with a test account prefunded with 10_000 ETH from genesis
    /// allocations and the eth mainnet latest chainspec.
    pub(crate) fn new() -> Self {
        let wallet = Wallet::default();
        Self { wallet }
    }

    pub(crate) fn signer(&self) -> EthereumSigner {
        self.wallet.clone().into()
    }
}
