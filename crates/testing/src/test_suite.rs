use crate::{chain_spec_builder::ChainSpecBuilder, wallet::Wallet};
use alloy_network::EthereumSigner;
use reth_primitives::ChainSpec;
use std::sync::Arc;

/// Mnemonic used to derive the test accounts
const TEST_MNEMONIC: &str = "test test test test test test test test test test test junk";

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
        let wallet = Wallet::new(TEST_MNEMONIC);
        Self { wallet }
    }

    /// Chain spec for e2e eth tests
    ///
    /// Includes 20 prefunded accounts with 10_000 ETH each derived from mnemonic "test test test
    /// test test test test test test test test junk".
    pub(crate) fn chain_spec(&self) -> Arc<ChainSpec> {
        ChainSpecBuilder::new().build()
    }

    pub(crate) fn signer(&self) -> EthereumSigner {
        self.wallet.clone().into()
    }
}
