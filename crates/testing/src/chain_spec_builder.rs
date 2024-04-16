use reth_primitives::{ChainSpec, Genesis};
use std::sync::Arc;

/// Helper struct to configure the chain spec as needed for e2e tests
#[must_use = "call `build` to construct the chainspec"]
pub(crate) struct ChainSpecBuilder {
    chain_spec: ChainSpec,
}

impl ChainSpecBuilder {
    /// Creates a new chain spec builder with the static genesis.json
    pub(crate) fn new() -> Self {
        let genesis: Genesis =
            serde_json::from_str(include_str!("../resources/etc/genesis.json")).unwrap();

        Self { chain_spec: genesis.into() }
    }

    /// Builds the chain spec
    pub(crate) fn build(self) -> Arc<ChainSpec> {
        Arc::new(self.chain_spec)
    }
}
