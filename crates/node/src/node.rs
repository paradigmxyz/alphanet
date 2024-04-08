//! # AlphaNet Node types configuration
//!
//! The [AlphaNetNode] type implements the [NodeTypes] trait, and configures the engine types
//! required for the optimism engine API.

use crate::evm::AlphaNetEvmConfig;
use reth::builder::NodeTypes;
use reth_node_optimism::OptimismEngineTypes;

/// Type configuration for a regular AlphaNet node.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct AlphaNetNode;

/// Configure the node types
impl NodeTypes for AlphaNetNode {
    type Primitives = ();
    type Engine = OptimismEngineTypes;
    type Evm = AlphaNetEvmConfig;

    fn evm_config(&self) -> Self::Evm {
        Self::Evm::default()
    }
}
