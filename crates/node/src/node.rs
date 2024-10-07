//! # AlphaNet Node types configuration
//!
//! The [AlphaNetNode] type implements the [NodeTypes] trait, and configures the engine types
//! required for the optimism engine API.

use crate::evm::AlphaNetEvmConfig;
use reth_node_api::{FullNodeTypes, NodeTypesWithEngine};
use reth_node_builder::{
    components::{ComponentsBuilder, ExecutorBuilder, PayloadServiceBuilder},
    BuilderContext, Node, NodeTypes,
};
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_node::{
    args::RollupArgs,
    node::{
        OptimismAddOns, OptimismConsensusBuilder, OptimismEngineValidatorBuilder,
        OptimismNetworkBuilder, OptimismPayloadBuilder, OptimismPoolBuilder,
    },
    OpExecutorProvider, OptimismEngineTypes,
};
use reth_payload_builder::PayloadBuilderHandle;
use reth_transaction_pool::TransactionPool;

/// Type configuration for a regular AlphaNet node.
#[derive(Debug, Clone, Default)]
pub struct AlphaNetNode {
    /// Additional Optimism args
    pub args: RollupArgs,
}

impl AlphaNetNode {
    /// Creates a new instance of the Optimism node type.
    pub const fn new(args: RollupArgs) -> Self {
        Self { args }
    }

    /// Returns the components for the given [RollupArgs].
    pub fn components<Node>(
        args: RollupArgs,
    ) -> ComponentsBuilder<
        Node,
        OptimismPoolBuilder,
        AlphaNetPayloadBuilder,
        OptimismNetworkBuilder,
        AlphaNetExecutorBuilder,
        OptimismConsensusBuilder,
        OptimismEngineValidatorBuilder,
    >
    where
        Node: FullNodeTypes<
            Types: NodeTypesWithEngine<Engine = OptimismEngineTypes, ChainSpec = OpChainSpec>,
        >,
    {
        let RollupArgs { disable_txpool_gossip, compute_pending_block, discovery_v4, .. } = args;
        ComponentsBuilder::default()
            .node_types::<Node>()
            .pool(OptimismPoolBuilder::default())
            .payload(AlphaNetPayloadBuilder::new(compute_pending_block))
            .network(OptimismNetworkBuilder {
                disable_txpool_gossip,
                disable_discovery_v4: !discovery_v4,
            })
            .executor(AlphaNetExecutorBuilder::default())
            .consensus(OptimismConsensusBuilder::default())
            .engine_validator(OptimismEngineValidatorBuilder::default())
    }
}

/// Configure the node types
impl NodeTypes for AlphaNetNode {
    type Primitives = ();
    type ChainSpec = OpChainSpec;
}

impl NodeTypesWithEngine for AlphaNetNode {
    type Engine = OptimismEngineTypes;
}

impl<N> Node<N> for AlphaNetNode
where
    N: FullNodeTypes<
        Types: NodeTypesWithEngine<Engine = OptimismEngineTypes, ChainSpec = OpChainSpec>,
    >,
{
    type ComponentsBuilder = ComponentsBuilder<
        N,
        OptimismPoolBuilder,
        AlphaNetPayloadBuilder,
        OptimismNetworkBuilder,
        AlphaNetExecutorBuilder,
        OptimismConsensusBuilder,
        OptimismEngineValidatorBuilder,
    >;

    type AddOns = OptimismAddOns;

    fn components_builder(&self) -> Self::ComponentsBuilder {
        let Self { args } = self;
        Self::components(args.clone())
    }

    fn add_ons(&self) -> Self::AddOns {
        OptimismAddOns::new(self.args.sequencer_http.clone())
    }
}

/// The AlphaNet evm and executor builder.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct AlphaNetExecutorBuilder;

impl<Node> ExecutorBuilder<Node> for AlphaNetExecutorBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec = OpChainSpec>>,
{
    type EVM = AlphaNetEvmConfig;
    type Executor = OpExecutorProvider<Self::EVM>;

    async fn build_evm(
        self,
        ctx: &BuilderContext<Node>,
    ) -> eyre::Result<(Self::EVM, Self::Executor)> {
        let chain_spec = ctx.chain_spec();
        let evm_config = AlphaNetEvmConfig::new(chain_spec.clone());
        let executor = OpExecutorProvider::new(chain_spec, evm_config.clone());

        Ok((evm_config, executor))
    }
}

/// The AlphaNet payload service builder.
///
/// This service wraps the default Optimism payload builder, but replaces the default evm config
/// with AlphaNet's own.
#[derive(Debug, Default, Clone)]
pub struct AlphaNetPayloadBuilder {
    /// Inner Optimism payload builder service.
    inner: OptimismPayloadBuilder,
}

impl AlphaNetPayloadBuilder {
    /// Create a new instance with the given `compute_pending_block` flag.
    pub const fn new(compute_pending_block: bool) -> Self {
        Self { inner: OptimismPayloadBuilder::new(compute_pending_block) }
    }
}

impl<Node, Pool> PayloadServiceBuilder<Node, Pool> for AlphaNetPayloadBuilder
where
    Node: FullNodeTypes<
        Types: NodeTypesWithEngine<Engine = OptimismEngineTypes, ChainSpec = OpChainSpec>,
    >,
    Pool: TransactionPool + Unpin + 'static,
{
    async fn spawn_payload_service(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
    ) -> eyre::Result<PayloadBuilderHandle<OptimismEngineTypes>> {
        self.inner.spawn(AlphaNetEvmConfig::new(ctx.chain_spec().clone()), ctx, pool)
    }
}
