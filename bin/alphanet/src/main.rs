//! # Reth Alphanet
//!
//! Reth AlphaNet is a testnet OP Stack rollup aimed at enabling experimentation of bleeding edge
//! Ethereum Research.

use alphanet_node::node::AlphaNetNode;
use reth::{
    args::RpcServerArgs,
    builder::{NodeBuilder, NodeConfig},
    primitives::{Chain, ChainSpec, Genesis},
    tasks::TaskManager,
};
use reth_node_optimism::{args::RollupArgs, OptimismNode};
use reth_tracing::{RethTracer, Tracer};

// We use jemalloc for performance reasons.
#[cfg(all(feature = "jemalloc", unix))]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let _guard = RethTracer::new().init()?;

    let tasks = TaskManager::current();

    // create optimism genesis with canyon at block 2
    let spec = ChainSpec::builder()
        .chain(Chain::mainnet())
        .genesis(Genesis::default())
        .london_activated()
        .paris_activated()
        .shanghai_activated()
        .cancun_activated()
        .build();

    let node_config =
        NodeConfig::test().with_rpc(RpcServerArgs::default().with_http()).with_chain(spec);

    let handle = NodeBuilder::new(node_config)
        .testing_node(tasks.executor())
        .with_types(AlphaNetNode::default())
        .with_components(OptimismNode::components(RollupArgs::default()))
        .launch()
        .await
        .unwrap();

    tracing::info!("Node started");

    handle.node_exit_future.await
}
