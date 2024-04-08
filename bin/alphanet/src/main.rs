//! # Reth AlphaNet
//!
//! Reth AlphaNet is a testnet OP Stack rollup aimed at enabling experimentation of bleeding edge
//! Ethereum Research. It aims to showcase how Reth's pluggable and modularized architecture can
//! serve as a distribution channel for research ideas.

#![warn(unused_crate_dependencies)]

use alphanet_node::node::AlphaNetNode;
use clap::Parser;
use reth::{
    builder::NodeHandle,
    cli::Cli,
    providers::BlockReaderIdExt,
    rpc::{api::EngineApiClient, types::engine::ForkchoiceState},
};
use reth_node_optimism::{args::RollupArgs, OptimismEngineTypes, OptimismNode};

// We use jemalloc for performance reasons.
#[cfg(all(feature = "jemalloc", unix))]
#[doc(hidden)]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[doc(hidden)]
fn main() {
    reth::sigsegv_handler::install();

    // Enable backtraces unless a RUST_BACKTRACE value has already been explicitly provided.
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    if let Err(err) = Cli::<RollupArgs>::parse().run(|builder, rollup_args| async move {
        let builder = builder
            .with_types(AlphaNetNode::default())
            .with_components(OptimismNode::components(rollup_args.clone()));

        let NodeHandle { node, node_exit_future } = builder.launch().await?;

        // If `enable_genesis_walkback` is set to true, the rollup client will need to
        // perform the derivation pipeline from genesis, validating the data dir.
        // When set to false, set the finalized, safe, and unsafe head block hashes
        // on the rollup client using a fork choice update. This prevents the rollup
        // client from performing the derivation pipeline from genesis, and instead
        // starts syncing from the current tip in the DB.
        if node.chain_spec().is_optimism() && !rollup_args.enable_genesis_walkback {
            let client = node.rpc_server_handles.auth.http_client();
            if let Ok(Some(head)) = node.provider.latest_header() {
                EngineApiClient::<OptimismEngineTypes>::fork_choice_updated_v2(
                    &client,
                    ForkchoiceState {
                        head_block_hash: head.hash(),
                        safe_block_hash: head.hash(),
                        finalized_block_hash: head.hash(),
                    },
                    None,
                )
                .await?;
            }
        }

        tracing::info!("AlphaNet node started");

        node_exit_future.await
    }) {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}
