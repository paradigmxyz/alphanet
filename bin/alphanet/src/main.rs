//! # Reth AlphaNet
//!
//! Reth AlphaNet is a testnet OP Stack rollup aimed at enabling experimentation of bleeding edge
//! Ethereum Research. It aims to showcase how Reth's pluggable and modularized architecture can
//! serve as a distribution channel for research ideas.
//!
//! ## Feature Flags
//!
//! - `jemalloc`: Uses [jemallocator](https://github.com/tikv/jemallocator) as the global allocator.
//!   This is **not recommended on Windows**. See [here](https://rust-lang.github.io/rfcs/1974-global-allocators.html#jemalloc)
//!   for more info.
//! - `jemalloc-prof`: Enables [jemallocator's](https://github.com/tikv/jemallocator) heap profiling
//!   and leak detection functionality. See [jemalloc's opt.prof](https://jemalloc.net/jemalloc.3.html#opt.prof)
//!   documentation for usage details. This is **not recommended on Windows**. See [here](https://rust-lang.github.io/rfcs/1974-global-allocators.html#jemalloc)
//!   for more info.
//! - `asm-keccak`: replaces the default, pure-Rust implementation of Keccak256 with one implemented
//!   in assembly; see [the `keccak-asm` crate](https://github.com/DaniPopes/keccak-asm) for more
//!   details and supported targets
//! - `min-error-logs`: Disables all logs below `error` level.
//! - `min-warn-logs`: Disables all logs below `warn` level.
//! - `min-info-logs`: Disables all logs below `info` level. This can speed up the node, since fewer
//!   calls to the logging component is made.
//! - `min-debug-logs`: Disables all logs below `debug` level.
//! - `min-trace-logs`: Disables all logs below `trace` level.

#![warn(unused_crate_dependencies)]

use alphanet_node::node::AlphaNetNode;
use clap::Parser;
use reth::{
    builder::NodeHandle,
    cli::Cli,
    providers::BlockReaderIdExt,
    rpc::{api::EngineApiClient, types::engine::ForkchoiceState},
};
use reth_node_optimism::{args::RollupArgs, rpc::SequencerClient, OptimismEngineTypes};
use std::sync::Arc;

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
        let NodeHandle { node, node_exit_future } = builder
            .node(AlphaNetNode::new(rollup_args.clone()))
            .extend_rpc_modules(move |ctx| {
                // register sequencer tx forwarder
                if let Some(sequencer_http) = rollup_args.sequencer_http.clone() {
                    ctx.registry.set_eth_raw_transaction_forwarder(Arc::new(SequencerClient::new(
                        sequencer_http,
                    )));
                }

                Ok(())
            })
            .launch()
            .await?;

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
