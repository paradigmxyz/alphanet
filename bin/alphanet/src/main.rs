//! # Reth Alphanet
//!
//! Reth AlphaNet is a testnet OP Stack rollup aimed at enabling experimentation of bleeding edge
//! Ethereum Research.

#![allow(missing_docs)]

// We use jemalloc for performance reasons.
#[cfg(all(feature = "jemalloc", unix))]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

fn main() {
    tracing::info!("Hello, world!");

    // Enable backtraces unless a RUST_BACKTRACE value has already been explicitly provided.
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }
}
