//! Standalone crate for AlphaNet's node configuration and builder types.
//!
//! This contains mainly two types, [AlphaNetNode](node::AlphaNetNode) and
//! [AlphaNetEvmConfig](evm::AlphaNetEvmConfig).
//!
//! The [AlphaNetNode](node::AlphaNetNode) type implements the
//! [NodeTypes](reth_node_builder::NodeTypes) trait, and configures the engine types required for
//! the optimism engine API.
//!
//! The [AlphaNetEvmConfig](evm::AlphaNetEvmConfig) type implements the
//! [ConfigureEvm](reth_node_api::ConfigureEvm) and
//! [ConfigureEvmEnv](reth_node_api::ConfigureEvmEnv) traits, configuring the custom AlphaNet
//! precompiles and instructions.

#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![warn(unused_crate_dependencies)]

pub mod chainspec;
pub mod evm;
pub mod node;
