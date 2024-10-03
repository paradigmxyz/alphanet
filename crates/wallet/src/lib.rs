//! # AlphaNet wallet.
//!
//! Implementations of a custom `wallet_` namespace for AlphaNet experiment 1.
//!
//! - `wallet_getCapabilities` based on [EIP-5792][eip-5792], with the only capability being
//!   `delegation`.
//! - `wallet_sendTransaction` that can perform sequencer-sponsored [EIP-7702][eip-7702] delegations
//!   and send other sequencer-sponsored transactions on behalf of EOAs with delegated code.
//!
//! # Restrictions
//!
//! `wallet_sendTransaction` has additional verifications in place to prevent some rudimentary abuse
//! of the sequencer's funds. For example, transactions cannot contain any `value`.
//!
//! [eip-5792]: https://eips.ethereum.org/EIPS/eip-5792
//! [eip-7702]: https://eips.ethereum.org/EIPS/eip-7702

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

use alloy_primitives::{map::HashMap, Address, ChainId, TxHash};
use alloy_rpc_types::TransactionRequest;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use serde::{Deserialize, Serialize};

/// The capability to perform [EIP-7702][eip-7702] delegations, sponsored by the sequencer.
///
/// The sequencer will only perform delegations, and act on behalf of delegated accounts, if the
/// account delegates to one of the addresses specified within this capability.
///
/// [eip-7702]: https://eips.ethereum.org/EIPS/eip-7702
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DelegationCapability {
    /// A list of valid delegation contracts.
    pub addresses: Vec<Address>,
}

/// Wallet capabilities for a specific chain.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Capabilities {
    /// The capability to delegate.
    pub delegation: DelegationCapability,
}

/// A map of wallet capabilities per chain ID.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WalletCapabilities(pub HashMap<ChainId, Capabilities>);

/// AlphaNet `wallet_` RPC namespace.
#[cfg_attr(not(test), rpc(server, namespace = "wallet"))]
#[cfg_attr(test, rpc(server, client, namespace = "wallet"))]
pub trait AlphaNetWalletApi {
    /// Get the capabilities of the wallet.
    ///
    /// Currently the only capability is [`DelegationCapability`].
    ///
    /// See also [EIP-5792][eip-5792].
    ///
    /// [eip-5792]: https://eips.ethereum.org/EIPS/eip-5792
    #[method(name = "getCapabilities")]
    fn get_capabilities(&self) -> RpcResult<WalletCapabilities>;

    /// Send a sequencer-sponsored transaction.
    ///
    /// The transaction will only be processed if:
    ///
    /// - The transaction is an [EIP-7702][eip-7702] transaction that delegates to one of the
    ///   addresses listed in [`DelegationCapability`] (see [`Self::get_capabilities`])
    /// - The transaction is an [EIP-1559][eip-1559] transaction to an EOA that is currently
    ///   delegated to one of the addresses above
    /// - The value in the transaction is exactly 0.
    ///
    /// The sequencer will sign the transaction and inject it into the transaction pool, provided it
    /// is valid. The nonce is managed by the sequencer.
    ///
    /// [eip-7702]: https://eips.ethereum.org/EIPS/eip-7702
    /// [eip-1559]: https://eips.ethereum.org/EIPS/eip-1559
    #[method(name = "sendTransaction")]
    fn send_transaction(&self, request: TransactionRequest) -> RpcResult<TxHash>;
}
