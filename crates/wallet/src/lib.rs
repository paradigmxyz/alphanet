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

use alloy_network::{
    eip2718::Encodable2718, Ethereum, EthereumWallet, NetworkWallet, TransactionBuilder,
};
use alloy_primitives::{map::HashMap, Address, ChainId, TxHash, TxKind, U256};
use alloy_rpc_types::TransactionRequest;
use jsonrpsee::{
    core::{async_trait, RpcResult},
    proc_macros::rpc,
};
use reth_primitives::{revm_primitives::Bytecode, BlockId};
use reth_rpc_eth_api::helpers::{EthCall, EthState, EthTransactions, FullEthApi, LoadFee};
use reth_storage_api::{StateProvider, StateProviderFactory};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{trace, warn};

use reth_revm as _;

/// The capability to perform [EIP-7702][eip-7702] delegations, sponsored by the sequencer.
///
/// The sequencer will only perform delegations, and act on behalf of delegated accounts, if the
/// account delegates to one of the addresses specified within this capability.
///
/// [eip-7702]: https://eips.ethereum.org/EIPS/eip-7702
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct DelegationCapability {
    /// A list of valid delegation contracts.
    pub addresses: Vec<Address>,
}

/// Wallet capabilities for a specific chain.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct Capabilities {
    /// The capability to delegate.
    pub delegation: DelegationCapability,
}

/// A map of wallet capabilities per chain ID.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct WalletCapabilities(pub HashMap<ChainId, Capabilities>);

impl WalletCapabilities {
    /// Get the capabilities of the wallet API for the specified chain ID.
    pub fn get(&self, chain_id: ChainId) -> Option<&Capabilities> {
        self.0.get(&chain_id)
    }
}

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
    async fn send_transaction(&self, request: TransactionRequest) -> RpcResult<TxHash>;
}

/// Errors returned by the wallet API.
#[derive(Debug, thiserror::Error)]
pub enum AlphaNetWalletError {
    /// The transaction value is not 0.
    ///
    /// The value should be 0 to prevent draining the sequencer.
    #[error("tx value not zero")]
    ValueNotZero,
    /// The from field is set on the transaction.
    ///
    /// Requests with the from field are rejected, since it is implied that it will always be the
    /// sequencer.
    #[error("tx from field is set")]
    FromSet,
    /// The nonce field is set on the transaction.
    ///
    /// Requests with the nonce field set are rejected, as this is managed by the sequencer.
    #[error("tx nonce is set")]
    NonceSet,
    /// An authorization item was invalid.
    ///
    /// The item is invalid if it tries to delegate an account to a contract that is not
    /// whitelisted.
    #[error("invalid authorization address")]
    InvalidAuthorization,
    /// The to field of the transaction was invalid.
    ///
    /// The destination is invalid if:
    ///
    /// - There is no bytecode at the destination, or
    /// - The bytecode is not an EIP-7702 delegation designator, or
    /// - The delegation designator points to a contract that is not whitelisted
    #[error("the destination of the transaction is not a delegated account")]
    IllegalDestination,
    /// The transaction request was invalid.
    ///
    /// This is likely an internal error, as most of the request is built by the sequencer.
    #[error("invalid tx request")]
    InvalidTransactionRequest,
    /// An internal error occurred.
    #[error("internal error")]
    InternalError,
}

impl From<AlphaNetWalletError> for jsonrpsee::types::error::ErrorObject<'static> {
    fn from(error: AlphaNetWalletError) -> Self {
        jsonrpsee::types::error::ErrorObject::owned::<()>(
            jsonrpsee::types::error::INVALID_PARAMS_CODE,
            error.to_string(),
            None,
        )
    }
}

/// Implementation of the AlphaNet `wallet_` namespace.
pub struct AlphaNetWallet<Provider, Eth> {
    inner: Arc<AlphaNetWalletInner<Provider, Eth>>,
}

impl<Provider, Eth> AlphaNetWallet<Provider, Eth> {
    /// Create a new AlphaNet wallet module.
    pub fn new(
        provider: Provider,
        wallet: EthereumWallet,
        eth_api: Eth,
        chain_id: ChainId,
        valid_designations: Vec<Address>,
    ) -> Self {
        let inner = AlphaNetWalletInner {
            provider,
            wallet,
            eth_api,
            chain_id,
            capabilities: WalletCapabilities(HashMap::from_iter([(
                chain_id,
                Capabilities { delegation: DelegationCapability { addresses: valid_designations } },
            )])),
        };
        Self { inner: Arc::new(inner) }
    }

    fn chain_id(&self) -> ChainId {
        self.inner.chain_id
    }
}

#[async_trait]
impl<Provider, Eth> AlphaNetWalletApiServer for AlphaNetWallet<Provider, Eth>
where
    Provider: StateProviderFactory + Send + Sync + 'static,
    Eth: FullEthApi + Send + Sync + 'static,
{
    fn get_capabilities(&self) -> RpcResult<WalletCapabilities> {
        trace!(target: "rpc::wallet", "Serving wallet_getCapabilities");
        Ok(self.inner.capabilities.clone())
    }

    async fn send_transaction(&self, mut request: TransactionRequest) -> RpcResult<TxHash> {
        trace!(target: "rpc::wallet", ?request, "Serving wallet_sendTransaction");

        // validate fields common to eip-7702 and eip-1559
        validate_tx_request(&request)?;

        let valid_delegations: &[Address] = self
            .inner
            .capabilities
            .get(self.chain_id())
            .map(|caps| caps.delegation.addresses.as_ref())
            .unwrap_or_default();
        if let Some(authorizations) = &request.authorization_list {
            // check that all auth items delegate to a valid address
            if authorizations.iter().any(|auth| !valid_delegations.contains(&auth.address)) {
                return Err(AlphaNetWalletError::InvalidAuthorization.into());
            }
        }

        // validate destination
        match (request.authorization_list.is_some(), request.to) {
            // if this is an eip-1559 tx, ensure that it is an account that delegates to a
            // whitelisted address
            (false, Some(TxKind::Call(addr))) => {
                let state =
                    self.inner.provider.latest().map_err(|_| AlphaNetWalletError::InternalError)?;
                let delegated_address = state
                    .account_code(addr)
                    .ok()
                    .flatten()
                    .and_then(|code| match code.0 {
                        Bytecode::Eip7702(code) => Some(code.address()),
                        _ => None,
                    })
                    .unwrap_or_default();

                // not a whitelisted address, or not an eip-7702 bytecode
                if delegated_address == Address::ZERO
                    || !valid_delegations.contains(&delegated_address)
                {
                    return Err(AlphaNetWalletError::IllegalDestination.into());
                }
            }
            // if it's an eip-7702 tx, let it through
            (true, _) => (),
            // create tx's disallowed
            _ => return Err(AlphaNetWalletError::IllegalDestination.into()),
        }

        // set nonce
        let tx_count = EthState::transaction_count(
            &self.inner.eth_api,
            NetworkWallet::<Ethereum>::default_signer_address(&self.inner.wallet),
            Some(BlockId::pending()),
        )
        .await
        .map_err(Into::into)?;
        request.nonce = Some(tx_count.to());

        // set chain id
        request.chain_id = Some(self.chain_id());

        // set gas limit
        let estimate =
            EthCall::estimate_gas_at(&self.inner.eth_api, request.clone(), BlockId::latest(), None)
                .await
                .map_err(Into::into)?;
        request = request.gas_limit(estimate.to());

        // set gas fees
        let (max_fee_per_gas, max_priority_fee_per_gas) =
            LoadFee::eip1559_fees(&self.inner.eth_api, None, None)
                .await
                .map_err(|_| AlphaNetWalletError::InvalidTransactionRequest)?;
        request.max_fee_per_gas = Some(max_fee_per_gas.to());
        request.max_priority_fee_per_gas = Some(max_priority_fee_per_gas.to());

        // build and sign
        let envelope =
            <TransactionRequest as TransactionBuilder<Ethereum>>::build::<EthereumWallet>(
                request,
                &self.inner.wallet,
            )
            .await
            .map_err(|_| AlphaNetWalletError::InvalidTransactionRequest)?;

        // this uses the internal `OpEthApi` to either forward the tx to the sequencer, or add it to
        // the txpool
        //
        // see: https://github.com/paradigmxyz/reth/blob/b67f004fbe8e1b7c05f84f314c4c9f2ed9be1891/crates/optimism/rpc/src/eth/transaction.rs#L35-L57
        EthTransactions::send_raw_transaction(&self.inner.eth_api, envelope.encoded_2718().into())
            .await
            .inspect_err(|err| warn!(target: "rpc::wallet", ?err, "Error adding sequencer-sponsored tx to pool"))
            .map_err(Into::into)
    }
}

/// Implementation of the AlphaNet `wallet_` namespace.
struct AlphaNetWalletInner<Provider, Eth> {
    provider: Provider,
    wallet: EthereumWallet,
    chain_id: ChainId,
    capabilities: WalletCapabilities,
    eth_api: Eth,
}

fn validate_tx_request(request: &TransactionRequest) -> Result<(), AlphaNetWalletError> {
    // reject transactions that have a non-zero value to prevent draining the sequencer.
    if request.value.is_some_and(|val| val > U256::ZERO) {
        return Err(AlphaNetWalletError::ValueNotZero);
    }

    // reject transactions that have from set, as this will be the sequencer.
    if request.from.is_some() {
        return Err(AlphaNetWalletError::FromSet);
    }

    // reject transaction requests that have nonce set, as this is managed by the sequencer.
    if request.nonce.is_some() {
        return Err(AlphaNetWalletError::NonceSet);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    mod types {
        use crate::{Capabilities, DelegationCapability, WalletCapabilities};
        use alloy_primitives::{address, map::HashMap};

        #[test]
        fn ser() {
            let caps = WalletCapabilities(HashMap::from_iter([(
                0x69420,
                Capabilities {
                    delegation: DelegationCapability {
                        addresses: vec![address!("90f79bf6eb2c4f870365e785982e1f101e93b906")],
                    },
                },
            )]));
            assert_eq!(serde_json::to_string(&caps).unwrap(), "{\"431136\":{\"delegation\":{\"addresses\":[\"0x90F79bf6EB2c4f870365E785982E1f101E93b906\"]}}}");
        }

        #[test]
        fn de() {
            let caps: WalletCapabilities = serde_json::from_str(
                r#"{
                    "431136": {
                        "delegation": {
                            "addresses": ["0x90f79bf6eb2c4f870365e785982e1f101e93b906"]
                        }
                    }
                }"#,
            )
            .expect("could not deser");

            assert_eq!(
                caps,
                WalletCapabilities(HashMap::from_iter([(
                    0x69420,
                    Capabilities {
                        delegation: DelegationCapability {
                            addresses: vec![address!("90f79bf6eb2c4f870365e785982e1f101e93b906")],
                        },
                    },
                )]))
            );
        }
    }
}
