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

use alloy_primitives::{map::HashMap, Address, ChainId, TxHash, TxKind, U256};
use alloy_rpc_types::TransactionRequest;
use jsonrpsee::{
    core::{async_trait, RpcResult},
    proc_macros::rpc,
};
use reth_optimism_rpc::SequencerClient;
use reth_primitives::{revm_primitives::Bytecode, BlockId};
use reth_rpc_eth_api::{
    helpers::{EthCall, EthState, FullEthApi},
    EthApiTypes,
};
use reth_storage_api::{StateProvider, StateProviderFactory};
use reth_transaction_pool::TransactionPool;
use serde::{Deserialize, Serialize};
use tracing::trace;

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

impl WalletCapabilities {
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

#[derive(Debug, thiserror::Error)]
pub enum AlphaNetWalletError {
    #[error("tx value not zero")]
    ValueNotZero,
    #[error("tx from field is set")]
    FromSet,
    #[error("tx nonce is set")]
    NonceSet,
    #[error("invalid authorization address")]
    InvalidAuthorization,
    #[error("the authority of an authorization item is the sequencer")]
    AuthorityIsSequencer,
    #[error("the destination of the transaction is not a delegated account")]
    IllegalDestination,
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

pub struct AlphaNetWallet<Provider, Pool, Eth> {
    provider: Provider,
    pool: Pool,
    sequencer_client: Option<SequencerClient>,
    chain_id: ChainId,
    capabilities: WalletCapabilities,
    eth_api: Eth,
}

impl<Provider, Pool, Eth> AlphaNetWallet<Provider, Pool, Eth> {
    pub fn new(
        provider: Provider,
        pool: Pool,
        eth_api: Eth,
        sequencer_client: Option<SequencerClient>,
        chain_id: ChainId,
        valid_designations: Vec<Address>,
    ) -> Self {
        let mut caps = HashMap::default();
        caps.insert(
            chain_id,
            Capabilities { delegation: DelegationCapability { addresses: valid_designations } },
        );

        Self {
            provider,
            pool,
            eth_api,
            sequencer_client,
            chain_id,
            capabilities: WalletCapabilities(caps),
        }
    }
}

#[async_trait]
impl<Provider, Pool, Eth> AlphaNetWalletApiServer for AlphaNetWallet<Provider, Pool, Eth>
where
    Pool: TransactionPool + Clone + 'static,
    Provider: StateProviderFactory + Send + Sync + 'static,
    Eth: FullEthApi + Send + Sync + 'static,
{
    fn get_capabilities(&self) -> RpcResult<WalletCapabilities> {
        trace!(target: "rpc::wallet", "Serving wallet_getCapabilities");
        Ok(self.capabilities.clone())
    }

    async fn send_transaction(&self, mut request: TransactionRequest) -> RpcResult<TxHash> {
        trace!(target: "rpc::wallet", ?request, "Serving wallet_sendTransaction");

        // reject transactions that have a non-zero value to prevent draining the sequencer.
        if request.value.is_some_and(|val| val > U256::ZERO) {
            return Err(AlphaNetWalletError::ValueNotZero.into());
        }

        // reject transactions that have from set, as this will be the sequencer.
        if request.from.is_some() {
            return Err(AlphaNetWalletError::FromSet.into());
        }

        // reject transaction requests that have nonce set, as this is managed by the sequencer.
        if request.nonce.is_some() {
            return Err(AlphaNetWalletError::NonceSet.into());
        }
        // set nonce and chain id
        request.chain_id = Some(self.chain_id);
        // gas estimation

        let valid_delegations: &[Address] = self
            .capabilities
            .get(self.chain_id)
            .map(|caps| caps.delegation.addresses.as_ref())
            .unwrap_or_default();
        if let Some(authorizations) = &request.authorization_list {
            // check that all auth items delegate to a valid address
            if authorizations.iter().any(|auth| !valid_delegations.contains(&auth.address)) {
                return Err(AlphaNetWalletError::InvalidAuthorization.into());
            }
        } else {
            // if to is set, ensure that it is an account that delegates to a whitelisted address
            // if this is not a 7702 tx
            match request.to {
                Some(TxKind::Call(addr)) => {
                    let state = self.provider.latest().unwrap();
                    if let Ok(Some(code)) = state.account_code(addr) {
                        match code.0 {
                            Bytecode::Eip7702(code) => {
                                // not a whitelisted address
                                if !valid_delegations.contains(&code.address()) {
                                    return Err(AlphaNetWalletError::IllegalDestination.into());
                                }
                            }
                            // not a 7702 account
                            _ => return Err(AlphaNetWalletError::IllegalDestination.into()),
                        }
                    } else {
                        // no bytecode
                        return Err(AlphaNetWalletError::IllegalDestination.into());
                    }
                }
                // create tx's disallowed
                _ => return Err(AlphaNetWalletError::IllegalDestination.into()),
            }
        }

        let tx_count =
            EthState::transaction_count(&self.eth_api, Address::ZERO, Some(BlockId::pending()))
                .await
                .map_err(Into::into)?;

        let estimate = EthCall::estimate_gas_at(&self.eth_api, request, BlockId::latest(), None)
            .await
            .map_err(Into::into)?;
        // build and sign
        // add to pool, or send to sequencer
        todo!()
    }
}
