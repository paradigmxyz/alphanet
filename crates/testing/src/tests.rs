use alloy_eips::{eip2718::Encodable2718, eip7702::Authorization};
use alphanet_node::{chainspec::ALPHANET_DEV, node::AlphaNetNode};
use reth_e2e_test_utils::{setup, transaction::TransactionTestContext};
use reth_node_core::rpc::types::{engine::PayloadAttributes, TransactionInput, TransactionRequest};
use reth_node_optimism::OptimismPayloadBuilderAttributes;
use reth_payload_builder::EthPayloadBuilderAttributes;
use reth_primitives::{Address, TxKind, B256, U256};

#[tokio::test]
async fn can_progress_7702() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (mut nodes, _tasks, wallet) = setup::<AlphaNetNode>(1, ALPHANET_DEV.clone(), false).await?;

    let mut node = nodes.pop().unwrap();

    // deploy contract
    let tx = TransactionRequest {
        nonce: Some(0),
        value: Some(U256::from(0)),
        to: Some(TxKind::Call(Address::random())),
        gas: Some(210000),
        max_fee_per_gas: Some(20e9 as u128),
        max_priority_fee_per_gas: Some(20e9 as u128),
        chain_id: Some(41144114),
        input: TransactionInput { input: None, data: None },
        ..Default::default()
    };
    let signed_tx = TransactionTestContext::sign_tx(wallet.inner.clone(), tx).await;
    let raw_tx = signed_tx.encoded_2718().into();

    // inject tx
    let _ = node.rpc.inject_tx(raw_tx).await?;

    // make the node advance
    let _ = node.advance_block(vec![], optimism_payload_attributes).await?;

    // delegate account to contract
    let authorization = Authorization {
        chain_id: U256::from(41144114),
        address: Address::ZERO, // todo
        nonce: 1,
    };
    // todo: sign auth
    let tx = TransactionRequest {
        nonce: Some(1),
        value: Some(U256::from(0)),
        to: Some(TxKind::Call(Address::random())),
        gas: Some(210000),
        max_fee_per_gas: Some(20e9 as u128),
        max_priority_fee_per_gas: Some(20e9 as u128),
        chain_id: Some(41144114),
        input: TransactionInput { input: None, data: None },
        // todo: authorization list
        ..Default::default()
    };
    let signed_tx = TransactionTestContext::sign_tx(wallet.inner, tx).await;
    let raw_tx = signed_tx.encoded_2718().into();

    // inject tx
    let tx_hash = node.rpc.inject_tx(raw_tx).await?;

    // make the node advance
    let (payload, _) = node.advance_block(vec![], optimism_payload_attributes).await?;

    let block_hash = payload.block().hash();
    let block_number = payload.block().number;

    // assert the block has been committed to the blockchain
    node.assert_new_block(tx_hash, block_hash, block_number).await?;

    Ok(())
}

/// Helper function to create a new eth payload attributes
pub(crate) fn optimism_payload_attributes(timestamp: u64) -> OptimismPayloadBuilderAttributes {
    let attributes = PayloadAttributes {
        timestamp,
        prev_randao: B256::ZERO,
        suggested_fee_recipient: Address::ZERO,
        withdrawals: Some(vec![]),
        parent_beacon_block_root: Some(B256::ZERO),
    };

    OptimismPayloadBuilderAttributes {
        payload_attributes: EthPayloadBuilderAttributes::new(B256::ZERO, attributes),
        transactions: vec![],
        no_tx_pool: false,
        gas_limit: Some(30_000_000),
    }
}
