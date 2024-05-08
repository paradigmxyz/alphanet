use crate::{test_suite::TestSuite, wallet::Wallet};
use alloy::{
    providers::{Provider, ProviderBuilder},
    sol,
    sol_types::SolValue,
};
use alloy_network::EthereumSigner;
use alphanet_node::node::AlphaNetNode;
use once_cell::sync::Lazy;
use reth::{
    builder::{NodeBuilder, NodeHandle},
    tasks::TaskManager,
};
use reth_node_core::{args::RpcServerArgs, node_config::NodeConfig};
use reth_primitives::{keccak256, Address, BlockId, DEV, U256};
use url::Url;

sol!(
    #[allow(clippy::too_many_arguments)]
    #[allow(missing_docs)]
    #[sol(rpc)]
    GasSponsorInvoker,
    "resources/eip3074/out/GasSponsorInvoker.sol/GasSponsorInvoker.json"
);

sol!(
    #[allow(clippy::too_many_arguments)]
    #[allow(missing_docs)]
    #[sol(rpc)]
    SenderRecorder,
    "resources/eip3074/out/SenderRecorder.sol/SenderRecorder.json"
);
use serial_test::serial;

#[tokio::test]
#[serial]
async fn test_eip3074_integration() {
    reth_tracing::init_test_tracing();
    let tasks = TaskManager::current();
    let test_suite = TestSuite::new();

    // spin up alphanet node
    let chain_spec = Lazy::force(&DEV).clone();
    let node_config = NodeConfig::test()
        .dev()
        .with_chain(chain_spec)
        .with_rpc(RpcServerArgs::default().with_unused_ports().with_http());
    let NodeHandle { node, .. } = NodeBuilder::new(node_config)
        .testing_node(tasks.executor())
        .node(AlphaNetNode::default())
        .launch()
        .await
        .unwrap();

    let rpc_url = node.rpc_server_handle().http_url().unwrap();
    let deployer = test_suite.signer();
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .signer(deployer)
        .on_http(Url::parse(&rpc_url).unwrap());
    let base_fee = provider.get_gas_price().await.unwrap();

    // Deploy sender recorder contract.
    let sender_recorder_builder = SenderRecorder::deploy_builder(&provider);
    let estimate = sender_recorder_builder.estimate_gas().await.unwrap();
    let sender_recorder_address =
        sender_recorder_builder.gas(estimate).gas_price(base_fee).nonce(0).deploy().await.unwrap();
    let sender_recorder = SenderRecorder::new(sender_recorder_address, &provider);
    let SenderRecorder::lastSenderReturn { _0 } =
        sender_recorder.lastSender().call().await.unwrap();
    assert_eq!(_0, Address::ZERO);

    // Deploy invoker contract.
    let invoker_builder = GasSponsorInvoker::deploy_builder(&provider);
    let estimate = invoker_builder.estimate_gas().await.unwrap();
    let invoker_address =
        invoker_builder.gas(estimate).gas_price(base_fee).nonce(1).deploy().await.unwrap();
    let invoker = GasSponsorInvoker::new(invoker_address, &provider);

    // signer account.
    let signer_wallet = Wallet::random();
    let signer_account: EthereumSigner = signer_wallet.clone().into();
    let signer_address = signer_account.default_signer().address();
    let signer_balance = provider.get_balance(signer_address, BlockId::latest()).await.unwrap();
    assert_eq!(signer_balance, U256::ZERO);
    let signer_nonce =
        provider.get_transaction_count(signer_address, BlockId::latest()).await.unwrap();

    // abi encoded method call.
    let binding = sender_recorder.recordSender();
    let data = reth_primitives::Bytes(binding.calldata().0.clone());

    // commit, digest and signature.
    let commit = keccak256((sender_recorder_address, data.clone()).abi_encode_sequence());
    let GasSponsorInvoker::getDigestReturn { digest } =
        invoker.getDigest(commit, U256::from(signer_nonce)).call().await.unwrap();
    let (v, r, s) = signer_wallet.sign_hash(digest).await;

    let builder = invoker.sponsorCall(
        signer_address,
        v,
        r.into(),
        s.into(),
        sender_recorder_address,
        data,
        U256::ZERO,
    );
    let estimate = builder.estimate_gas().await.unwrap();
    let receipt = builder
        .gas(estimate)
        .gas_price(base_fee)
        .nonce(2)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await;
    assert!(receipt.is_ok());

    let SenderRecorder::lastSenderReturn { _0 } =
        sender_recorder.lastSender().call().await.unwrap();
    assert_eq!(_0, signer_address);
}

#[tokio::test]
#[serial]
async fn test_eip3074_send_eth() {
    reth_tracing::init_test_tracing();
    let tasks = TaskManager::current();
    let test_suite = TestSuite::new();

    // spin up alphanet node
    let chain_spec = Lazy::force(&DEV).clone();
    let node_config = NodeConfig::test()
        .dev()
        .with_chain(chain_spec)
        .with_rpc(RpcServerArgs::default().with_unused_ports().with_http());
    let NodeHandle { node, .. } = NodeBuilder::new(node_config)
        .testing_node(tasks.executor())
        .node(AlphaNetNode::default())
        .launch()
        .await
        .unwrap();

    let rpc_url = node.rpc_server_handle().http_url().unwrap();
    let deployer = test_suite.signer();
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .signer(deployer)
        .on_http(Url::parse(&rpc_url).unwrap());
    let base_fee = provider.get_gas_price().await.unwrap();

    // Deploy invoker contract.
    let invoker_builder = GasSponsorInvoker::deploy_builder(&provider);
    let estimate = invoker_builder.estimate_gas().await.unwrap();
    let invoker_address =
        invoker_builder.gas(estimate).gas_price(base_fee).nonce(0).deploy().await.unwrap();
    let invoker = GasSponsorInvoker::new(invoker_address, &provider);

    // signer account.
    let signer_wallet = Wallet::new(1);
    let signer_account: EthereumSigner = signer_wallet.clone().into();
    let signer_address = signer_account.default_signer().address();
    let start_signer_balance =
        provider.get_balance(signer_address, BlockId::latest()).await.unwrap();
    assert!(start_signer_balance.ne(&U256::ZERO));
    let signer_nonce =
        provider.get_transaction_count(signer_address, BlockId::latest()).await.unwrap();

    let data = reth_primitives::Bytes::new();

    // receiver account
    let receiver_wallet = Wallet::random();
    let receiver_account: EthereumSigner = receiver_wallet.clone().into();
    let receiver_address = receiver_account.default_signer().address();
    let receiver_balance = provider.get_balance(receiver_address, BlockId::latest()).await.unwrap();
    assert_eq!(receiver_balance, U256::ZERO);

    // commit, digest and signature.
    let commit = keccak256((receiver_address, data.clone()).abi_encode_sequence());
    let GasSponsorInvoker::getDigestReturn { digest } =
        invoker.getDigest(commit, U256::from(signer_nonce)).call().await.unwrap();
    let (v, r, s) = signer_wallet.sign_hash(digest).await;

    let amount = U256::from_str_radix("1000000000000000000", 10).unwrap(); // 1 ETH

    let builder =
        invoker.sponsorCall(signer_address, v, r.into(), s.into(), receiver_address, data, amount);
    let estimate = builder.estimate_gas().await.unwrap();
    let receipt = builder
        .gas(estimate)
        .gas_price(base_fee)
        .nonce(1)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await;
    assert!(receipt.is_ok());

    let receiver_balance = provider.get_balance(receiver_address, BlockId::latest()).await.unwrap();
    assert_eq!(receiver_balance, amount);
    let end_signer_balance = provider.get_balance(signer_address, BlockId::latest()).await.unwrap();
    assert!(end_signer_balance.eq(&start_signer_balance.saturating_sub(amount)));
}
