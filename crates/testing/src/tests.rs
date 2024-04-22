use crate::{test_suite::TestSuite, wallet::Wallet};
use alloy::{
    dyn_abi::abi,
    providers::{Provider, ProviderBuilder},
    sol,
};
use alloy_network::EthereumSigner;
use alphanet_node::node::AlphaNetNode;
use once_cell::sync::Lazy;
use reth::{
    builder::{NodeBuilder, NodeHandle},
    tasks::TaskManager,
};
use reth_node_core::{args::RpcServerArgs, node_config::NodeConfig};
use reth_node_optimism::{args::RollupArgs, OptimismNode};
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

#[tokio::test]
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
        .with_types(AlphaNetNode::default())
        .with_components(OptimismNode::components(RollupArgs::default()))
        .launch()
        .await
        .unwrap();

    let rpc_url = node.rpc_server_handle().http_url().unwrap();
    let deployer = test_suite.signer();
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .signer(deployer)
        .on_http(Url::parse(&rpc_url).unwrap())
        .unwrap();
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
    let commit = keccak256(abi::encode(&[sender_recorder_address, data]));
    let GasSponsorInvoker::getDigestReturn { digest } =
        invoker.getDigest(commit, U256::from(signer_nonce)).call().await.unwrap();
    let (v, r, s) = signer_wallet.sign_hash(digest).await;

    let builder =
        invoker.sponsorCall(signer_address, v, r.into(), s.into(), sender_recorder_address, data);
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
