use crate::{test_suite::TestSuite, wallet::Wallet};
use alloy::{
    providers::{Provider, ProviderBuilder},
    sol,
};
use alloy_network::EthereumSigner;
use alphanet_node::node::AlphaNetNode;
use reth::{
    builder::{NodeBuilder, NodeHandle},
    tasks::TaskManager,
};
use reth_node_core::{args::RpcServerArgs, node_config::NodeConfig};
use reth_node_optimism::{args::RollupArgs, OptimismNode};
use reth_primitives::{Address, ChainSpec, ChainSpecBuilder, U256};
use std::sync::Arc;
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

    // manually set optimism genesis fields, see https://github.com/paradigmxyz/reth/issues/7702
    let chain_spec: Arc<ChainSpec> = ChainSpecBuilder::from(&test_suite.chain_spec())
        .regolith_activated()
        .bedrock_activated()
        .ecotone_activated()
        .build()
        .into();

    // spin up alphanet node
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
    let signer = test_suite.signer();
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .signer(signer)
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
    let _invoker = GasSponsorInvoker::new(invoker_address, &provider);

    // signer account and sign commit.
    let signer_account: EthereumSigner = Wallet::random().into();
    let signer_balance =
        provider.get_balance(signer_account.default_signer().address(), None).await.unwrap();
    assert_eq!(signer_balance, U256::ZERO);
}
