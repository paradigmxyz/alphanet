use crate::test_suite::TestSuite;
use alloy::{
    primitives::hex,
    providers::{Provider, ProviderBuilder},
    sol,
};
use alphanet_node::node::AlphaNetNode;
use once_cell::sync::Lazy;
use reth::{builder::NodeHandle, tasks::TaskManager};
use reth_chainspec::DEV;
use reth_node_builder::NodeBuilder;
use reth_node_core::{args::RpcServerArgs, node_config::NodeConfig};
use reth_primitives::Bytes;
use url::Url;

sol!(
    #[allow(clippy::too_many_arguments)]
    #[allow(missing_docs)]
    #[sol(rpc)]
    BlsG1AddCaller,
    "resources/bls12-381/out/BlsG1AddCaller.sol/BlsG1AddCaller.json"
);

#[tokio::test]
async fn test_bls12_381_g1_add() {
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
        .wallet(deployer)
        .on_http(Url::parse(&rpc_url).unwrap());
    let base_fee = provider.get_gas_price().await.unwrap();

    // Deploy caller contract
    let caller_builder = BlsG1AddCaller::deploy_builder(&provider);
    let estimate = caller_builder.estimate_gas().await.unwrap();
    let caller_address =
        caller_builder.gas(estimate).gas_price(base_fee).nonce(0).deploy().await.unwrap();
    let caller = BlsG1AddCaller::new(caller_address, &provider);

    // test input and expected output from https://github.com/ethereum/execution-spec-tests/blob/main/tests/prague/eip2537_bls_12_381_precompiles/vectors/add_G1_bls.json
    let data = hex!("0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e100000000000000000000000000000000112b98340eee2777cc3c14163dea3ec97977ac3dc5c70da32e6e87578f44912e902ccef9efe28d4a78b8999dfbca942600000000000000000000000000000000186b28d92356c4dfec4b5201ad099dbdede3781f8998ddf929b4cd7756192185ca7b8f4ef7088f813270ac3d48868a21");

    let builder = caller.call(data.into());
    let call_return = builder.call().await.unwrap();
    let expected: Bytes = hex!("000000000000000000000000000000000a40300ce2dec9888b60690e9a41d3004fda4886854573974fab73b046d3147ba5b7a5bde85279ffede1b45b3918d82d0000000000000000000000000000000006d3d887e9f53b9ec4eb6cedf5607226754b07c01ace7834f57f3e7315faefb739e59018e22c492006190fba4a870025").into();

    assert_eq!(expected, call_return._output);
}
