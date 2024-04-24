# alphanet

<!-- [![Crates.io][crates-badge]][crates-io] -->
<!-- [![Downloads][downloads-badge]][crates-io] -->
[![MIT License][mit-badge]][mit-url]
[![Apache-2.0 License][apache-badge]][apache-url]
[![CI Status][actions-badge]][actions-url]

## What is Reth AlphaNet?

Reth AlphaNet is a testnet OP Stack rollup aimed at enabling experimentation of bleeding edge Ethereum Research.
AlphaNet is __not__ a fork of reth.
AlphaNet implements traits provided by the [reth node builder API](https://paradigmxyz.github.io/reth/docs/reth_node_builder/index.html), allowing implementation of precompiles and instructions of experimental EIPs without forking the node.

Specifically, AlphaNet currently implements the following EIPs:
 - [EIP-3074](https://eips.ethereum.org/EIPS/eip-3074): `AUTH` and `AUTHCALL` instructions.
 - [EIP-7212](https://eips.ethereum.org/EIPS/eip-7212): Precompile for secp256r1 curve support.
 - [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537): Precompiles for BLS12-381 curve operations.

### Why AlphaNet?

AlphaNet has 2 goals:
1. Showcase Reth's performance at the extremes. We intend to launch a hosted version of AlphaNet on [Conduit](https://conduit.xyz/), targeting 50mgas/s, and eventually ramping up to 1ggas/s and beyond. In the process we hope to hit the state growth performance bottleneck, and discover ways to solve it. If our hosted chains end up getting too big, we may possibly restart the experiment from zero, and try again.
2. Showcase how Reth's modular architecture can serve as a distribution channel for research ideas. Specifically,
AlphaNet's node extensions were chosen for their ability to enable applications that enhance the onchain user experience, and
drastically reduce cost for existing applications that improve UX.

### AlphaNet Local Development

AlphaNet does not yet have a running testnet, but can be run locally for development and testing purposes. To do this, the binary can be run with the `--dev` flag, which will start the node with a development configuration.

First, alphanet should be built locally:
```bash
git clone https://github.com/paradigmxyz/alphanet
cd alphanet
cargo install --path bin/alphanet
```

```bash
alphanet node --chain etc/alphanet-genesis.json --dev --http --http.api all
```

This will start the node with a development configuration, and expose the HTTP API on `http://localhost:8545`.

To use 3074-enabled foundry, use [eip-3074-foundry](https://github.com/clabby/eip-3074-foundry) and follow installation instructions.

### Running AlphaNet

⚠️ AlphaNet does not yet have a running testnet, please use the local development instructions above! ⚠️

Running AlphaNet will require running additional infrastructure for the archival L1 node. These instructions are a guide for
running the AlphaNet OP-stack node only.

For instructions on running the full AlphaNet OP stack, including the L1 node, see the [Reth book section on running the OP stack](https://paradigmxyz.github.io/reth/run/optimism.html), using the `alphanet` binary instead of `op-reth`.

#### Running the alphanet execution node

To run AlphaNet from source, clone the repository and run the following commands:

```bash
git clone https://github.com/paradigmxyz/alphanet.git
cd alphanet
cargo install --path bin/alphanet
alphanet node
    --chain etc/alphanet-genesis.json \
    --rollup.sequencer-http <TODO> \
    --http \
    --ws \
    --authrpc.port 9551 \
    --authrpc.jwtsecret /path/to/jwt.hex
```

#### Running op-node with the alphanet configuration

Once `alphanet` is started, [`op-node`](https://github.com/ethereum-optimism/optimism/tree/develop/op-node) can be run with the
included `alphanet-rollup.json`:

```bash
cd alphanet/
op-node \
    --rollup.config ./etc/alphanet-rollup.json \
    --l1=<your-sepolia-L1-rpc> \
    --l2=http://localhost:9551 \
    --l2.jwt-secret=/path/to/jwt.hex \
    --rpc.addr=0.0.0.0 \
    --rpc.port=7000 \
    --l1.trustrpc
```

### Security

See [SECURITY.md](SECURITY.md).

### Note on EIP-3074 integration tests

If you are modifying the EIP-3074 solidity smart contracts used in the
`alphanet-testing` crate you should regenerate the built artifacts with:
```bash
$ make build-eip3074-bytecode
```
This command uses the docker image from the [foundry-alphanet] repo which contains
patched versions of solc and forge compatible with the instructions introduced
by EIP-3074.

The changes in the artifacts should be committed to this repo, this way we don't
have to rely on docker being available to generate the artifacts and run the
tests. There's a CI step that will check if the committed artifacts match the
smart contracts source code.

#### License

<sup>
Licensed under either of <a href="LICENSE-APACHE">Apache License, Version
2.0</a> or <a href="LICENSE-MIT">MIT license</a> at your option.
</sup>

<br>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in these crates by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.
</sub>

<!-- [crates-badge]: https://img.shields.io/crates/v/alphanet.svg -->
<!-- [crates-io]: https://crates.io/crates/alphanet -->
<!-- [downloads-badge]: https://img.shields.io/crates/d/alphanet -->
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[apache-badge]: https://img.shields.io/badge/license-Apache--2.0-blue.svg
[mit-url]: LICENSE-MIT
[apache-url]: LICENSE-APACHE
[actions-badge]: https://github.com/paradigmxyz/alphanet/workflows/unit/badge.svg
[actions-url]: https://github.com/paradigmxyz/alphanet/actions?query=workflow%3ACI+branch%3Amain
[foundry-alphanet]: https://github.com/paradigmxyz/foundry-alphanet
