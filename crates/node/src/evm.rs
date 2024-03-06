use alphanet_precompile::secp256r1::P256VERIFY;
use reth::{
    primitives::{
        revm::{config::revm_spec, env::fill_op_tx_env},
        revm_primitives::{AnalysisKind, CfgEnvWithHandlerCfg, TxEnv},
        Address, Bytes, ChainSpec, Head, Header, Transaction, U256,
    },
    revm::{
        handler::register::EvmHandler,
        precompile::{PrecompileSpecId, Precompiles},
        Database, Evm, EvmBuilder,
    },
};
use reth_node_api::{ConfigureEvm, ConfigureEvmEnv};
use std::sync::Arc;

/// Custom EVM configuration
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct AlphaNetEvmConfig;

impl AlphaNetEvmConfig {
    /// Sets the precompiles to the EVM handler
    ///
    /// This will be invoked when the EVM is created via [ConfigureEvm::evm] or
    /// [ConfigureEvm::evm_with_inspector]
    ///
    /// This will use the default mainnet precompiles and add additional precompiles.
    pub fn set_precompiles<EXT, DB>(handler: &mut EvmHandler<'_, EXT, DB>)
    where
        DB: Database,
    {
        // first we need the evm spec id, which determines the precompiles
        let spec_id = handler.cfg.spec_id;

        // install the precompiles
        handler.pre_execution.load_precompiles = Arc::new(move || {
            let mut precompiles = Precompiles::new(PrecompileSpecId::from_spec_id(spec_id)).clone();
            precompiles.inner.insert(P256VERIFY.0, P256VERIFY.1);
            precompiles
        });
    }
}

impl ConfigureEvm for AlphaNetEvmConfig {
    fn evm<'a, DB: Database + 'a>(&self, db: DB) -> Evm<'a, (), DB> {
        EvmBuilder::default()
            .with_db(db)
            // add additional precompiles
            .append_handler_register(Self::set_precompiles)
            .build()
    }

    fn evm_with_inspector<'a, DB: Database + 'a, I>(&self, db: DB, inspector: I) -> Evm<'a, I, DB> {
        EvmBuilder::default()
            .with_db(db)
            .with_external_context(inspector)
            // add additional precompiles
            .append_handler_register(Self::set_precompiles)
            .build()
    }
}

impl ConfigureEvmEnv for AlphaNetEvmConfig {
    type TxMeta = Bytes;

    fn fill_tx_env<T>(tx_env: &mut TxEnv, transaction: T, sender: Address, meta: Self::TxMeta)
    where
        T: AsRef<Transaction>,
    {
        fill_op_tx_env(tx_env, transaction, sender, meta)
    }

    fn fill_cfg_env(
        cfg_env: &mut CfgEnvWithHandlerCfg,
        chain_spec: &ChainSpec,
        header: &Header,
        total_difficulty: U256,
    ) {
        let spec_id = revm_spec(
            chain_spec,
            Head {
                number: header.number,
                timestamp: header.timestamp,
                difficulty: header.difficulty,
                total_difficulty,
                hash: Default::default(),
            },
        );

        cfg_env.chain_id = chain_spec.chain().id();
        cfg_env.perf_analyse_created_bytecodes = AnalysisKind::Analyse;

        cfg_env.handler_cfg.spec_id = spec_id;
        cfg_env.handler_cfg.is_optimism = chain_spec.is_optimism();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth::primitives::{
        revm_primitives::{BlockEnv, CfgEnv, SpecId},
        Chain, ChainSpecBuilder, ForkCondition, Genesis, Hardfork,
    };

    #[test]
    fn test_fill_cfg_and_block_env() {
        let mut cfg_env = CfgEnvWithHandlerCfg::new_with_spec_id(CfgEnv::default(), SpecId::LATEST);
        let mut block_env = BlockEnv::default();
        let header = Header::default();
        let chain_spec = ChainSpecBuilder::default()
            .chain(Chain::optimism_mainnet())
            .genesis(Genesis::default())
            .with_fork(Hardfork::Frontier, ForkCondition::Block(0))
            .build();
        let total_difficulty = U256::ZERO;

        AlphaNetEvmConfig::fill_cfg_and_block_env(
            &mut cfg_env,
            &mut block_env,
            &chain_spec,
            &header,
            total_difficulty,
        );

        assert_eq!(cfg_env.chain_id, chain_spec.chain().id());
    }
}
