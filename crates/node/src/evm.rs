//! # AlphaNet EVM configuration
//!
//! The [AlphaNetEvmConfig] type implements the [ConfigureEvm] and [ConfigureEvmEnv] traits,
//! configuring the custom AlphaNet precompiles and instructions.
//!
//! These trait implementations allow for custom precompiles and instructions to be implemented and
//! integrated in a reth node only with importing, without the need to fork the node or EVM
//! implementation.
//!
//! This currently configures the instructions defined by [`alphanet_instructions`], and the
//! precompiles defined by [`alphanet_precompile`].

use alphanet_instructions::{context::InstructionsContext, eip3074, BoxedInstructionWithOpCode};
use alphanet_precompile::{bls12_381, secp256r1};
use reth::primitives::{Address, Bytes, ChainSpec, Header, Transaction, U256};
use reth_node_api::{ConfigureEvm, ConfigureEvmEnv};
use reth_node_optimism::OptimismEvmConfig;
use revm::{
    handler::register::EvmHandler,
    inspector_handle_register,
    precompile::{PrecompileSpecId, Precompiles},
    Database, Evm, EvmBuilder, GetInspector,
};
use revm_interpreter::{opcode::InstructionTables, Host};
use revm_precompile::PrecompileWithAddress;
use revm_primitives::{CfgEnvWithHandlerCfg, TxEnv};
use std::sync::Arc;

/// Custom EVM configuration
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct AlphaNetEvmConfig;

/// Inserts the given precompiles with address in the context precompiles.
fn insert_precompiles<I>(precompiles: &mut Precompiles, precompiles_with_address: I)
where
    I: Iterator<Item = PrecompileWithAddress>,
{
    for precompile_with_address in precompiles_with_address {
        precompiles.inner.insert(precompile_with_address.0, precompile_with_address.1);
    }
}

/// Inserts the given boxed instructions with opcodes in the instructions table.
fn insert_boxed_instructions<'a, I, H>(
    table: &mut InstructionTables<'a, H>,
    boxed_instructions_with_opcodes: I,
) where
    I: Iterator<Item = BoxedInstructionWithOpCode<'a, H>>,
    H: Host + 'a,
{
    for boxed_instruction_with_opcode in boxed_instructions_with_opcodes {
        table.insert_boxed(
            boxed_instruction_with_opcode.opcode,
            boxed_instruction_with_opcode.boxed_instruction,
        );
    }
}

impl AlphaNetEvmConfig {
    /// Sets the precompiles to the EVM handler
    ///
    /// This will be invoked when the EVM is created via [ConfigureEvm::evm] or
    /// [ConfigureEvm::evm_with_inspector]
    ///
    /// This will use the default mainnet precompiles and add additional precompiles.
    fn set_precompiles<EXT, DB>(handler: &mut EvmHandler<'_, EXT, DB>)
    where
        DB: Database,
    {
        // first we need the evm spec id, which determines the precompiles
        let spec_id = handler.cfg.spec_id;

        // install the precompiles
        handler.pre_execution.load_precompiles = Arc::new(move || {
            let mut precompiles = Precompiles::new(PrecompileSpecId::from_spec_id(spec_id)).clone();
            insert_precompiles(&mut precompiles, secp256r1::precompiles());
            insert_precompiles(&mut precompiles, bls12_381::precompiles());

            precompiles.into()
        });
    }

    /// Appends custom instructions to the EVM handler
    ///
    /// This will be invoked when the EVM is created via [ConfigureEvm::evm] or
    /// [ConfigureEvm::evm_with_inspector]
    ///
    /// This will use the default mainnet instructions and append additional instructions.
    fn append_custom_instructions<EXT, DB>(
        handler: &mut EvmHandler<'_, EXT, DB>,
        instructions_context: InstructionsContext,
    ) where
        DB: Database,
    {
        if let Some(ref mut table) = handler.instruction_table {
            insert_boxed_instructions(
                table,
                eip3074::boxed_instructions(instructions_context.clone()),
            );

            instructions_context.clear();
        }
    }
}

impl ConfigureEvm for AlphaNetEvmConfig {
    fn evm<'a, DB: Database + 'a>(&self, db: DB) -> Evm<'a, (), DB> {
        let instructions_context = InstructionsContext::default();
        EvmBuilder::default()
            .with_db(db)
            .optimism()
            // add additional precompiles
            .append_handler_register(Self::set_precompiles)
            // add custom instructions
            .append_handler_register_box(Box::new(move |h| {
                Self::append_custom_instructions(h, instructions_context.clone());
                let post_execution_context = instructions_context.clone();
                #[allow(clippy::arc_with_non_send_sync)]
                {
                    h.post_execution.end = Arc::new(move |_, outcome: _| {
                        post_execution_context.clear();
                        outcome
                    });
                }
            }))
            .build()
    }

    fn evm_with_inspector<'a, DB, I>(&self, db: DB, inspector: I) -> Evm<'a, I, DB>
    where
        DB: Database + 'a,
        I: GetInspector<DB>,
    {
        let instructions_context = InstructionsContext::default();
        EvmBuilder::default()
            .with_db(db)
            .with_external_context(inspector)
            .optimism()
            // add additional precompiles
            .append_handler_register(Self::set_precompiles)
            // add custom instructions
            .append_handler_register_box(Box::new(move |h| {
                Self::append_custom_instructions(h, instructions_context.clone());
                let post_execution_context = instructions_context.clone();
                #[allow(clippy::arc_with_non_send_sync)]
                {
                    h.post_execution.end = Arc::new(move |_, outcome: _| {
                        post_execution_context.clear();
                        outcome
                    });
                }
            }))
            .append_handler_register(inspector_handle_register)
            .build()
    }
}

impl ConfigureEvmEnv for AlphaNetEvmConfig {
    type TxMeta = Bytes;

    fn fill_tx_env<T>(tx_env: &mut TxEnv, transaction: T, sender: Address, meta: Self::TxMeta)
    where
        T: AsRef<Transaction>,
    {
        OptimismEvmConfig::fill_tx_env(tx_env, transaction, sender, meta)
    }

    fn fill_cfg_env(
        cfg_env: &mut CfgEnvWithHandlerCfg,
        chain_spec: &ChainSpec,
        header: &Header,
        total_difficulty: U256,
    ) {
        OptimismEvmConfig::fill_cfg_env(cfg_env, chain_spec, header, total_difficulty);
    }
}

#[cfg(test)]
mod tests {
    use reth::primitives::{
        revm_primitives::{BlockEnv, CfgEnv, SpecId},
        Chain, ChainSpecBuilder, ForkCondition, Genesis, Hardfork,
    };

    use super::*;

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
