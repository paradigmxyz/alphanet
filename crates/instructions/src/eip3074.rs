//! EIP-3074 custom instructions.
//!
//! To insert the instructions in a custom EVM an instructions context must be
//! constructed and passed to the instructions themselves. It should be cleared at the end
//! of each transaction, like this:
//! ```
//! use alphanet_instructions::{context::InstructionsContext, eip3074};
//! use reth::primitives::{ChainSpec, Transaction, U256};
//! use reth_node_api::{ConfigureEvm, ConfigureEvmEnv};
//! use revm::{Database, Evm, EvmBuilder};
//! use revm_primitives::{Address, Bytes, CfgEnvWithHandlerCfg, TxEnv};
//! use std::sync::Arc;
//!
//! #[derive(Debug, Clone, Copy, Default)]
//! #[non_exhaustive]
//! struct AlphaNetEvmConfig;
//!
//! impl ConfigureEvm for AlphaNetEvmConfig {
//!     fn evm<'a, DB: Database + 'a>(&self, db: DB) -> Evm<'a, (), DB> {
//!         // this instructions context will allow to set the `authorized` context variable.
//!         let instructions_context = InstructionsContext::default();
//!         let to_capture_instructions = instructions_context.clone();
//!         let to_capture_post_execution = instructions_context.clone();
//!         EvmBuilder::default()
//!             .with_db(db)
//!             .append_handler_register_box(Box::new(move |handler| {
//!                 if let Some(ref mut table) = handler.instruction_table {
//!                     for boxed_instruction_with_opcode in
//!                         eip3074::boxed_instructions(to_capture_instructions.clone())
//!                     {
//!                         table.insert_boxed(
//!                             boxed_instruction_with_opcode.opcode,
//!                             boxed_instruction_with_opcode.boxed_instruction,
//!                         );
//!                     }
//!                 }
//!                 let post_execution_context = instructions_context.clone();
//!                 handler.post_execution.end = Arc::new(move |_, outcome: _| {
//!                     // at the end if the transaction execution we clear the instructions
//!                     post_execution_context.clear();
//!                     outcome
//!                 });
//!             }))
//!             .build()
//!     }
//! }
//!
//! impl ConfigureEvmEnv for AlphaNetEvmConfig {
//!     type TxMeta = Bytes;
//!     fn fill_tx_env<T>(_: &mut TxEnv, _: T, _: Address, _: <Self as ConfigureEvmEnv>::TxMeta)
//!     where
//!         T: AsRef<Transaction>,
//!     {
//!         todo!()
//!     }
//!     fn fill_cfg_env(
//!         _: &mut CfgEnvWithHandlerCfg,
//!         _: &ChainSpec,
//!         _: &reth::primitives::Header,
//!         _: U256,
//!     ) {
//!         todo!()
//!     }
//! }
//! ```
use crate::{context::InstructionsContext, BoxedInstructionWithOpCode};
use revm::{Database, Evm};
use revm_interpreter::{
    gas,
    instructions::host::{calc_call_gas, get_memory_input_and_out_ranges},
    pop, pop_address, push, resize_memory, CallContext, CallInputs, CallScheme, InstructionResult,
    Interpreter, InterpreterAction, Transfer,
};
use revm_precompile::secp256k1::ecrecover;
use revm_primitives::{
    alloy_primitives::B512, keccak256, spec_to_generic, Address, SpecId, B256, KECCAK_EMPTY, U256,
};

/// Numeric op code for the `AUTH` mnemonic.
const AUTH_OPCODE: u8 = 0xF6;
/// Numeric op code for the `AUTHCALL` mnemonic.
const AUTHCALL_OPCODE: u8 = 0xF7;
/// Constant used to compose the message expected by `AUTH`
const MAGIC: u8 = 0x04;
/// Gas to charge when the authority has been previously loaded.
const WARM_AUTHORITY_GAS: u64 = 100;
/// Gas to charge when the authority has not been previously loaded.
const COLD_AUTHORITY_GAS: u64 = 2600;
/// Fixed gas to charge.
const FIXED_FEE_GAS: u64 = 3100;
/// Context variable name to store (AUTH) and retrieve (AUTHCALL) the validated
/// authority.
const AUTHORIZED_VAR_NAME: &str = "authorized";

/// Generates an iterator over EIP3074 boxed instructions. Defining the
/// instructions inside a `Box` allows them to capture variables defined in its
/// environment.
pub fn boxed_instructions<'a, EXT: 'a, DB: Database + 'a>(
    context: InstructionsContext,
) -> impl Iterator<Item = BoxedInstructionWithOpCode<'a, Evm<'a, EXT, DB>>> {
    let to_capture_for_auth = context.clone();
    let to_capture_for_authcall = context.clone();

    let boxed_auth_instruction =
        Box::new(move |interpreter: &mut Interpreter, evm: &mut Evm<'a, EXT, DB>| {
            auth_instruction(interpreter, evm, &to_capture_for_auth);
        });

    let boxed_authcall_instruction =
        Box::new(move |interpreter: &mut Interpreter, evm: &mut Evm<'a, EXT, DB>| {
            authcall_instruction(interpreter, evm, &to_capture_for_authcall);
        });

    [
        BoxedInstructionWithOpCode {
            opcode: AUTH_OPCODE,
            boxed_instruction: boxed_auth_instruction,
        },
        BoxedInstructionWithOpCode {
            opcode: AUTHCALL_OPCODE,
            boxed_instruction: boxed_authcall_instruction,
        },
    ]
    .into_iter()
}

/// Composes the message expected by the AUTH instruction in this format:
/// `keccak256(MAGIC || chainId || nonce || invokerAddress || commit)`
fn compose_msg(chain_id: u64, nonce: u64, invoker_address: Address, commit: B256) -> B256 {
    let mut msg = [0u8; 129];
    msg[0] = MAGIC;
    msg[1..33].copy_from_slice(B256::left_padding_from(&chain_id.to_be_bytes()).as_slice());
    msg[33..65].copy_from_slice(B256::left_padding_from(&nonce.to_be_bytes()).as_slice());
    msg[65..97].copy_from_slice(B256::left_padding_from(invoker_address.as_slice()).as_slice());
    msg[97..].copy_from_slice(commit.as_slice());
    keccak256(msg.as_slice())
}

/// `AUTH` instruction, interprets data from the stack and memory to validate an
/// `authority` account for subsequent `AUTHCALL` invocations. See also:
///
/// <https://eips.ethereum.org/EIPS/eip-3074#auth-0xf6>
fn auth_instruction<EXT, DB: Database>(
    interp: &mut Interpreter,
    evm: &mut Evm<'_, EXT, DB>,
    ctx: &InstructionsContext,
) {
    interp.gas.record_cost(FIXED_FEE_GAS);

    pop!(interp, authority, offset, length);

    let authority = Address::from_slice(&authority.to_be_bytes::<32>()[12..]);

    interp.gas.record_cost(if evm.context.evm.journaled_state.state.contains_key(&authority) {
        WARM_AUTHORITY_GAS
    } else {
        COLD_AUTHORITY_GAS
    }); // authority state fee

    let length = length.saturating_to::<usize>();
    let offset = offset.saturating_to::<usize>();
    resize_memory!(interp, offset, length);

    // read yParity, r, s and commit from memory using offset and length
    let y_parity = interp.shared_memory.get_byte(offset);
    let r = interp.shared_memory.get_word(offset + 1);
    let s = interp.shared_memory.get_word(offset + 33);
    let commit = interp.shared_memory.get_word(offset + 65);

    let authority_account = match evm.context.evm.load_account(authority) {
        Ok(acc) => {
            if acc.0.info.code_hash != KECCAK_EMPTY {
                ctx.remove(AUTHORIZED_VAR_NAME);
                push!(interp, B256::ZERO.into());
                interp.instruction_result = InstructionResult::Continue;
                return;
            }
            acc
        }
        Err(_) => {
            interp.instruction_result = InstructionResult::Stop;
            return;
        }
    };
    let nonce = authority_account.0.info.nonce;
    let chain_id = evm.context.evm.env.cfg.chain_id;
    let msg = compose_msg(chain_id, nonce, interp.contract.address, commit);

    // check valid signature
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(r.as_slice());
    sig[32..].copy_from_slice(s.as_slice());
    let signer = match ecrecover(&B512::from_slice(&sig), y_parity, &msg) {
        Ok(signer) => signer,
        Err(_) => {
            interp.instruction_result = InstructionResult::Stop;
            return;
        }
    };

    let (to_persist_authority, result) = if Address::from_slice(&signer[12..]) == authority {
        (&signer[12..], B256::with_last_byte(1))
    } else {
        ((&[] as &[u8]), B256::ZERO)
    };

    ctx.set(AUTHORIZED_VAR_NAME, Vec::from(to_persist_authority));

    if let Err(e) = interp.stack.push_b256(result) {
        interp.instruction_result = e;
    }
}

/// `AUTHCALL` instruction, tries to read a context variable set by a previous
/// `AUTH` invocation and, if present, uses it as the `caller` in a `CALL`
/// executed as the next action. See also:
///
/// <https://eips.ethereum.org/EIPS/eip-3074#authcall-0xf7>
fn authcall_instruction<EXT, DB: Database>(
    interp: &mut Interpreter,
    evm: &mut Evm<'_, EXT, DB>,
    ctx: &InstructionsContext,
) {
    let authorized = match ctx.get(AUTHORIZED_VAR_NAME) {
        Some(address) => Address::from_slice(&address),
        None => {
            interp.instruction_result = InstructionResult::Stop;
            return;
        }
    };

    pop!(interp, local_gas_limit);
    pop_address!(interp, to);
    // max gas limit is not possible in real ethereum situation.
    let mut local_gas_limit = u64::try_from(local_gas_limit).unwrap_or(u64::MAX);

    if local_gas_limit == 0 {
        // from spec, if gas limit is 0 forward all the remaining gas
        local_gas_limit = interp.gas.remaining();
    }

    pop!(interp, value);
    if interp.is_static && value != U256::ZERO {
        interp.instruction_result = InstructionResult::CallNotAllowedInsideStatic;
        return;
    }
    pop!(interp, value_ext);
    if value_ext != U256::ZERO {
        // value ext should always be zero
        interp.instruction_result = InstructionResult::Stop;
        return;
    }

    let Some((input, return_memory_offset)) = get_memory_input_and_out_ranges(interp) else {
        return;
    };

    // calc_call_gas requires a generic SPEC argument, spec_to_generic! provides
    // it by using the spec ID set in the evm.
    let Some(mut gas_limit) = spec_to_generic!(
        evm.spec_id(),
        calc_call_gas::<Evm<'_, EXT, DB>, SPEC>(
            interp,
            evm,
            to,
            value != U256::ZERO,
            local_gas_limit,
            true,
            true
        )
    ) else {
        return;
    };

    gas!(interp, gas_limit);

    // add call stipend if there is value to be transferred.
    if value != U256::ZERO {
        gas_limit = gas_limit.saturating_add(gas::CALL_STIPEND);
    }

    // Call host to interact with target contract
    interp.next_action = InterpreterAction::Call {
        inputs: Box::new(CallInputs {
            contract: to,
            transfer: Transfer { source: interp.contract.address, target: to, value },
            input,
            gas_limit,
            context: CallContext {
                address: to,
                // set caller to the authorized address.
                caller: authorized,
                code_address: to,
                apparent_value: value,
                scheme: CallScheme::Call,
            },
            is_static: interp.is_static,
            return_memory_offset,
        }),
    };
    interp.instruction_result = InstructionResult::CallOrCreate;
}

#[cfg(test)]
mod tests {
    use super::*;
    use revm::{
        db::{CacheDB, EmptyDBTyped},
        InMemoryDB,
    };
    use revm_interpreter::{Contract, SharedMemory, Stack};
    use revm_primitives::{address, Account, Bytecode, Bytes};
    use secp256k1::{rand, Context, Message, PublicKey, Secp256k1, SecretKey, Signing};
    use std::convert::Infallible;

    fn setup_interpreter() -> Interpreter {
        let code = Bytecode::new_raw([AUTH_OPCODE, 0x00].into());
        let code_hash = code.hash_slow();
        let contract = Contract::new(
            Bytes::new(),
            code,
            code_hash,
            Address::default(),
            Address::default(),
            B256::ZERO.into(),
        );

        let interpreter = Interpreter::new(contract, 3000000, false);
        assert_eq!(interpreter.gas.spent(), 0);

        interpreter
    }

    fn setup_evm() -> Evm<'static, (), CacheDB<EmptyDBTyped<Infallible>>> {
        Evm::builder()
            .with_db(InMemoryDB::default())
            .append_handler_register_box(Box::new(|handler| {
                if let Some(ref mut table) = handler.instruction_table {
                    table.insert_boxed(AUTH_OPCODE, Box::new(move |_interpreter, _handler| {}));
                }
            }))
            .build()
    }

    fn setup_authority<T: Context + Signing>(secp: Secp256k1<T>) -> (SecretKey, Address) {
        let secret_key = SecretKey::new(&mut rand::thread_rng());
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let hash = keccak256(&public_key.serialize_uncompressed()[1..]);
        (secret_key, Address::from_slice(&hash[12..]))
    }

    fn setup_auth_stack(stack: &mut Stack, authority: Address) {
        let offset = 0;
        let length = 97;
        stack.push(U256::from(length)).unwrap();
        stack.push(U256::from(offset)).unwrap();
        stack.push_b256(B256::left_padding_from(authority.as_slice())).unwrap();
    }

    fn setup_authcall_stack(stack: &mut Stack, gas: u64, to: Address, value: u64) {
        let ret_offset = 0;
        let ret_length = 64;
        let args_offset = 64;
        let args_length = 64;
        stack.push(U256::from(ret_length)).unwrap();
        stack.push(U256::from(ret_offset)).unwrap();
        stack.push(U256::from(args_length)).unwrap();
        stack.push(U256::from(args_offset)).unwrap();
        stack.push(U256::ZERO).unwrap();
        stack.push(U256::from(value)).unwrap();
        stack.push_b256(B256::left_padding_from(to.as_slice())).unwrap();
        stack.push(U256::from(gas)).unwrap();
    }

    fn setup_auth_shared_memory(
        shared_memory: &mut SharedMemory,
        y_parity: i32,
        r: &B256,
        s: &B256,
    ) {
        shared_memory.resize(100);
        shared_memory.set_byte(0, y_parity.try_into().unwrap());
        shared_memory.set_word(1, r);
        shared_memory.set_word(33, s);
        shared_memory.set_word(65, &B256::ZERO);
    }

    fn generate_signature<T: Context + Signing>(
        secp: Secp256k1<T>,
        secret_key: SecretKey,
        msg: B256,
    ) -> (i32, B256, B256) {
        let sig = secp.sign_ecdsa_recoverable(&Message::from_digest(msg.0), &secret_key);
        let (recid, ret) = sig.serialize_compact();
        let y_parity = recid.to_i32();
        let r = B256::from_slice(&ret[..32]);
        let s = B256::from_slice(&ret[32..]);
        (y_parity, r, s)
    }

    fn default_msg() -> B256 {
        compose_msg(1, 0, Address::default(), B256::ZERO)
    }

    #[test]
    fn test_auth_instruction_stack_underflow() {
        let mut interpreter = setup_interpreter();
        let mut evm = setup_evm();

        auth_instruction(&mut interpreter, &mut evm, &InstructionsContext::default());
        assert_eq!(interpreter.instruction_result, InstructionResult::StackUnderflow);

        // check gas
        let expected_gas = FIXED_FEE_GAS;
        assert_eq!(expected_gas, interpreter.gas.spent());
    }

    #[test]
    fn test_auth_instruction_happy_path() {
        let mut interpreter = setup_interpreter();

        let secp = Secp256k1::new();
        let (secret_key, authority) = setup_authority(secp.clone());

        setup_auth_stack(&mut interpreter.stack, authority);

        let msg = default_msg();

        let (y_parity, r, s) = generate_signature(secp, secret_key, msg);

        setup_auth_shared_memory(&mut interpreter.shared_memory, y_parity, &r, &s);

        let mut evm = setup_evm();
        let context = InstructionsContext::default();

        auth_instruction(&mut interpreter, &mut evm, &context);

        assert_eq!(interpreter.instruction_result, InstructionResult::Continue);
        let result = interpreter.stack.pop().unwrap();
        assert_eq!(result.saturating_to::<usize>(), 1);

        // check gas
        let expected_gas = FIXED_FEE_GAS + COLD_AUTHORITY_GAS;
        assert_eq!(expected_gas, interpreter.gas.spent());

        assert_eq!(context.get(AUTHORIZED_VAR_NAME).unwrap(), authority.to_vec());
    }

    #[test]
    fn test_auth_instruction_memory_expansion_gas_recorded() {
        let mut interpreter = setup_interpreter();

        let secp = Secp256k1::new();
        let (_, authority) = setup_authority(secp.clone());

        setup_auth_stack(&mut interpreter.stack, authority);

        let mut evm = setup_evm();

        auth_instruction(&mut interpreter, &mut evm, &InstructionsContext::default());

        assert_eq!(interpreter.instruction_result, InstructionResult::Stop);

        // check gas
        let expected_gas = FIXED_FEE_GAS + COLD_AUTHORITY_GAS + 12; // fixed_fee + cold authority + memory expansion
        assert_eq!(expected_gas, interpreter.gas.spent());
    }

    #[test]
    fn test_auth_instruction_invalid_authority() {
        let mut interpreter = setup_interpreter();

        let secp = Secp256k1::new();
        let (secret_key, _) = setup_authority(secp.clone());
        let (_, non_authority) = setup_authority(secp.clone());

        setup_auth_stack(&mut interpreter.stack, non_authority);

        let msg = default_msg();

        let (y_parity, r, s) = generate_signature(secp, secret_key, msg);

        setup_auth_shared_memory(&mut interpreter.shared_memory, y_parity, &r, &s);

        let mut evm = setup_evm();

        auth_instruction(&mut interpreter, &mut evm, &InstructionsContext::default());

        assert_eq!(interpreter.instruction_result, InstructionResult::Continue);
        let result = interpreter.stack.pop().unwrap();
        assert_eq!(result.saturating_to::<usize>(), 0);
    }

    #[test]
    fn test_auth_instruction_warm_authority() {
        let mut interpreter = setup_interpreter();

        let secp = Secp256k1::new();
        let (secret_key, authority) = setup_authority(secp.clone());

        setup_auth_stack(&mut interpreter.stack, authority);

        let msg = default_msg();

        let (y_parity, r, s) = generate_signature(secp, secret_key, msg);

        setup_auth_shared_memory(&mut interpreter.shared_memory, y_parity, &r, &s);

        let mut evm = setup_evm();
        evm.context.evm.journaled_state.state.insert(authority, Account::default());

        auth_instruction(&mut interpreter, &mut evm, &InstructionsContext::default());

        assert_eq!(interpreter.instruction_result, InstructionResult::Continue);
        let result = interpreter.stack.pop().unwrap();
        assert_eq!(result.saturating_to::<usize>(), 1);

        // check gas
        let expected_gas = FIXED_FEE_GAS + WARM_AUTHORITY_GAS;
        assert_eq!(expected_gas, interpreter.gas.spent());
    }

    #[test]
    fn test_auth_instruction_invalid_signature() {
        let mut interpreter = setup_interpreter();

        let secp = Secp256k1::new();
        let (secret_key, authority) = setup_authority(secp.clone());

        setup_auth_stack(&mut interpreter.stack, authority);

        let msg = default_msg();

        let (y_parity, r, _) = generate_signature(secp, secret_key, msg);

        setup_auth_shared_memory(&mut interpreter.shared_memory, y_parity, &r, &B256::ZERO);

        let mut evm = setup_evm();

        auth_instruction(&mut interpreter, &mut evm, &InstructionsContext::default());

        assert_eq!(interpreter.instruction_result, InstructionResult::Stop);

        // check gas
        let expected_gas = FIXED_FEE_GAS + COLD_AUTHORITY_GAS;
        assert_eq!(expected_gas, interpreter.gas.spent());
    }

    #[test]
    fn test_auth_instruction_extcodesize() {
        let mut interpreter = setup_interpreter();

        let secp = Secp256k1::new();
        let (secret_key, authority) = setup_authority(secp.clone());

        setup_auth_stack(&mut interpreter.stack, authority);

        let msg = default_msg();

        let (y_parity, r, s) = generate_signature(secp, secret_key, msg);

        setup_auth_shared_memory(&mut interpreter.shared_memory, y_parity, &r, &s);

        let mut evm = setup_evm();
        evm.context.evm.journaled_state.state.insert(authority, Account::default());
        evm.context
            .evm
            .journaled_state
            .set_code(authority, Bytecode::new_raw([AUTH_OPCODE, 0x00].into()));

        let context = InstructionsContext::default();
        auth_instruction(&mut interpreter, &mut evm, &context);

        assert_eq!(interpreter.instruction_result, InstructionResult::Continue);
        assert_eq!(context.get(AUTHORIZED_VAR_NAME), None);
        pop!(interpreter, auth_result);
        assert_eq!(auth_result.saturating_to::<usize>(), 0);
    }

    #[test]
    fn test_authcall_instruction_authorized_not_set() {
        let mut interpreter = setup_interpreter();
        let mut evm = setup_evm();

        authcall_instruction(&mut interpreter, &mut evm, &InstructionsContext::default());
        assert_eq!(interpreter.instruction_result, InstructionResult::Stop);

        // check gas
        let expected_gas = 0;
        assert_eq!(expected_gas, interpreter.gas.spent());
    }

    #[test]
    fn test_authcall_instruction_stack_underflow() {
        let mut interpreter = setup_interpreter();
        let mut evm = setup_evm();

        let authorized = address!("cafecafecafecafecafecafecafecafecafecafe");
        let ctx = InstructionsContext::default();
        ctx.set(AUTHORIZED_VAR_NAME, authorized.to_vec());

        authcall_instruction(&mut interpreter, &mut evm, &ctx);
        assert_eq!(interpreter.instruction_result, InstructionResult::StackUnderflow);

        // check gas
        let expected_gas = 0;
        assert_eq!(expected_gas, interpreter.gas.spent());
    }

    #[test]
    fn test_authcall_instruction_happy_path() {
        let mut interpreter = setup_interpreter();

        let gas_limit = 30_000;
        let to = address!("cafecafecafecafecafecafecafecafecafecafe");
        let value = 100;
        setup_authcall_stack(&mut interpreter.stack, gas_limit, to, value);

        let mut evm = setup_evm();
        let ctx = InstructionsContext::default();
        let authorized = address!("beefbeefbeefbeefbeefbeefbeefbeefbeefbeef");
        ctx.set(AUTHORIZED_VAR_NAME, authorized.to_vec());
        authcall_instruction(&mut interpreter, &mut evm, &ctx);

        assert_eq!(interpreter.instruction_result, InstructionResult::CallOrCreate);

        // check gas
        let expected_gas = 66612;
        assert_eq!(expected_gas, interpreter.gas.spent());

        // check next action
        let value = U256::from(value);
        match interpreter.next_action {
            InterpreterAction::Call { inputs } => {
                assert_eq!(inputs.contract, to);
                assert_eq!(
                    inputs.transfer,
                    Transfer { source: interpreter.contract.address, target: to, value }
                );
                assert_eq!(inputs.input, Bytes::from(&[0_u8; 64]));
                assert_eq!(inputs.gas_limit, gas_limit + gas::CALL_STIPEND);
                assert_eq!(
                    inputs.context,
                    CallContext {
                        address: to,
                        // set caller to the authorized address.
                        caller: authorized,
                        code_address: to,
                        apparent_value: value,
                        scheme: CallScheme::Call,
                    }
                );
                assert_eq!(inputs.is_static, interpreter.is_static);
                assert_eq!(inputs.return_memory_offset, (0..64));
            }
            _ => panic!("unexpected next action!"),
        }
    }
}
