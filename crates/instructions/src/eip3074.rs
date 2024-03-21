use crate::InstructionWithOpCode;
use revm::{Database, Evm};
use revm_interpreter::{gas::memory_gas, next_multiple_of_32, InstructionResult, Interpreter};
use revm_primitives::{alloy_primitives::B512, keccak256, Address, B256};
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    Message, Secp256k1,
};

const AUTH_OPCODE: u8 = 0xF6;
const AUTHCALL_OPCODE: u8 = 0xF7;
const MAGIC: u8 = 0x04;
const WARM_AUTHORITY_GAS: u64 = 100;
const COLD_AUTHORITY_GAS: u64 = 2600;
const FIXED_FEE_GAS: u64 = 3100;

/// eip3074 instructions.
pub fn instructions<'a, EXT: 'a, DB: Database + 'a>(
) -> impl Iterator<Item = InstructionWithOpCode<Evm<'a, EXT, DB>>> {
    [
        InstructionWithOpCode { opcode: AUTH_OPCODE, instruction: auth_instruction::<EXT, DB> },
        InstructionWithOpCode {
            opcode: AUTHCALL_OPCODE,
            instruction: authcall_instruction::<EXT, DB>,
        },
    ]
    .into_iter()
}

// TODO: use ecrecover from revm-precompile::secp256k1.
fn ecrecover(sig: &B512, recid: u8, msg: &B256) -> Result<B256, secp256k1::Error> {
    let recid = RecoveryId::from_i32(recid as i32).expect("recovery ID is valid");
    let sig = RecoverableSignature::from_compact(sig.as_slice(), recid)?;

    let secp = Secp256k1::new();
    let msg = Message::from_digest(msg.0);
    let public = secp.recover_ecdsa(&msg, &sig)?;

    let mut hash = keccak256(&public.serialize_uncompressed()[1..]);
    hash[..12].fill(0);
    Ok(hash)
}

// keccak256(MAGIC || chainId || nonce || invokerAddress || commit)
fn compose_msg(chain_id: u64, nonce: u64, invoker_address: Address, commit: B256) -> B256 {
    let mut msg = [0u8; 129];
    msg[0] = MAGIC;
    msg[1..33].copy_from_slice(B256::left_padding_from(&chain_id.to_be_bytes()).as_slice());
    msg[33..65].copy_from_slice(B256::left_padding_from(&nonce.to_be_bytes()).as_slice());
    msg[65..97].copy_from_slice(B256::left_padding_from(invoker_address.as_slice()).as_slice());
    msg[97..].copy_from_slice(commit.as_slice());
    keccak256(msg.as_slice())
}

fn auth_instruction<EXT, DB: Database>(interp: &mut Interpreter, evm: &mut Evm<'_, EXT, DB>) {
    interp.gas.record_cost(FIXED_FEE_GAS);

    // TODO: use pop_ret! from revm-interpreter
    if interp.stack.len() < 3 {
        interp.instruction_result = InstructionResult::StackUnderflow;
        return;
    }
    // SAFETY: length checked above
    let (authority, offset, length) = unsafe { interp.stack.pop3_unsafe() };

    let authority = Address::from_slice(&authority.to_be_bytes::<32>()[12..]);

    interp.gas.record_cost(if evm.context.evm.journaled_state.state.contains_key(&authority) {
        WARM_AUTHORITY_GAS
    } else {
        COLD_AUTHORITY_GAS
    }); // authority state fee

    // TODO: use shared_memory_resize! from revm-interpreter
    let length = length.saturating_to::<usize>();
    let offset = offset.saturating_to::<usize>();
    if length != 0 {
        let size = offset.saturating_add(length);
        if size > interp.shared_memory.len() {
            let rounded_size = next_multiple_of_32(size);

            let words_num = rounded_size / 32;
            if !interp.gas.record_memory(memory_gas(words_num)) {
                interp.instruction_result = InstructionResult::MemoryLimitOOG;
                return;
            }
            interp.shared_memory.resize(rounded_size);
        }
    }

    // read yParity, r, s and commit from memory using offset and length
    let y_parity = interp.shared_memory.get_byte(offset);
    let r = interp.shared_memory.get_word(offset + 1);
    let s = interp.shared_memory.get_word(offset + 33);
    let commit = interp.shared_memory.get_word(offset + 65);

    let caller_address = evm.context.evm.env.tx.caller;
    let caller_account = match evm.context.evm.load_account(caller_address) {
        Ok(caller) => caller,
        Err(_) => {
            interp.instruction_result = InstructionResult::Stop;
            return;
        }
    };
    let nonce = caller_account.0.info.nonce;
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

    let result = if Address::from_slice(&signer[12..]) == authority {
        // TODO: set authorized context variable to authority

        B256::with_last_byte(1)
    } else {
        // TODO: authorized context variable is reset to unset value

        B256::ZERO
    };

    if let Err(e) = interp.stack.push_b256(result) {
        interp.instruction_result = e;
    }
}

fn authcall_instruction<EXT, DB: Database>(interp: &mut Interpreter, _evm: &mut Evm<'_, EXT, DB>) {
    interp.gas.record_cost(133);
}

#[cfg(test)]
mod tests {
    use super::*;
    use revm::{
        db::{CacheDB, EmptyDBTyped},
        InMemoryDB,
    };
    use revm_interpreter::{Contract, SharedMemory, Stack};
    use revm_primitives::{Account, Bytecode, Bytes, U256};
    use secp256k1::{rand, Context, PublicKey, SecretKey, Signing};
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

        let interpreter = Interpreter::new(Box::new(contract), 3000000, true);
        assert_eq!(interpreter.gas.spend(), 0);

        interpreter
    }

    fn setup_evm() -> Evm<'static, (), CacheDB<EmptyDBTyped<Infallible>>> {
        Evm::builder()
            .with_db(InMemoryDB::default())
            .append_handler_register(|handler| {
                if let Some(ref mut table) = handler.instruction_table {
                    table.insert(AUTH_OPCODE, auth_instruction);
                }
            })
            .build()
    }

    fn setup_authority<T: Context + Signing>(secp: Secp256k1<T>) -> (SecretKey, Address) {
        let secret_key = SecretKey::new(&mut rand::thread_rng());
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let hash = keccak256(&public_key.serialize_uncompressed()[1..]);
        (secret_key, Address::from_slice(&hash[12..]))
    }

    fn setup_stack(stack: &mut Stack, authority: Address) {
        let offset = 0;
        let length = 97;
        stack.push(U256::from(length)).unwrap();
        stack.push(U256::from(offset)).unwrap();
        stack.push_b256(B256::left_padding_from(authority.as_slice())).unwrap();
    }

    fn setup_shared_memory(shared_memory: &mut SharedMemory, y_parity: i32, r: &B256, s: &B256) {
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

        auth_instruction(&mut interpreter, &mut evm);
        assert_eq!(interpreter.instruction_result, InstructionResult::StackUnderflow);

        // check gas
        let expected_gas = FIXED_FEE_GAS;
        assert_eq!(expected_gas, interpreter.gas.spend());
    }

    #[test]
    fn test_auth_instruction_happy_path() {
        let mut interpreter = setup_interpreter();

        let secp = Secp256k1::new();
        let (secret_key, authority) = setup_authority(secp.clone());

        setup_stack(&mut interpreter.stack, authority);

        let msg = default_msg();

        let (y_parity, r, s) = generate_signature(secp, secret_key, msg);

        setup_shared_memory(&mut interpreter.shared_memory, y_parity, &r, &s);

        let mut evm = setup_evm();

        auth_instruction(&mut interpreter, &mut evm);

        assert_eq!(interpreter.instruction_result, InstructionResult::Continue);
        let result = interpreter.stack.pop().unwrap();
        assert_eq!(result.saturating_to::<usize>(), 1);

        // check gas
        let expected_gas = FIXED_FEE_GAS + COLD_AUTHORITY_GAS;
        assert_eq!(expected_gas, interpreter.gas.spend());

        // TODO: check authorized context variable set
    }

    #[test]
    fn test_auth_instruction_memory_expansion_gas_recorded() {
        let mut interpreter = setup_interpreter();

        let secp = Secp256k1::new();
        let (_, authority) = setup_authority(secp.clone());

        setup_stack(&mut interpreter.stack, authority);

        let mut evm = setup_evm();

        auth_instruction(&mut interpreter, &mut evm);

        assert_eq!(interpreter.instruction_result, InstructionResult::Stop);

        // check gas
        let expected_gas = FIXED_FEE_GAS + COLD_AUTHORITY_GAS + 12; // fixed_fee + cold authority + memory expansion
        assert_eq!(expected_gas, interpreter.gas.spend());
    }

    #[test]
    fn test_auth_instruction_invalid_authority() {
        let mut interpreter = setup_interpreter();

        let secp = Secp256k1::new();
        let (secret_key, _) = setup_authority(secp.clone());
        let (_, non_authority) = setup_authority(secp.clone());

        setup_stack(&mut interpreter.stack, non_authority);

        let msg = default_msg();

        let (y_parity, r, s) = generate_signature(secp, secret_key, msg);

        setup_shared_memory(&mut interpreter.shared_memory, y_parity, &r, &s);

        let mut evm = setup_evm();

        auth_instruction(&mut interpreter, &mut evm);

        assert_eq!(interpreter.instruction_result, InstructionResult::Continue);
        let result = interpreter.stack.pop().unwrap();
        assert_eq!(result.saturating_to::<usize>(), 0);
    }

    #[test]
    fn test_auth_instruction_warm_authority() {
        let mut interpreter = setup_interpreter();

        let secp = Secp256k1::new();
        let (secret_key, authority) = setup_authority(secp.clone());

        setup_stack(&mut interpreter.stack, authority);

        let msg = default_msg();

        let (y_parity, r, s) = generate_signature(secp, secret_key, msg);

        setup_shared_memory(&mut interpreter.shared_memory, y_parity, &r, &s);

        let mut evm = setup_evm();
        evm.context.evm.journaled_state.state.insert(authority, Account::default());

        auth_instruction(&mut interpreter, &mut evm);

        assert_eq!(interpreter.instruction_result, InstructionResult::Continue);
        let result = interpreter.stack.pop().unwrap();
        assert_eq!(result.saturating_to::<usize>(), 1);

        // check gas
        let expected_gas = FIXED_FEE_GAS + WARM_AUTHORITY_GAS;
        assert_eq!(expected_gas, interpreter.gas.spend());
    }

    #[test]
    fn test_auth_instruction_invalid_signature() {
        let mut interpreter = setup_interpreter();

        let secp = Secp256k1::new();
        let (secret_key, authority) = setup_authority(secp.clone());

        setup_stack(&mut interpreter.stack, authority);

        let msg = default_msg();

        let (y_parity, r, _) = generate_signature(secp, secret_key, msg);

        setup_shared_memory(&mut interpreter.shared_memory, y_parity, &r, &B256::ZERO);

        let mut evm = setup_evm();

        auth_instruction(&mut interpreter, &mut evm);

        assert_eq!(interpreter.instruction_result, InstructionResult::Stop);

        // check gas
        let expected_gas = FIXED_FEE_GAS + COLD_AUTHORITY_GAS;
        assert_eq!(expected_gas, interpreter.gas.spend());
    }
}
