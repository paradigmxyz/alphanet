use revm::{Database, Evm};
use revm_interpreter::{
    gas::memory_gas, next_multiple_of_32, Instruction, InstructionResult, Interpreter,
};
use revm_primitives::{alloy_primitives::B512, keccak256, Address, B256};
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    Message, Secp256k1,
};

const AUTH_OPCODE: u8 = 0xF6;
const AUTHCALL_OPCODE: u8 = 0xF7;

/// Type alias for a function pointer that initializes instruction objects.
pub type InstructionInitializer<'a, EXT, DB> = fn() -> InstructionWithOpCode<Evm<'a, EXT, DB>>;

/// Constructs and returns a collection of instruction initializers.
pub fn initializers<'a, EXT, DB: Database>() -> Vec<InstructionInitializer<'a, EXT, DB>> {
    vec![auth::<EXT, DB>, authcall::<EXT, DB>]
}

/// Association of OpCode and correspondent instruction.
#[derive(Clone, Debug)]
pub struct InstructionWithOpCode<H> {
    /// Opcode.
    pub opcode: u8,
    /// Instruction.
    pub instruction: Instruction<H>,
}

// TODO: use ecrecover from revm-precompile::secp256k1.
fn ecrecover(sig: &B512, recid: u8, msg: &B256) -> Result<B256, secp256k1::Error> {
    let recid = RecoveryId::from_i32(recid as i32).expect("recovery ID is valid");
    let sig = RecoverableSignature::from_compact(sig.as_slice(), recid)?;

    let secp = Secp256k1::new();
    let msg = Message::from_digest_slice(msg.as_slice())?;
    let public = secp.recover_ecdsa(&msg, &sig)?;

    let mut hash = keccak256(&public.serialize_uncompressed()[1..]);
    hash[..12].fill(0);
    Ok(hash)
}

// keccak256(MAGIC || chainId || nonce || invokerAddress || commit)
fn compose_msg(chain_id: u64, nonce: u64, invoker_address: Address, commit: B256) -> B256 {
    const MAGIC: u8 = 0x04;

    let mut msg = Vec::<u8>::with_capacity(129);
    msg.push(MAGIC);
    msg.extend_from_slice(B256::left_padding_from(&chain_id.to_be_bytes()).as_slice());
    msg.extend_from_slice(B256::left_padding_from(&nonce.to_be_bytes()).as_slice());
    msg.extend_from_slice(B256::left_padding_from(invoker_address.as_slice()).as_slice());
    msg.extend_from_slice(commit.as_slice());
    keccak256(msg.as_slice())
}

fn auth_instruction<EXT, DB: Database>(interp: &mut Interpreter, evm: &mut Evm<'_, EXT, DB>) {
    interp.gas.record_cost(3100); // fixed fee

    // TODO: use pop_ret! from revm-interpreter
    if interp.stack.len() < 3 {
        interp.instruction_result = InstructionResult::StackUnderflow;
        return;
    }
    // SAFETY: length checked above
    let (authority, offset, length) = unsafe { interp.stack.pop3_unsafe() };

    let authority = Address::from_slice(&authority.to_be_bytes::<32>()[12..]);

    interp.gas.record_cost(if evm.context.evm.journaled_state.state.contains_key(&authority) {
        100
    } else {
        2600
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

    let msg = compose_msg(
        evm.cfg().chain_id,
        evm.tx().nonce.unwrap_or(0),
        interp.contract.address,
        commit,
    );

    // check valid signature
    let mut sig = Vec::<u8>::with_capacity(64);
    sig.extend_from_slice(r.as_slice());
    sig.extend_from_slice(s.as_slice());
    let signer = match ecrecover(&B512::from_slice(&sig), y_parity, &msg) {
        Ok(sig) => sig,
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

/// AUTH's opcode and instruction.
pub fn auth<'a, EXT, DB: Database>() -> InstructionWithOpCode<Evm<'a, EXT, DB>> {
    InstructionWithOpCode { opcode: AUTH_OPCODE, instruction: auth_instruction::<EXT, DB> }
}

fn authcall_instruction<EXT, DB: Database>(interp: &mut Interpreter, _evm: &mut Evm<'_, EXT, DB>) {
    interp.gas.record_cost(133);
}

/// AUTHCALL's opcode and instruction.
pub fn authcall<'a, EXT, DB: Database>() -> InstructionWithOpCode<Evm<'a, EXT, DB>> {
    InstructionWithOpCode { opcode: AUTHCALL_OPCODE, instruction: authcall_instruction::<EXT, DB> }
}

#[cfg(test)]
mod tests {
    use super::*;
    use revm::{
        db::{CacheDB, EmptyDBTyped},
        InMemoryDB,
    };
    use revm_interpreter::Contract;
    use revm_primitives::{Bytecode, Bytes, U256};
    use secp256k1::{rand, PublicKey, SecretKey};
    use std::convert::Infallible;

    fn test_interpreter() -> Interpreter {
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

    fn test_evm() -> Evm<'static, (), CacheDB<EmptyDBTyped<Infallible>>> {
        Evm::builder()
            .with_db(InMemoryDB::default())
            .append_handler_register(|handler| {
                if let Some(ref mut table) = handler.instruction_table {
                    table.insert(AUTH_OPCODE, auth_instruction);
                }
            })
            .build()
    }

    #[test]
    fn test_auth_instruction_stack_underflow() {
        let mut interpreter = test_interpreter();
        let mut evm = test_evm();

        auth_instruction(&mut interpreter, &mut evm);
        assert_eq!(interpreter.instruction_result, InstructionResult::StackUnderflow);

        // check gas
        let expected_gas = 3100; // fixed_fee
        assert_eq!(expected_gas, interpreter.gas.spend());
    }

    #[test]
    fn test_auth_instruction_happy_path() {
        let mut interpreter = test_interpreter();

        let secp = Secp256k1::new();
        let secret_key = SecretKey::new(&mut rand::thread_rng());
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        let hash = keccak256(&public_key.serialize_uncompressed()[1..]);
        let authority = Address::from_slice(&hash[12..]);
        let offset = 0;
        let lenght = 97;
        interpreter.stack.push(U256::from(lenght)).unwrap();
        interpreter.stack.push(U256::from(offset)).unwrap();
        interpreter.stack.push_b256(B256::left_padding_from(authority.as_slice())).unwrap();

        let commit = B256::ZERO;
        let msg = compose_msg(1, 0, Address::default(), commit);

        let sig = secp.sign_ecdsa_recoverable(
            &Message::from_digest_slice(msg.as_slice()).unwrap(),
            &secret_key,
        );
        let (recid, ret) = sig.serialize_compact();
        let y_parity = recid.to_i32();
        let r = B256::from_slice(&ret[..32]);
        let s = B256::from_slice(&ret[32..]);

        interpreter.shared_memory.resize(100);
        interpreter.shared_memory.set_byte(offset, y_parity.try_into().unwrap());
        interpreter.shared_memory.set_word(offset + 1, &r);
        interpreter.shared_memory.set_word(offset + 33, &s);
        interpreter.shared_memory.set_word(offset + 65, &commit);

        let mut evm = test_evm();

        auth_instruction(&mut interpreter, &mut evm);

        assert_eq!(interpreter.instruction_result, InstructionResult::Continue);
        let result = interpreter.stack.pop().unwrap();
        assert_eq!(result.saturating_to::<usize>(), 1);

        // check gas
        let expected_gas = 3100 + 2600; // fixed_fee + cold authority
        assert_eq!(expected_gas, interpreter.gas.spend());

        // TODO: check authorized context variable set
    }
}
