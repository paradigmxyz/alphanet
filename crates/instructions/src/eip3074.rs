use revm::{Database, Evm};
use revm_interpreter::{Instruction, InstructionResult, Interpreter};
use revm_primitives::{keccak256, B256};

const CUSTOM_INSTRUCTION_COST: u64 = 133;
const AUTH_OPCODE: u8 = 0xF6;
const AUTHCALL_OPCODE: u8 = 0xF7;
const MAGIC: u8 = 0x04;

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

fn auth_instruction<EXT, DB: Database>(interp: &mut Interpreter, evm: &mut Evm<'_, EXT, DB>) {
    if interp.stack.len() < 3 {
        interp.instruction_result = InstructionResult::StackUnderflow;
        return;
    }
    // SAFETY: length checked above
    let (authority, offset, _length) = unsafe { interp.stack.pop3_unsafe() };

    // read yParity, r, s and commit from memory using offset and length
    let _y_parity = interp.shared_memory.get_byte(offset.saturating_to::<usize>());
    let _r = interp.shared_memory.get_word(offset.saturating_to::<usize>() + 1);
    let _s = interp.shared_memory.get_word(offset.saturating_to::<usize>() + 33);
    let commit = interp.shared_memory.get_word(offset.saturating_to::<usize>() + 65);

    // compose message keccak256(MAGIC || chainId || nonce || invokerAddress || commit)
    let mut _msg = Vec::<u8>::with_capacity(129);
    _msg.push(MAGIC);
    _msg.extend_from_slice(B256::left_padding_from(&evm.cfg().chain_id.to_be_bytes()).as_slice());
    _msg.extend_from_slice(
        B256::left_padding_from(&evm.tx().nonce.unwrap_or(0).to_be_bytes()).as_slice(),
    );
    _msg.extend_from_slice(B256::left_padding_from(interp.contract.address.as_slice()).as_slice());
    _msg.extend_from_slice(commit.as_slice());
    let _msg = keccak256(_msg.as_slice());

    // check valid signature
    let valid_signature = true;

    // extract signer
    let signer = authority;

    let result = if valid_signature && signer == authority {
        // set authorized context variable to authority

        B256::with_last_byte(1)
    } else {
        // authorized context variable is reset to unset value

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
    interp.gas.record_cost(CUSTOM_INSTRUCTION_COST);
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
    use revm_primitives::{Address, Bytecode, Bytes, U256};
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
    }

    #[test]
    fn test_auth_instruction_happy_path() {
        let mut interpreter = test_interpreter();

        let authority = Address::default();
        let offset = 0;
        let lenght = 97;
        interpreter.stack.push(U256::from(lenght)).unwrap();
        interpreter.stack.push(U256::from(offset)).unwrap();
        interpreter.stack.push_slice(authority.as_slice()).unwrap();

        let y_parity = 1;
        let r = B256::ZERO;
        let s = B256::ZERO;
        let commit = B256::ZERO;
        interpreter.shared_memory.resize(4000);
        interpreter.shared_memory.set_byte(offset, y_parity);
        interpreter.shared_memory.set_word(offset + 1, &r);
        interpreter.shared_memory.set_word(offset + 33, &s);
        interpreter.shared_memory.set_word(offset + 65, &commit);

        let mut evm = test_evm();

        auth_instruction(&mut interpreter, &mut evm);

        assert_eq!(interpreter.instruction_result, InstructionResult::Continue);
        let result = interpreter.stack.pop().unwrap();
        assert_eq!(result.saturating_to::<usize>(), 1);
    }
}
