use revm::{Database, Evm};
use revm_interpreter::{Instruction, InstructionResult, Interpreter};

const CUSTOM_INSTRUCTION_COST: u64 = 133;
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

fn auth_instruction<EXT, DB: Database>(interp: &mut Interpreter, _evm: &mut Evm<'_, EXT, DB>) {
    if interp.stack.len() < 3 {
        interp.instruction_result = InstructionResult::StackUnderflow;
        return;
    }
    // SAFETY: length checked above
    let (_authority, _offset, _length) = unsafe { interp.stack.pop3_unsafe() };
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
    use revm_primitives::{Address, Bytecode, Bytes, B256};
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
}
